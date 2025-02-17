"""
This module contains the SessionStateMachine and the V2GCommunicationSession,
which itself is subclassing the SessionStateMachine. These classes can be used
by both EVCC and SECC, as they share the exact same functionality when sending,
receiving, and processing messages during an ISO 15118 communication session.
"""

import asyncio
import gc
import logging
from abc import ABC, abstractmethod
from asyncio.streams import StreamReader, StreamWriter
from typing import List, Optional, Tuple, Type, Union, Any

from pydantic import ValidationError

from iso15118.shared.exceptions import (
    EXIDecodingError,
    FaultyStateImplementationError,
    InvalidV2GTPMessageError,
    MessageProcessingError,
    V2GMessageValidationError,
)
from iso15118.shared.exi_codec import EXI
from iso15118.shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from iso15118.shared.messages.datatypes import SelectedService as SelectedServiceV2_DIN
from iso15118.shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from iso15118.shared.messages.enums import (
    ControlMode,
    DINPayloadTypes,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
    Namespace,
    Protocol,
    SessionStopAction,
)
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from iso15118.shared.messages.iso15118_20.common_messages import (
    MatchedService as OfferedServiceV20,
)
from iso15118.shared.messages.iso15118_20.common_messages import (
    SelectedEnergyService,
    SelectedVAS,
)
from iso15118.shared.messages.iso15118_20.common_types import (
    V2GMessage as V2GMessageV20,
)
from iso15118.shared.messages.v2gtp import V2GTPMessage
from iso15118.shared.notifications import StopNotification
from iso15118.shared.states import Pause, State, Terminate, Session
from iso15118.shared.utils import wait_for_tasks

logger = logging.getLogger(__name__)


class SessionStateMachine(Session):
    """
    Each newly established TCP session initiates a communication session, which
    is essentially the sate machine for the ISO 15118 message handling.
    """

    def __init__(
        self,
        start_state: Type[State],
    ):
        """
        The EVCC state machine starts with waiting for the
        SupportedAppProtocolRes message from the SECC.

        The SECC state machine starts with waiting for the
        SupportedAppProtocolReq message from the EVCC.

        The ISO 15118 version is determined with the SupportedAppProtocolRequest.
        The states ProcessSupportedAppProtocolReq (SECC) and
        ProcessSupportedAppProtocolRes (EVCC), respectively, need to set the
        iso_version of the corresponding CommunicationSession object.

        Args:
            start_state: The state that initialises the state machine
        """
        self.start_state = start_state
        self._current_state = start_state(self)
        self.v20_payload_type_to_namespace = {
            ISOV20PayloadTypes.AC_MAINSTREAM: Namespace.ISO_V20_AC,
            ISOV20PayloadTypes.DC_MAINSTREAM: Namespace.ISO_V20_DC,
            ISOV20PayloadTypes.ACDP_MAINSTREAM: Namespace.ISO_V20_ACDP,
            ISOV20PayloadTypes.WPT_MAINSTREAM: Namespace.ISO_V20_WPT,
        }

    # Session abstractmethods impl
    @property
    def current_state(self) -> State:
        return self._current_state

    @current_state.setter
    def current_state(self, state: State) -> None:
        self._current_state = state

    def get_exi_ns(
        self,
        payload_type: Union[DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes],
    ) -> Namespace:
        """
        Provides the right protocol namespace for the EXI decoder.
        In DIN SPEC 70121 and ISO 15118-2, all messages are defined
        in one XSD schema (e.g. 'urn:iso:15118:2:2013:MsgDef' for ISO 15118-2),
        but in ISO 15118-20, we need to distinguish between Common, AC, DC, WPT,
        and ACDP.

        An ISO 15118-20 communication starts with messages defined in namespace
        'urn:iso:std:iso:15118:-20:CommonMessages', but some messages are then
        energy mode specific and, thus, we need the specific schema where these
        messages are defined.
        """
        if self.protocol == Protocol.UNKNOWN:
            return Namespace.SAP
        elif self.protocol == Protocol.ISO_15118_2:
            return Namespace.ISO_V2_MSG_DEF
        elif self.protocol == Protocol.DIN_SPEC_70121:
            return Namespace.DIN_MSG_DEF
        elif self.protocol.ns.startswith(Namespace.ISO_V20_BASE):
            if isinstance(payload_type, ISOV20PayloadTypes):
                return self.v20_payload_type_to_namespace.get(
                    payload_type, Namespace.ISO_V20_COMMON_MSG
                )
        return Namespace.ISO_V20_COMMON_MSG

    async def process_message(self, message: bytes) -> None:
        """
        The following steps are conducted in this state machine's general
        process_message() function:

        1. Try to create a V2GTP (V2G Transfer Protocol) message from the
           incoming byte stream.
        2. If step 1 didn't raise a InvalidV2GTPMessageError then we try to
           EXI decode the V2GTP payload
        3. If step 2 didn't raise an EXIDecodingError then we hand over the
           decoded payload to the current state's process_message() function,
           which will create the next message to send - but only in case a new
           message needs to be sent. For that to be true, the next_v2gtp_msg
           must have been set by the current state, which is usually the case
           for the EVCC if the next state is not a Terminate state. The SECC
           will always send a next response, even if the next state is Terminate.
           The next state to transition to is also determined by the state's
           process_message() method.

        Args:
            message:    The incoming message from the EVCC/SECC, given as a
                        bytearray (the payload of a V2GTPMessage).
                        The message can be a
                        - SupportedAppProtocolRequest  (EVCC),
                        - SupportedAppProtocolResponse (SECC),
                        - V2GMessage according to the DIN SPEC 70121 standard,
                        - V2GMessage according to the ISO 15118-2 standard, or
                        - V2GMessage according to the ISO 15118-20 standard

        Raises:
            InvalidV2GTPMessageError, FaultyStateImplementationError,
            EXIDecodingError
        """
        # Step 1
        try:
            # First extract the V2GMessage payload from the V2GTPMessage ...
            # and then decode the bytearray into the message
            logger.debug(f"process_message size={len(message)}")
            
            v2gtp_msg = V2GTPMessage.from_bytes(self.protocol, message)
        except InvalidV2GTPMessageError as exc:
            logger.exception("Incoming TCPPacket is not a valid V2GTPMessage")
            raise exc

        # Step 2
        decoded_message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            V2GMessageV20,
            V2GMessageDINSPEC,
            None,
        ] = None
        try:
            decoded_message = EXI().from_exi(
                v2gtp_msg.payload, self.get_exi_ns(v2gtp_msg.payload_type)
            )
        except V2GMessageValidationError as exc:
            logger.error(
                f"EXI message (ns={self.get_exi_ns(v2gtp_msg.payload_type)}) "
                f"where validation failed: {v2gtp_msg.payload.hex()}"
            )
            raise exc
        except EXIDecodingError as exc:
            logger.exception(f"{exc}")
            logger.error(
                f"EXI message (ns={self.get_exi_ns(v2gtp_msg.payload_type)}) "
                f"where error occured: {v2gtp_msg.payload.hex()}"
            )
            raise exc

        # Shouldn't happen, but just to be sure (otherwise mypy would complain)
        if not decoded_message:
            logger.error(
                "Unusual error situation: decoded_message is None"
                "although no EXIDecodingError was raised"
            )
            return

        # Step 3
        try:
            logger.info(f"{str(decoded_message)} received")
            await self.current_state.process_message(decoded_message, v2gtp_msg.payload)
        except MessageProcessingError as exc:
            logger.exception(
                f"{exc.__class__.__name__} while processing " f"{exc.message_name}"
            )
            raise exc
        except FaultyStateImplementationError as exc:
            logger.exception(f"{exc.__class__.__name__}: {exc}")
            raise exc
        except ValidationError as exc:
            logger.exception(f"{exc.__class__.__name__}: {exc.raw_errors}")
            raise exc
        except AttributeError as exc:
            logger.exception(f"{exc}")
            raise exc

        if (
            self.current_state.next_v2gtp_msg is None
            and self.current_state.next_state is not Terminate
        ):
            raise FaultyStateImplementationError(
                "Field 'next_v2gtp_msg' is "
                "None but must be set because "
                "next state is not Terminate"
            )

    def go_to_next_state(self) -> None:
        """
        This method assures that the communication session's current state is
        always up-to-date, which is something other parts of the code rely on.

        Is automatically called by the rcv_loop after sending the next message.
        But we only transition if the current state defined a next state.
        If that's not the case, the current state will decide how to transition
        based on the next incoming message.
        """
        if self.current_state.next_state:
            self.current_state.next_state(self)

    def resume(self) -> None:
        logger.debug("Trying to resume communication session")
        self.current_state = self.start_state(self)


class V2GCommunicationSession(SessionStateMachine):
    """
    A communication session class that is shared between the EVCC and the SECC
    to execute the corresponding state machine, process incoming messages, and
    send subsequent messages as a result.
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        transport: Tuple[StreamReader, StreamWriter],
        start_state: Type["State"],
        session_handler_queue: asyncio.Queue[Any],
    ):
        """
        Initialise the communication session with EVCC or SECC specific
        parameters

        Args:
            transport:  A tuple consisting of a StreamReader and StreamWriter
                        object for the TCP socket
            start_state: The state that initialises the state machine
            session_handler_queue:  The asyncio.Queue object used for pushing
                                    timeout, termination, and pausing
                                    notifications to the session handler
        """
        super().__init__(start_state)

        self._protocol: Protocol = Protocol.UNKNOWN
        self.reader, self.writer = transport
        # For timeout, termination, and pausing notifications
        self.session_handler_queue = session_handler_queue
        self.peer_name = self.writer.get_extra_info("peername")
        self._session_id: str = ""
        # Mutually agreed-upon ISO 15118 application protocol as result of SAP
        self.chosen_protocol: str = ""
        # Whether the SECC supports service renegotiation (ISO 15118-20)
        self.service_renegotiation_supported: bool = False
        # The services which the SECC offers (ISO 15118-20)
        self.matched_services_v20: List[OfferedServiceV20] = []
        # The value-added services the EVCC selected (ISO 15118-20)
        self.selected_vas_list_v20: List[SelectedVAS] = []
        # The charge service and value-added services the EVCC selected (ISO 15118-2)
        self.selected_services: List[SelectedServiceV2_DIN] = []
        # The energy service the EVCC selected (ISO 15118-20)
        self.selected_energy_service: Optional[SelectedEnergyService] = None
        # Variable selected_charging_type_is_ac set if one of the AC modes is selected
        self.selected_charging_type_is_ac: bool = True
        # The SAScheduleTuple element the EVCC chose (referenced by ID)
        self.selected_schedule: Optional[int] = None
        # The control mode used for this session (Scheduled or Dynamic). In ISO 15118-2,
        # there is only Scheduled, in -20 we have both and need to choose certain
        # datatypes of messages based on which control mode was chosen
        self.control_mode: Optional[ControlMode] = None
        # Contains info whether the communication session is stopped successfully (True)
        # or due to a failure (False), plus additional info regarding the reason behind.
        self._stop_reason: Optional[StopNotification] = None
        self.last_message_sent: Optional[V2GTPMessage] = None
        self._started: bool = True

        logger.info("Starting a new communication session")

    # Session abstractmethods impl
    @property
    def session_id(self) -> str:
        return self._session_id

    @session_id.setter
    def session_id(self, id: str) -> None:
        self._session_id = id

    @property
    def protocol(self) -> Protocol:
        return self._protocol

    @protocol.setter
    def protocol(self, proto: Protocol) -> None:
        self._protocol = proto

    @property
    def stop_reason(self) -> Optional[StopNotification]:
        return self._stop_reason

    @stop_reason.setter
    def stop_reason(self, reason: Optional[StopNotification]) -> None:
        if reason and not reason.peer_ip_address:
            reason.peer_ip_address = self.writer.get_extra_info("peername")
        self._stop_reason = reason

    async def start(self, timeout: float) -> None:
        """
        Starts a EVCC / SECC communication session by spawning up the rcv_loop()
        method, that constantly waits a given amount of seconds to read data
        from the TCP socket and process the incoming data.

        Args:
            timeout:    The time the EVCC / SECC is waiting for a next message
        """
        tasks = [self.rcv_loop(timeout)]

        try:
            self._started = True
            await wait_for_tasks(tasks)
        finally:
            self._started = False

    # abstractmethodes for the derived classes
    @abstractmethod
    def save_session_info(self) -> None:
        raise NotImplementedError

    @abstractmethod
    async def on_stop(self, reason: str) -> None:
        raise NotImplementedError

    def _update_state_info(self, state: State) -> None:
        logger.info(f"iso15118 state: {str(state)}")

    async def stop(self, reason: str, graceful: bool = True) -> None:
        """
        Closes the TCP connection after 5 seconds and terminates or pauses the
        data link for this V2GCommunicationSession object after 2 seconds to
        make sure any message that needs to be sent can still go through.
        TODO check if that really makes sense of if TCP should be terminated
             after 2 s and the data link after 5 s
        # ll9877 comment: removed the sleeps => not needed.

        Especially necessary for the SECC, which needs to send a response with
        a FAILED response code or a SessionStopRes with response code "OK"
        before closing the TCP connection.

        Not a formal requirement in ISO 15118-2, but a best practice decided
        within the ISO 15118 User Group, and it became a formal requirement in
        ISO 15118-20 (at least for the SECC side, see [V2G20-1633]).
        """
        if self.current_state.next_state == Pause:
            self.save_session_info()
            terminate_or_pause = SessionStopAction.PAUSE
        else:
            terminate_or_pause = SessionStopAction.TERMINATE

        logger.info(
            f"The data link will {terminate_or_pause} and "
            "the TCP connection will close. "
        )
        logger.info(f"Reason: {reason}")


        # Signal data link layer
        await self.on_stop(reason)
        logger.info(f"{terminate_or_pause}d the data link")
        
        try:
            # fixes error on cable unplug / disconnect: asyncio SSL: APPLICATION_DATA_AFTER_CLOSE_NOTIFY
            if not graceful:
                self.writer.transport.abort()
            self.writer.close()
            await self.writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionResetError) as exc:
            logger.info(str(exc))
        logger.info("TCP connection closed to peer with address " f"{self.peer_name}")

    async def send(self, message: V2GTPMessage) -> None:
        """
        Sends a V2GTPMessage via the TCP socket and stores the last message sent

        Args:
            message: A V2GTPMessage
        """

        # TODO: we may also check for writer exceptions
        msg = message.to_bytes()
        self.writer.write(msg)
        await self.writer.drain()
        self.last_message_sent = message
        logger.info(f"Sent {str(self.current_state.message)}, size={len(msg)}bytes")

    async def rcv_loop(self, timeout: float) -> None:
        """
        A constant loop that implements the timeout for each message. Starts
        waiting for a specified time (see argument 'timeout') to read something
        from the TCP socket via the StreamReader. Once data is received, it is
        processed and the according next message will be sent. The processing of
        the incoming data also returns the timeout value for the next message
        being sent, and the loop starts over again waiting to read data on the
        TCP socket for the given amount of time ('timeoout').

        We expect the incoming message to be an EXI encoded message.

        Args:
            timeout:    The time the EVCC / SECC is waiting for a next message
        """
        # ll9877 comment: use rec_buffer as received bytes might be chunks of a message ( MTU size 1500 bytes )
        # this makes also below comment about "the biggest message" obsolete
        rec_buffer = bytearray()
        while True:
            try:
                # The biggest message is the Certificate Installation Response,
                # which is estimated to be maximum between 5k to 6k
                # TODO check if that still holds with -20 (e.g. cross certs)
                message = await asyncio.wait_for(self.reader.read(7000), timeout)
                if message == b"" and self.reader.at_eof():
                    stop_reason: str = "TCP peer closed connection"
                    await self.stop_session(False, False, stop_reason)
                    return
            except (asyncio.TimeoutError, ConnectionResetError) as exc:
                if type(exc) is asyncio.TimeoutError:
                    if self.last_message_sent:
                        error_msg = (
                            f"{exc.__class__.__name__} occurred. Waited "
                            f"for {timeout} s after sending last message: "
                            f"{str(self.last_message_sent)}"
                        )
                    else:
                        error_msg = (
                            f"{exc.__class__.__name__} occurred. Waited "
                            f"for {timeout} s. No V2GTP message was "
                            "previously sent. This is probably a timeout "
                            f"while waiting for SupportedAppProtocolReq"
                        )
                else:
                    error_msg = f"{exc.__class__.__name__} occurred. {str(exc)}"

                await self.stop_session(False, True, error_msg)
                return
            gc_enabled = gc.isenabled()
            try:
                if gc_enabled:
                    gc.disable()
                
                # ll9877 comment: Check if the received bytes contain a processable message ( might be chunks )
                rec_buffer.extend(message)
                message_len = V2GTPMessage.get_message_length(rec_buffer)
                if message_len <= 0 or len(rec_buffer) < message_len:
                    logger.info(f"not full message received, wait for more data. rec_buffer len={len(rec_buffer)}, message len={message_len}")
                    continue

                # This will create the values needed for the next state, such as
                # next_state, next_v2gtp_message, next_message_payload_type etc.
                await self.process_message(bytes(rec_buffer[:message_len]))
                # remove processed message
                rec_buffer = rec_buffer[message_len:]

                if self.current_state.next_v2gtp_msg:
                    # next_v2gtp_msg would not be set only if the next state is either
                    # Terminate or Pause on the EVCC side
                    await self.send(self.current_state.next_v2gtp_msg)
                    logger.info(f"iso15118 state: {str(self.current_state)}")

                if self.current_state.next_state in (Terminate, Pause):
                    # self.stop_reason is already set
                    await self.stop_session(False, True, self.stop_reason.reason)
                    return

                timeout = self.current_state.next_msg_timeout
                self.go_to_next_state()
            except (
                MessageProcessingError,
                FaultyStateImplementationError,
                EXIDecodingError,
                InvalidV2GTPMessageError,
                AttributeError,
                ValueError,
                ConnectionResetError,
                Exception,
            ) as exc:
                message_name = ""
                additional_info = ""
                if isinstance(exc, MessageProcessingError):
                    message_name = exc.message_name
                if isinstance(exc, FaultyStateImplementationError):
                    additional_info = f": {exc}"
                if isinstance(exc, EXIDecodingError):
                    additional_info = f": {exc}"
                if isinstance(exc, InvalidV2GTPMessageError):
                    additional_info = f": {exc}"

                stop_reason = (
                    f"{exc.__class__.__name__} occurred while processing message "
                    f"{message_name} in state {str(self.current_state)} : {exc}. "
                    f"{additional_info}"
                )

                await self.stop_session(False, True, stop_reason)
                return
            finally:
                if gc_enabled:
                    gc.enable()

    async def stop_session(self, successful: bool, graceful: bool, reason: str) -> None:
        if not self.stop_reason or self.stop_reason.reason != reason:
            self.stop_reason = StopNotification(successful, reason, self.peer_name)

        await self.stop(reason, graceful)
        self.session_handler_queue.put_nowait(self.stop_reason)
