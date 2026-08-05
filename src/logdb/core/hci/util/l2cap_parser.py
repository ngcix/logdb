"""
Decode HCI ACL data into L2CAP channels, upper protocols and profiles.

    HCI ACL packet (0x02)
        -> ACL header      : connection handle, PB flag, data length
        -> L2CAP header    : length, CID
        -> fixed CID       : ATT / SMP / signaling / ...
           dynamic CID     : PSM learned from the signaling channel
        -> RFCOMM / AVDTP / AVCTP / HIDP / BNEP / SDP ...
        -> profile         : A2DP / AVRCP / HID / PAN / GATT ...

Channels created before the capture started have no signaling to learn the
PSM from, so a conservative signature check is used as a fallback and the
result is tagged with protocol_source = "heuristic".
"""

from typing import Any, Dict, Optional, Tuple

from .l2cap_opcodes import (
    ACL_BC_FLAGS,
    ACL_CONTINUATION_PB_FLAG,
    ACL_PB_FLAGS,
    ATT_ERROR_CODES,
    ATT_OPCODES,
    ATT_OPCODES_WITH_HANDLE,
    AVC_CTYPES,
    AVC_OPCODES,
    AVC_SUBUNIT_TYPES,
    AVCTP_PACKET_TYPES,
    AVCTP_PROFILE_IDS,
    AVDTP_MESSAGE_TYPES,
    AVDTP_PACKET_TYPES,
    AVDTP_SIGNAL_IDS,
    AVRCP_EVENT_IDS,
    AVRCP_PASS_THROUGH_OPERATIONS,
    AVRCP_PDU_IDS,
    BLUETOOTH_SIG_COMPANY_ID,
    BNEP_PACKET_TYPES,
    HIDP_REPORT_TYPES,
    HIDP_TRANSACTION_TYPES,
    L2CAP_CONNECTION_RESULTS,
    L2CAP_DYNAMIC_CID_START,
    L2CAP_FIXED_CID_PROTOCOLS,
    L2CAP_SIGNALING_CODES,
    PSM_PROTOCOLS,
    RFCOMM_FRAME_TYPES,
    RFCOMM_MCC_TYPES,
    RFCOMM_PF_BIT,
    RTP_DYNAMIC_PAYLOAD_TYPES,
    RTP_VERSION,
    SDP_PDU_IDS,
    SMP_FAILURE_REASONS,
    SMP_IO_CAPABILITIES,
    SMP_OPCODES,
    get_fixed_cid_name,
    get_profile,
    get_psm_name,
)

# Signaling codes that open a channel, per specification version
_CONNECTION_REQUEST_CODES = (0x02, 0x0C, 0x14, 0x17)
_CONNECTION_RESPONSE_CODES = (0x03, 0x0D, 0x15, 0x18)


def _u8(data: bytes, offset: int) -> Optional[int]:
    return data[offset] if len(data) > offset else None


def _u16(data: bytes, offset: int) -> Optional[int]:
    """Little endian 16 bit value (L2CAP and most upper protocols)"""
    if len(data) < offset + 2:
        return None
    return data[offset] | (data[offset + 1] << 8)


def _u16be(data: bytes, offset: int) -> Optional[int]:
    """Big endian 16 bit value (AVCTP PID, RTP fields)"""
    if len(data) < offset + 2:
        return None
    return (data[offset] << 8) | data[offset + 1]


def _u24be(data: bytes, offset: int) -> Optional[int]:
    if len(data) < offset + 3:
        return None
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def _u32be(data: bytes, offset: int) -> Optional[int]:
    if len(data) < offset + 4:
        return None
    return int.from_bytes(data[offset:offset + 4], byteorder='big')


def _enum(value: Optional[int], table: Dict[int, str], width: int = 2) -> Optional[str]:
    if value is None:
        return None
    return table.get(value, f'Unknown_0x{value:0{width}x}')


class L2CAPParser:
    """
    Stateful ACL decoder.

    State kept across packets:
      - fragment reassembly buffers, per (connection handle, direction)
      - CID -> PSM registry, learned from the L2CAP signaling channel
    """

    #: hex preview length for undecoded payloads
    PAYLOAD_PREVIEW_BYTES = 16

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Drop all channel and reassembly state (call per log file)"""
        # (handle, direction) -> pending PDU being reassembled
        self._pending: Dict[Tuple[int, str], Dict[str, Any]] = {}
        # (handle, cid) -> channel info learned from signaling
        self._channels: Dict[Tuple[int, int], Dict[str, Any]] = {}
        # (handle, signaling identifier) -> open request waiting for its response
        self._open_requests: Dict[Tuple[int, int], Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # ACL / L2CAP layer
    # ------------------------------------------------------------------

    def parse_acl(self, handle: int, pb_flag: int, bc_flag: int,
                  direction: str, data: bytes) -> Dict[str, Any]:
        """
        Decode one ACL payload (everything after the ACL header).

        Returns a dict with the acl / l2cap headers plus, once a full L2CAP
        PDU is available, protocol, profile and the protocol specific decode.
        """
        result: Dict[str, Any] = {}

        # ACL header flags, temporarily kept out of the JSON output.
        # Uncomment to report them again.
        # result["acl"] = {
        #     "pb_flag": f'0x{pb_flag:02x}',
        #     "pb_flag_name": _enum(pb_flag, ACL_PB_FLAGS),
        #     "bc_flag": f'0x{bc_flag:02x}',
        #     "bc_flag_name": _enum(bc_flag, ACL_BC_FLAGS),
        # }

        if pb_flag == ACL_CONTINUATION_PB_FLAG:
            self._continue_pdu(handle, direction, data, result)
        else:
            self._start_pdu(handle, direction, data, result)
        return result

    def _start_pdu(self, handle: int, direction: str, data: bytes,
                   result: Dict[str, Any]) -> None:
        """Handle a first fragment: it carries the L2CAP header"""
        key = (handle, direction)
        dropped = self._pending.pop(key, None)

        l2cap_length = _u16(data, 0)
        cid = _u16(data, 2)
        if l2cap_length is None or cid is None:
            result["l2cap"] = {"error": "Truncated_L2CAP_Header"}
            return

        payload = data[4:]
        info: Dict[str, Any] = {
            "length": l2cap_length,
            "cid": f'0x{cid:04x}',
            "channel": get_fixed_cid_name(cid),
        }
        if dropped:
            info["dropped_incomplete_pdu"] = dropped["l2cap_length"]

        if len(payload) < l2cap_length:
            # Fragmented PDU: remember it and wait for the continuations
            self._pending[key] = {
                "cid": cid,
                "l2cap_length": l2cap_length,
                "buffer": bytearray(payload),
                "fragments": 1,
            }
            info["complete"] = False
            info["received_len"] = len(payload)
            result["l2cap"] = info
            # The channel is already known, report it even while incomplete
            channel = self._resolve_channel(handle, cid, payload)
            result.update(channel)
            return

        info["payload_len"] = l2cap_length
        result["l2cap"] = info
        self._dispatch(handle, cid, bytes(payload[:l2cap_length]), result)

    def _continue_pdu(self, handle: int, direction: str, data: bytes,
                      result: Dict[str, Any]) -> None:
        """Handle a continuing fragment: append and decode once complete"""
        key = (handle, direction)
        pending = self._pending.get(key)
        if pending is None:
            result["l2cap"] = {"error": "Continuation_Without_Start"}
            return

        pending["buffer"].extend(data)
        pending["fragments"] += 1
        cid = pending["cid"]
        received = len(pending["buffer"])
        l2cap_length = pending["l2cap_length"]

        info: Dict[str, Any] = {
            "length": l2cap_length,
            "cid": f'0x{cid:04x}',
            "channel": get_fixed_cid_name(cid),
            "fragments": pending["fragments"],
        }

        if received < l2cap_length:
            info["complete"] = False
            info["received_len"] = received
            result["l2cap"] = info
            result.update(self._resolve_channel(handle, cid, bytes(pending["buffer"])))
            return

        del self._pending[key]
        payload = bytes(pending["buffer"][:l2cap_length])
        info["payload_len"] = len(payload)
        info["reassembled"] = True
        result["l2cap"] = info
        self._dispatch(handle, cid, payload, result)

    # ------------------------------------------------------------------
    # Channel -> protocol resolution
    # ------------------------------------------------------------------

    def _resolve_channel(self, handle: int, cid: int,
                         payload: bytes) -> Dict[str, Any]:
        """
        Work out which protocol a CID carries.

        Fixed CIDs are defined by the spec; dynamic CIDs are looked up in the
        registry built from the signaling channel and, failing that, guessed
        from the payload signature.
        """
        protocol = L2CAP_FIXED_CID_PROTOCOLS.get(cid)
        if protocol:
            return {
                "protocol": protocol,
                "profile": get_profile(protocol),
            }

        channel = self._channels.get((handle, cid))
        if channel:
            info = {
                "protocol": channel["protocol"],
                "profile": get_profile(channel["protocol"]),
                "psm": f'0x{channel["psm"]:04x}',
                "psm_name": channel["psm_name"],
            }
            return info

        if cid >= L2CAP_DYNAMIC_CID_START:
            guess = self._guess_protocol(payload)
            if guess:
                return {
                    "protocol": guess,
                    "profile": get_profile(guess),
                }

        return {"protocol": "Unknown", "profile": "Unknown"}

    @staticmethod
    def _guess_protocol(payload: bytes) -> Optional[str]:
        """
        Conservative signature check for channels opened before the capture.

        Only signatures with a distinctive constant are used: the AVCTP
        profile id, the RFCOMM frame type / EA bit combination and the RTP
        version + dynamic payload type of an AVDTP media stream.
        """
        if len(payload) < 2:
            return None

        # AVCTP single packets carry a 16 bit profile id right after the header
        # (IPID must be clear, only single packets have the id at this offset)
        pid = _u16be(payload, 1)
        if pid in AVCTP_PROFILE_IDS and not payload[0] & 0x01 and (payload[0] >> 2) & 0x03 == 0x00:
            return "AVCTP"

        # RFCOMM: EA bit set in the address byte plus a known frame type
        if payload[0] & 0x01 and (payload[1] & ~RFCOMM_PF_BIT) in RFCOMM_FRAME_TYPES:
            return "RFCOMM"

        # AVDTP media: RTP header with a dynamic payload type
        if (payload[0] >> 6) == RTP_VERSION and (payload[1] & 0x7F) in RTP_DYNAMIC_PAYLOAD_TYPES:
            return "AVDTP_Media"

        # AVDTP signaling: single/start packet carrying a known signal id
        message_type = payload[0] & 0x03
        packet_type = (payload[0] >> 2) & 0x03
        if packet_type == 0x00 and message_type != 0x01 and (payload[1] & 0x3F) in AVDTP_SIGNAL_IDS:
            return "AVDTP"

        return None

    def _dispatch(self, handle: int, cid: int, payload: bytes,
                  result: Dict[str, Any]) -> None:
        """Decode a complete L2CAP PDU with the protocol of its channel"""
        channel = self._resolve_channel(handle, cid, payload)
        result.update(channel)
        protocol = channel["protocol"]

        if protocol == "L2CAP_Signaling":
            decoded = self._decode_signaling(handle, payload)
        elif protocol == "ATT":
            decoded = self._decode_att(payload)
        elif protocol == "SMP":
            decoded = self._decode_smp(payload)
        elif protocol == "SDP":
            decoded = self._decode_sdp(payload)
        elif protocol == "RFCOMM":
            decoded = self._decode_rfcomm(payload)
        elif protocol == "AVDTP":
            decoded = self._decode_avdtp(payload)
        elif protocol == "AVDTP_Media":
            decoded = self._decode_avdtp_media(payload)
        elif protocol in ("AVCTP", "AVCTP_Browsing"):
            decoded = self._decode_avctp(payload)
        elif protocol == "HIDP":
            decoded = self._decode_hidp(payload)
        elif protocol == "BNEP":
            decoded = self._decode_bnep(payload)
        else:
            decoded = None

        if decoded:
            result[protocol.lower()] = decoded
        elif payload:
            result["payload_preview"] = payload[:self.PAYLOAD_PREVIEW_BYTES].hex()

    # ------------------------------------------------------------------
    # L2CAP signaling (CID 0x0001 / 0x0005)
    # ------------------------------------------------------------------

    def _decode_signaling(self, handle: int, payload: bytes) -> Dict[str, Any]:
        """Decode the signaling commands of one PDU and track channel setup"""
        commands = []
        offset = 0
        while offset + 4 <= len(payload):
            code = payload[offset]
            identifier = payload[offset + 1]
            length = _u16(payload, offset + 2) or 0
            params = payload[offset + 4:offset + 4 + length]
            command: Dict[str, Any] = {
                "code": f'0x{code:02x}',
                "name": _enum(code, L2CAP_SIGNALING_CODES),
                "identifier": identifier,
                "length": length,
            }
            self._decode_signaling_command(handle, code, identifier, params, command)
            commands.append(command)
            offset += 4 + length

        decoded: Dict[str, Any] = {"commands": commands}
        if commands:
            decoded["name"] = commands[0]["name"]
        return decoded

    def _decode_signaling_command(self, handle: int, code: int, identifier: int,
                                  params: bytes, command: Dict[str, Any]) -> None:
        """Decode one signaling command and update the channel registry"""
        if code in _CONNECTION_REQUEST_CODES:
            psm = _u16(params, 0)
            scid = _u16(params, 2)
            if psm is not None:
                command["psm"] = f'0x{psm:04x}'
                command["psm_name"] = get_psm_name(psm)
            if scid is not None:
                command["source_cid"] = f'0x{scid:04x}'
            if psm is not None and scid is not None:
                self._open_requests[(handle, identifier)] = {"psm": psm, "scid": scid}
                # Register the requester side straight away, the response only
                # tells us the CID of the other side
                self._register_channel(handle, scid, psm)

        elif code in _CONNECTION_RESPONSE_CODES:
            dcid = _u16(params, 0)
            scid = _u16(params, 2)
            result_code = _u16(params, 4)
            if dcid is not None:
                command["destination_cid"] = f'0x{dcid:04x}'
            if scid is not None:
                command["source_cid"] = f'0x{scid:04x}'
            if result_code is not None:
                command["result"] = _enum(result_code, L2CAP_CONNECTION_RESULTS, width=4)
            request = self._open_requests.get((handle, identifier))
            if request and result_code == 0x0000:
                command["psm"] = f'0x{request["psm"]:04x}'
                command["psm_name"] = get_psm_name(request["psm"])
                for channel_cid in (dcid, scid, request["scid"]):
                    self._register_channel(handle, channel_cid, request["psm"])
                self._open_requests.pop((handle, identifier), None)

        elif code in (0x06, 0x07):  # Disconnection request / response
            dcid = _u16(params, 0)
            scid = _u16(params, 2)
            if dcid is not None:
                command["destination_cid"] = f'0x{dcid:04x}'
            if scid is not None:
                command["source_cid"] = f'0x{scid:04x}'
            if code == 0x07:
                for channel_cid in (dcid, scid):
                    if channel_cid is not None:
                        self._channels.pop((handle, channel_cid), None)

        elif code in (0x04, 0x05):  # Configuration request / response
            dcid = _u16(params, 0)
            if dcid is not None:
                command["destination_cid"] = f'0x{dcid:04x}'

        elif code == 0x12:  # Connection parameter update request
            command["interval_min"] = _u16(params, 0)
            command["interval_max"] = _u16(params, 2)
            command["max_latency"] = _u16(params, 4)
            command["timeout_multiplier"] = _u16(params, 6)

        elif code == 0x16:  # LE flow control credit
            cid = _u16(params, 0)
            if cid is not None:
                command["cid"] = f'0x{cid:04x}'
            command["credits"] = _u16(params, 2)

    def _register_channel(self, handle: int, cid: Optional[int],
                          psm: int) -> None:
        """Remember which PSM a dynamic CID belongs to"""
        if cid is None or cid < L2CAP_DYNAMIC_CID_START:
            return
        protocol = PSM_PROTOCOLS.get(psm, "Unknown")
        self._channels[(handle, cid)] = {
            "psm": psm,
            "psm_name": get_psm_name(psm),
            "protocol": protocol,
        }

    # ------------------------------------------------------------------
    # Fixed channel protocols
    # ------------------------------------------------------------------

    def _decode_att(self, payload: bytes) -> Dict[str, Any]:
        opcode = _u8(payload, 0)
        if opcode is None:
            return {}
        decoded: Dict[str, Any] = {
            "opcode": f'0x{opcode:02x}',
            "name": _enum(opcode, ATT_OPCODES),
        }
        if opcode == 0x01:  # Error response
            request_opcode = _u8(payload, 1)
            decoded["request_opcode"] = _enum(request_opcode, ATT_OPCODES)
            handle = _u16(payload, 2)
            if handle is not None:
                decoded["attribute_handle"] = f'0x{handle:04x}'
            decoded["error"] = _enum(_u8(payload, 4), ATT_ERROR_CODES)
        elif opcode in (0x02, 0x03):  # Exchange MTU
            decoded["mtu"] = _u16(payload, 1)
        elif opcode in (0x04, 0x08, 0x10):  # Requests over a handle range
            start_handle = _u16(payload, 1)
            end_handle = _u16(payload, 3)
            if start_handle is not None:
                decoded["starting_handle"] = f'0x{start_handle:04x}'
            if end_handle is not None:
                decoded["ending_handle"] = f'0x{end_handle:04x}'
            uuid = payload[5:]
            if uuid:
                decoded["uuid"] = uuid[::-1].hex()
        elif opcode in ATT_OPCODES_WITH_HANDLE:
            handle = _u16(payload, 1)
            if handle is not None:
                decoded["attribute_handle"] = f'0x{handle:04x}'
            value = payload[3:]
            if value:
                decoded["value_len"] = len(value)
                decoded["value"] = value[:self.PAYLOAD_PREVIEW_BYTES].hex()
        elif len(payload) > 1:
            decoded["parameters"] = payload[1:1 + self.PAYLOAD_PREVIEW_BYTES].hex()
        return decoded

    def _decode_smp(self, payload: bytes) -> Dict[str, Any]:
        opcode = _u8(payload, 0)
        if opcode is None:
            return {}
        decoded: Dict[str, Any] = {
            "opcode": f'0x{opcode:02x}',
            "name": _enum(opcode, SMP_OPCODES),
        }
        if opcode in (0x01, 0x02):  # Pairing request / response
            decoded["io_capability"] = _enum(_u8(payload, 1), SMP_IO_CAPABILITIES)
            decoded["oob_data_flag"] = _u8(payload, 2)
            auth_req = _u8(payload, 3)
            if auth_req is not None:
                decoded["auth_req"] = f'0x{auth_req:02x}'
                decoded["bonding"] = bool(auth_req & 0x01)
                decoded["mitm"] = bool(auth_req & 0x04)
                decoded["secure_connections"] = bool(auth_req & 0x08)
            decoded["max_encryption_key_size"] = _u8(payload, 4)
        elif opcode == 0x05:  # Pairing failed
            decoded["reason"] = _enum(_u8(payload, 1), SMP_FAILURE_REASONS)
        elif opcode == 0x0B:  # Security request
            auth_req = _u8(payload, 1)
            if auth_req is not None:
                decoded["auth_req"] = f'0x{auth_req:02x}'
        return decoded

    # ------------------------------------------------------------------
    # PSM based protocols
    # ------------------------------------------------------------------

    def _decode_sdp(self, payload: bytes) -> Dict[str, Any]:
        pdu_id = _u8(payload, 0)
        if pdu_id is None:
            return {}
        return {
            "pdu_id": f'0x{pdu_id:02x}',
            "name": _enum(pdu_id, SDP_PDU_IDS),
            "transaction_id": _u16be(payload, 1),
            "parameter_length": _u16be(payload, 3),
        }

    def _decode_rfcomm(self, payload: bytes) -> Dict[str, Any]:
        address = _u8(payload, 0)
        control = _u8(payload, 1)
        if address is None or control is None:
            return {}
        dlci = address >> 2
        frame_type = control & ~RFCOMM_PF_BIT
        decoded: Dict[str, Any] = {
            "dlci": dlci,
            "server_channel": dlci >> 1,
            "direction_bit": dlci & 0x01,
            "command_response": (address >> 1) & 0x01,
            "frame_type": _enum(frame_type, RFCOMM_FRAME_TYPES),
            "poll_final": bool(control & RFCOMM_PF_BIT),
        }

        # Information length uses the EA bit as a 1 or 2 byte marker
        length_byte = _u8(payload, 2)
        offset = 3
        if length_byte is None:
            return decoded
        if length_byte & 0x01:
            info_length = length_byte >> 1
        else:
            high = _u8(payload, 3) or 0
            info_length = (length_byte >> 1) | (high << 7)
            offset = 4
        decoded["information_length"] = info_length

        if dlci == 0 and frame_type == 0xEF:
            # Multiplexer control channel carries an MCC command
            mcc_type = _u8(payload, offset)
            if mcc_type is not None:
                decoded["mcc_type"] = _enum(mcc_type >> 2, RFCOMM_MCC_TYPES)
                decoded["mcc_command_response"] = (mcc_type >> 1) & 0x01
        elif info_length:
            info = payload[offset:offset + info_length]
            decoded["information"] = info[:self.PAYLOAD_PREVIEW_BYTES].hex()
        return decoded

    def _decode_avdtp(self, payload: bytes) -> Dict[str, Any]:
        header = _u8(payload, 0)
        if header is None:
            return {}
        packet_type = (header >> 2) & 0x03
        decoded: Dict[str, Any] = {
            "transaction_label": header >> 4,
            "packet_type": _enum(packet_type, AVDTP_PACKET_TYPES),
            "message_type": _enum(header & 0x03, AVDTP_MESSAGE_TYPES),
        }
        # Only single and start packets carry the signal identifier
        if packet_type == 0x01:
            decoded["number_of_signal_packets"] = _u8(payload, 1)
            signal_offset = 2
        elif packet_type == 0x00:
            signal_offset = 1
        else:
            return decoded

        signal = _u8(payload, signal_offset)
        if signal is not None:
            decoded["signal_id"] = f'0x{signal & 0x3F:02x}'
            decoded["name"] = _enum(signal & 0x3F, AVDTP_SIGNAL_IDS)
        parameters = payload[signal_offset + 1:]
        if parameters:
            # Commands start with the ACP SEID, responses carry signal
            # specific data (capability lists, SEID lists, ...)
            if header & 0x03 == 0x00:
                decoded["acp_seid"] = parameters[0] >> 2
            decoded["parameters"] = parameters[:self.PAYLOAD_PREVIEW_BYTES].hex()
        return decoded

    def _decode_avdtp_media(self, payload: bytes) -> Dict[str, Any]:
        """RTP header of an A2DP media packet"""
        first = _u8(payload, 0)
        second = _u8(payload, 1)
        if first is None or second is None:
            return {}
        csrc_count = first & 0x0F
        decoded: Dict[str, Any] = {
            "rtp_version": first >> 6,
            "padding": bool(first & 0x20),
            "extension": bool(first & 0x10),
            "csrc_count": csrc_count,
            "marker": bool(second & 0x80),
            "payload_type": second & 0x7F,
            "sequence_number": _u16be(payload, 2),
            "timestamp": _u32be(payload, 4),
            "ssrc": _u32be(payload, 8),
        }
        media_offset = 12 + csrc_count * 4
        if len(payload) > media_offset:
            # First byte after the RTP header is the SBC/codec frame header
            decoded["media_payload_len"] = len(payload) - media_offset
            decoded["codec_header"] = f'0x{payload[media_offset]:02x}'
        return decoded

    def _decode_avctp(self, payload: bytes) -> Dict[str, Any]:
        header = _u8(payload, 0)
        if header is None:
            return {}
        packet_type = (header >> 2) & 0x03
        decoded: Dict[str, Any] = {
            "transaction_label": header >> 4,
            "packet_type": _enum(packet_type, AVCTP_PACKET_TYPES),
            "command_response": "Response" if header & 0x02 else "Command",
            "ipid": bool(header & 0x01),
        }
        offset = 1
        if packet_type == 0x01:
            decoded["number_of_packets"] = _u8(payload, 1)
            offset = 2
        elif packet_type in (0x02, 0x03):
            return decoded

        pid = _u16be(payload, offset)
        if pid is None:
            return decoded
        decoded["profile_id"] = f'0x{pid:04x}'
        decoded["profile_name"] = _enum(pid, AVCTP_PROFILE_IDS, width=4)

        avc = self._decode_avc(payload[offset + 2:])
        if avc:
            decoded["avc"] = avc
            if "name" in avc:
                decoded["name"] = avc["name"]
        return decoded

    def _decode_avc(self, payload: bytes) -> Dict[str, Any]:
        """AV/C frame carried by AVCTP, i.e. the AVRCP command itself"""
        ctype = _u8(payload, 0)
        subunit = _u8(payload, 1)
        opcode = _u8(payload, 2)
        if ctype is None or subunit is None or opcode is None:
            return {}
        decoded: Dict[str, Any] = {
            "ctype": _enum(ctype & 0x0F, AVC_CTYPES),
            "subunit_type": _enum(subunit >> 3, AVC_SUBUNIT_TYPES),
            "subunit_id": subunit & 0x07,
            "opcode": _enum(opcode, AVC_OPCODES),
        }

        if opcode == 0x7C:  # PASS THROUGH
            operation = _u8(payload, 3)
            if operation is not None:
                decoded["operation_id"] = _enum(operation & 0x7F,
                                                AVRCP_PASS_THROUGH_OPERATIONS)
                decoded["state"] = "Released" if operation & 0x80 else "Pressed"
                decoded["name"] = f'AVRCP_{decoded["operation_id"]}'
            return decoded

        if opcode != 0x00:  # UNIT INFO / SUBUNIT INFO carry no PDU
            decoded["name"] = f'AVRCP_{decoded["opcode"]}'
            return decoded

        company_id = _u24be(payload, 3)
        if company_id is not None:
            decoded["company_id"] = f'0x{company_id:06x}'
            decoded["bluetooth_sig"] = company_id == BLUETOOTH_SIG_COMPANY_ID
        pdu_id = _u8(payload, 6)
        if pdu_id is not None:
            decoded["pdu_id"] = f'0x{pdu_id:02x}'
            decoded["name"] = _enum(pdu_id, AVRCP_PDU_IDS)
        decoded["parameter_length"] = _u16be(payload, 8)

        # RegisterNotification and the notification responses start with the event id
        if pdu_id == 0x31:
            decoded["event_id"] = _enum(_u8(payload, 10), AVRCP_EVENT_IDS)
        return decoded

    def _decode_hidp(self, payload: bytes) -> Dict[str, Any]:
        header = _u8(payload, 0)
        if header is None:
            return {}
        transaction_type = header >> 4
        decoded: Dict[str, Any] = {
            "transaction_type": _enum(transaction_type, HIDP_TRANSACTION_TYPES),
            "parameter": header & 0x0F,
        }
        decoded["name"] = f'HIDP_{decoded["transaction_type"]}'
        if transaction_type in (0x04, 0x05, 0x0A, 0x0B):
            decoded["report_type"] = _enum(header & 0x03, HIDP_REPORT_TYPES)
        if len(payload) > 1:
            decoded["report_len"] = len(payload) - 1
            decoded["report"] = payload[1:1 + self.PAYLOAD_PREVIEW_BYTES].hex()
        return decoded

    def _decode_bnep(self, payload: bytes) -> Dict[str, Any]:
        header = _u8(payload, 0)
        if header is None:
            return {}
        packet_type = header & 0x7F
        return {
            "packet_type": _enum(packet_type, BNEP_PACKET_TYPES),
            "name": _enum(packet_type, BNEP_PACKET_TYPES),
            "extension": bool(header & 0x80),
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def channel_summary(self) -> Dict[str, Dict[str, Any]]:
        """Channels learned from signaling, keyed by handle:cid"""
        return {
            f'0x{handle:04x}:0x{cid:04x}': dict(info)
            for (handle, cid), info in sorted(self._channels.items())
        }
