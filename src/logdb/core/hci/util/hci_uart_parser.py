# [Cline generated]
import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from .utility import BtUtil
from .l2cap_parser import L2CAPParser
from .hci_opcodes import (
    AIR_MODES,
    AUTHENTICATION_REQUIREMENTS,
    CLOCK_ACCURACY,
    CURRENT_MODES,
    ENCRYPTION_STATES,
    IO_CAPABILITIES,
    KEYPRESS_NOTIFICATION_TYPES,
    LE_ADDRESS_TYPES,
    LE_ADV_EVENT_TYPES,
    LE_PHY_TYPES,
    LINK_KEY_TYPES,
    LINK_TYPES,
    OOB_DATA_PRESENT,
    PAGE_SCAN_REPETITION_MODES,
    ROLES,
    get_command_name,
    get_event_name,
    get_status_name,
    get_subevent_name,
)

# Default file path for HCI SNOOZ log
BT_SNOOZ_LOG_VOC = "snooz_VOC.cfa"


def _u8(data: bytes, offset: int) -> Optional[int]:
    """Read an unsigned byte, None if the payload is too short"""
    return data[offset] if len(data) > offset else None


def _s8(data: bytes, offset: int) -> Optional[int]:
    """Read a signed byte (RSSI, TX power), None if the payload is too short"""
    value = _u8(data, offset)
    return value - 256 if value is not None and value > 127 else value


def _u16(data: bytes, offset: int) -> Optional[int]:
    """Read a little endian 16 bit value, None if the payload is too short"""
    if len(data) < offset + 2:
        return None
    return data[offset] | (data[offset + 1] << 8)


def _u24(data: bytes, offset: int) -> Optional[int]:
    """Read a little endian 24 bit value (class of device)"""
    if len(data) < offset + 3:
        return None
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16)


def _u32(data: bytes, offset: int) -> Optional[int]:
    """Read a little endian 32 bit value (passkey, numeric value)"""
    if len(data) < offset + 4:
        return None
    return (data[offset] | (data[offset + 1] << 8) |
            (data[offset + 2] << 16) | (data[offset + 3] << 24))


def _hex(data: bytes, offset: int, size: int) -> Optional[str]:
    """Read a fixed size blob (link key, feature mask) as hex string"""
    if len(data) < offset + size:
        return None
    return data[offset:offset + size].hex()


def _enum(value: Optional[int], table: Dict[int, str]) -> Optional[str]:
    """Map a numeric parameter to its spec name"""
    if value is None:
        return None
    return table.get(value, f'Reserved_0x{value:02x}')


class HCIUartPacket:
    """Represents a single HCI UART packet"""
    
    def __init__(self):
        self.packet_num: int = 0
        self.timestamp_raw: int = 0
        self.timestamp_iso: Optional[str] = None
        self.packet_type: str = ""  # COMMAND, ACL_DATA, SCO_DATA, EVENT
        self.direction: str = ""     # SENT, RECEIVED
        self.opcode: Optional[str] = None
        self.command_name: Optional[str] = None
        self.event_code: Optional[str] = None
        self.event_name: Optional[str] = None
        self.param_len: int = 0
        self.parameters: Dict[str, Any] = {}
        self.connection_handle: Optional[str] = None
        self.bd_addr: Optional[str] = None
        self.status: Optional[str] = None
        self.reason: Optional[str] = None
        self.data_length: Optional[int] = None
        self.raw_data: Optional[str] = None
        self.protocol: Optional[str] = None
        self.profile: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with packet_num, timestamp, and data fields"""
        data = {
            "type": self.packet_type,
            "direction": self.direction,
            "param_len": self.param_len
        }

        if self.opcode:
            data["opcode"] = self.opcode
        if self.command_name:
            data["command_name"] = self.command_name
        if self.event_code:
            data["event_code"] = self.event_code
        if self.event_name:
            data["event_name"] = self.event_name
        if self.connection_handle:
            data["connection_handle"] = self.connection_handle
        if self.bd_addr:
            data["bd_addr"] = self.bd_addr
        if self.protocol:
            data["protocol"] = self.protocol
        if self.profile:
            data["profile"] = self.profile
        if self.status:
            data["status"] = self.status
        if self.reason:
            data["reason"] = self.reason
        if self.data_length is not None:
            data["data_length"] = self.data_length
        if self.parameters:
            data["parameters"] = self.parameters

        result = {
            "packet_num": self.packet_num,
            "timestamp": self.timestamp_iso,
            "data": data
        }

        return result


class HCIUartParser:
    """
    Parser for HCI UART logs from .cfa files.
    Based on get_HCI_VOC_log method from BTHelper.py
    Converts each HCI UART packet into JSON objects.
    """
    
    # HCI Packet Types
    HCI_COMMAND_PACKET = 1
    HCI_ACL_DATA_PACKET = 2
    HCI_SCO_DATA_PACKET = 3
    HCI_EVENT_PACKET = 4
    
    def __init__(self):
        self.packets: List[HCIUartPacket] = []
        self.frame_count: int = 0
        
        # Scan tracking
        self.is_br_scanning = False
        self.num_found = 0
        self.scan_br_log: List[str] = []
        self.hci_connection_log: List[str] = []

        # ACL payload decoder: L2CAP channels, protocols and profiles
        self.l2cap = L2CAPParser()

        # Event code -> parameter decoder
        self._event_parsers = {
            # Inquiry / discovery
            0x01: self._evt_inquiry_complete,
            0x02: self._evt_inquiry_result,
            0x22: self._evt_inquiry_result_with_rssi,
            0x2F: self._evt_extended_inquiry_result,
            0x20: self._evt_page_scan_repetition_mode_change,
            # Connection management
            0x03: self._evt_connection_complete,
            0x04: self._evt_connection_request,
            0x05: self._evt_disconnection_complete,
            0x12: self._evt_role_change,
            0x14: self._evt_mode_change,
            0x1B: self._evt_max_slots_change,
            0x1C: self._evt_read_clock_offset_complete,
            0x1D: self._evt_connection_packet_type_changed,
            0x2C: self._evt_synchronous_connection_complete,
            0x2D: self._evt_synchronous_connection_changed,
            0x2E: self._evt_sniff_subrating,
            0x38: self._evt_link_supervision_timeout_changed,
            # Security / pairing
            0x06: self._evt_authentication_complete,
            0x07: self._evt_remote_name_request_complete,
            0x08: self._evt_encryption_change,
            0x09: self._evt_status_handle,
            0x0A: self._evt_link_key_type_changed,
            0x16: self._evt_bd_addr_only,
            0x17: self._evt_bd_addr_only,
            0x18: self._evt_link_key_notification,
            0x30: self._evt_status_handle,
            0x31: self._evt_bd_addr_only,
            0x32: self._evt_io_capability_response,
            0x33: self._evt_user_confirmation_request,
            0x34: self._evt_bd_addr_only,
            0x35: self._evt_bd_addr_only,
            0x36: self._evt_simple_pairing_complete,
            0x3B: self._evt_user_passkey_notification,
            0x3C: self._evt_keypress_notification,
            0x3D: self._evt_remote_host_supported_features,
            0x57: self._evt_handle_only,
            0x59: self._evt_encryption_change_v2,
            # Remote device information
            0x0B: self._evt_read_remote_supported_features_complete,
            0x0C: self._evt_read_remote_version_complete,
            0x23: self._evt_read_remote_extended_features_complete,
            # Controller / flow control
            0x0E: self._evt_command_complete,
            0x0F: self._evt_command_status,
            0x10: self._evt_hardware_error,
            0x11: self._evt_handle_only,
            0x13: self._evt_number_of_completed_packets,
            0x1A: self._evt_data_buffer_overflow,
            0x1E: self._evt_handle_only,
            0x39: self._evt_handle_only,
            # LE and vendor
            0x3E: self._evt_le_meta,
            0xFF: self._evt_vendor_specific,
        }

        # LE meta event subevent code -> parameter decoder
        self._le_subevent_parsers = {
            0x01: self._le_connection_complete,
            0x02: self._le_advertising_report,
            0x03: self._le_connection_update_complete,
            0x04: self._le_read_remote_features_complete,
            0x05: self._le_long_term_key_request,
            0x06: self._le_remote_connection_parameter_request,
            0x07: self._le_data_length_change,
            0x0A: self._le_enhanced_connection_complete,
            0x0B: self._le_directed_advertising_report,
            0x0C: self._le_phy_update_complete,
            0x0D: self._le_extended_advertising_report,
            0x0E: self._le_periodic_advertising_sync_established,
            0x10: self._le_periodic_advertising_sync_lost,
            0x12: self._le_advertising_set_terminated,
            0x13: self._le_scan_request_received,
            0x14: self._le_channel_selection_algorithm,
            0x1A: self._le_cis_request,
            0x21: self._le_transmit_power_reporting,
            0x23: self._le_subrate_change,
        }

    def _to_time(self, timestamp_bytes: bytes) -> int:
        """Convert timestamp bytes to Unix timestamp using BtUtil"""
        return BtUtil.toTime(int.from_bytes(timestamp_bytes, byteorder='big'))
    
    def _format_timestamp(self, unix_timestamp: int) -> Optional[str]:
        """Format Unix timestamp to ISO format"""
        if unix_timestamp <= 0:
            return None
        try:
            dt = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
            return dt.isoformat()
        except (ValueError, OSError):
            return None
    
    def _format_bd_addr(self, addr_bytes: bytes) -> str:
        """Format BD address bytes to string format (aa-bb-cc-dd-ee-ff)"""
        if len(addr_bytes) != 6:
            return addr_bytes.hex()
        return "-".join(f'{byte:02x}' for byte in reversed(addr_bytes))
    
    def _format_connection_handle(self, handle_bytes: bytes) -> str:
        """Format connection handle to hex string"""
        if len(handle_bytes) < 2:
            return "0x0000"
        temp = handle_bytes[0] | handle_bytes[1] << 8
        return f'0x{temp:04x}'
    
    def _parse_hci_command(self, snoop_file, timeline: int) -> Optional[HCIUartPacket]:
        """Parse HCI Command packet"""
        packet = HCIUartPacket()
        packet.packet_num = self.frame_count
        packet.timestamp_raw = timeline
        packet.timestamp_iso = self._format_timestamp(timeline)
        packet.packet_type = "COMMAND"
        packet.direction = "SENT"
        
        # Read opcode (2 bytes)
        cmd_bytes = snoop_file.read(2)
        if len(cmd_bytes) < 2:
            return None
            
        # Read param length (1 byte)
        length_byte = snoop_file.read(1)
        if not length_byte:
            return None
        length = length_byte[0] & 0x00FF
        
        # Calculate opcode
        opcode = (cmd_bytes[1] << 8) | cmd_bytes[0]
        packet.opcode = f'0x{opcode:04x}'
        packet.param_len = length
        
        # Parse specific commands (based on get_HCI_VOC_log)
        if cmd_bytes[0] == 0x05 and cmd_bytes[1] == 0x04:
            # HCI_Create_Connection
            packet.command_name = "HCI_Create_Connection"
            bd_addr = snoop_file.read(6)
            if len(bd_addr) >= 6:
                packet.bd_addr = self._format_bd_addr(bd_addr)
                packet.parameters["bd_addr"] = packet.bd_addr
            length -= 6
            
        elif cmd_bytes[0] == 0x11 and cmd_bytes[1] == 0x04:
            # HCI_Authentication_Requested
            packet.command_name = "HCI_Authentication_Requested"
            handle = snoop_file.read(2)
            if len(handle) >= 2:
                packet.connection_handle = self._format_connection_handle(handle)
                packet.parameters["connection_handle"] = packet.connection_handle
            length = 0
            
        elif cmd_bytes[0] == 0x09 and cmd_bytes[1] == 0x04:
            # HCI_Accept_Connection_Request
            packet.command_name = "HCI_Accept_Connection_Request"
            bd_addr = snoop_file.read(6)
            if len(bd_addr) >= 6:
                packet.bd_addr = self._format_bd_addr(bd_addr)
                packet.parameters["bd_addr"] = packet.bd_addr
            length -= 6
            
        elif cmd_bytes[0] == 0x01 and cmd_bytes[1] == 0x04:
            # HCI_Inquiry
            packet.command_name = "HCI_Inquiry"
            self.is_br_scanning = True
            self.num_found = 0
            self.scan_br_log.append(f"{packet.timestamp_iso}     C     HCI_Inquiry")
            
        elif cmd_bytes[0] == 0x02 and cmd_bytes[1] == 0x04:
            # HCI_Inquiry_Cancel
            packet.command_name = "HCI_Inquiry_Cancel"
            self.scan_br_log.append(f"Num of founded BR/EDR device : {self.num_found}")
            self.scan_br_log.append(f"{packet.timestamp_iso}     C     HCI_Inquiry_Cancel")
            self.is_br_scanning = False
            
        
        # Skip remaining bytes
        if length > 0:
            snoop_file.seek(length, 1)
            
        # Log connection commands
        if packet.command_name in ["HCI_Create_Connection", "HCI_Authentication_Requested", 
                                    "HCI_Accept_Connection_Request"]:
            log_entry = f"{packet.timestamp_iso}     C     {packet.command_name}"
            if packet.bd_addr:
                log_entry += f"     BD_ADDR: {packet.bd_addr}"
            if packet.connection_handle:
                log_entry += f"     Handle: {packet.connection_handle}"
            self.hci_connection_log.append(log_entry)
            
        return packet
    
    def _parse_hci_acl_data(self, snoop_file, timeline: int,
                            direction: str = "SENT") -> Optional[HCIUartPacket]:
        """Parse HCI ACL Data packet and decode the L2CAP payload it carries"""
        packet = HCIUartPacket()
        packet.packet_num = self.frame_count
        packet.timestamp_raw = timeline
        packet.timestamp_iso = self._format_timestamp(timeline)
        packet.packet_type = "ACL_DATA"
        packet.direction = direction

        # Read handle (2 bytes): 12 bit handle + PB flag + BC flag
        handle_bytes = snoop_file.read(2)
        if len(handle_bytes) < 2:
            return None

        handle_field = handle_bytes[0] | (handle_bytes[1] << 8)
        handle = handle_field & 0x0FFF
        pb_flag = (handle_field >> 12) & 0x03
        bc_flag = (handle_field >> 14) & 0x03
        packet.connection_handle = f'0x{handle:04x}'

        # Read length (2 bytes LE)
        length_bytes = snoop_file.read(2)
        if len(length_bytes) < 2:
            return None
        data_length = ((length_bytes[1] & 0x00FF) << 8) + (length_bytes[0] & 0x00FF)
        packet.data_length = data_length
        packet.param_len = data_length

        # Read and store data as hex
        acl_data = snoop_file.read(data_length)
        if acl_data:
            packet.raw_data = acl_data.hex()

        # ACL -> L2CAP -> protocol -> profile
        decoded = self.l2cap.parse_acl(handle, pb_flag, bc_flag, direction, acl_data)
        packet.protocol = decoded.get("protocol")
        packet.profile = decoded.get("profile")
        packet.parameters.update(decoded)

        return packet
    
    def _parse_hci_event(self, snoop_file, timeline: int) -> Optional[HCIUartPacket]:
        """Parse HCI Event packet"""
        packet = HCIUartPacket()
        packet.packet_num = self.frame_count
        packet.timestamp_raw = timeline
        packet.timestamp_iso = self._format_timestamp(timeline)
        packet.packet_type = "EVENT"
        packet.direction = "RECEIVED"
        
        # Read event code (1 byte)
        event_code_byte = snoop_file.read(1)
        if not event_code_byte:
            return None
        event_code = event_code_byte[0] & 0x00FF
        packet.event_code = f'0x{event_code:02x}'
        
        # Read param length (1 byte)
        length_byte = snoop_file.read(1)
        if not length_byte:
            return None
        length = length_byte[0] & 0x00FF
        packet.param_len = length
        
        # The whole parameter block is read at once, the decoders below then
        # work on that buffer so no branch has to track the remaining length
        data = snoop_file.read(length)
        packet.event_name = self._event_name(event_code)

        parser = self._event_parsers.get(event_code)
        if parser:
            parser(packet, data)
        elif data:
            packet.raw_data = data.hex()

        return packet

    def _event_name(self, event_code: int) -> str:
        """Event name using the HCI_<name> convention (LE/vendor keep their own prefix)"""
        name = get_event_name(event_code)
        if name.startswith(("LE_", "Vendor_", "Unknown_")):
            return name
        return f'HCI_{name}'

    # ------------------------------------------------------------------
    # Event parameter helpers
    # ------------------------------------------------------------------

    def _put(self, packet: HCIUartPacket, key: str, value: Any) -> None:
        """Store a parameter, skipping values missing from a truncated payload"""
        if value is not None:
            packet.parameters[key] = value

    def _set_status(self, packet: HCIUartPacket, data: bytes, offset: int = 0) -> Optional[int]:
        """Decode a Status parameter into status / status_name"""
        status = _u8(data, offset)
        if status is None:
            return None
        packet.status = f'0x{status:02x}'
        packet.parameters["status"] = packet.status
        packet.parameters["status_name"] = get_status_name(status)
        return status

    def _set_reason(self, packet: HCIUartPacket, data: bytes, offset: int) -> Optional[int]:
        """Decode a Reason parameter into reason / reason_name"""
        reason = _u8(data, offset)
        if reason is None:
            return None
        packet.reason = f'0x{reason:02x}'
        packet.parameters["reason"] = packet.reason
        packet.parameters["reason_name"] = get_status_name(reason)
        return reason

    def _set_handle(self, packet: HCIUartPacket, data: bytes, offset: int) -> Optional[str]:
        """Decode a Connection_Handle parameter"""
        if len(data) < offset + 2:
            return None
        packet.connection_handle = self._format_connection_handle(data[offset:offset + 2])
        packet.parameters["connection_handle"] = packet.connection_handle
        return packet.connection_handle

    def _set_bd_addr(self, packet: HCIUartPacket, data: bytes, offset: int) -> Optional[str]:
        """Decode a BD_ADDR parameter"""
        if len(data) < offset + 6:
            return None
        packet.bd_addr = self._format_bd_addr(data[offset:offset + 6])
        packet.parameters["bd_addr"] = packet.bd_addr
        return packet.bd_addr

    def _log_connection(self, packet: HCIUartPacket, name: Optional[str] = None) -> None:
        """Append a connection lifecycle entry to hci_connection_log"""
        log_entry = f"{packet.timestamp_iso}     E     {name or packet.event_name}"
        if packet.bd_addr:
            log_entry += f"     BD_ADDR: {packet.bd_addr}"
        if packet.status:
            log_entry += f"     Status: {packet.parameters.get('status_name', packet.status)}"
        if packet.connection_handle:
            log_entry += f"     Handle: {packet.connection_handle}"
        if packet.reason:
            log_entry += f"     Reason: {packet.parameters.get('reason_name', packet.reason)}"
        self.hci_connection_log.append(log_entry)

    # ------------------------------------------------------------------
    # Generic decoders shared by several events
    # ------------------------------------------------------------------

    def _evt_status_handle(self, packet: HCIUartPacket, data: bytes) -> None:
        """Status + Connection_Handle (Encryption_Key_Refresh_Complete, ...)"""
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)

    def _evt_handle_only(self, packet: HCIUartPacket, data: bytes) -> None:
        """Connection_Handle only (Flush_Occurred, QoS_Violation, ...)"""
        self._set_handle(packet, data, 0)

    def _evt_bd_addr_only(self, packet: HCIUartPacket, data: bytes) -> None:
        """BD_ADDR only (PIN_Code_Request, Link_Key_Request, IO_Capability_Request, ...)"""
        self._set_bd_addr(packet, data, 0)

    # ------------------------------------------------------------------
    # Inquiry / discovery events
    # ------------------------------------------------------------------

    def _evt_inquiry_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self.scan_br_log.append(f"Num of founded device : {self.num_found}")
        self.scan_br_log.append(f"{packet.timestamp_iso}     E     HCI_Inquiry_Complete")
        self.is_br_scanning = False

    def _evt_inquiry_result(self, packet: HCIUartPacket, data: bytes) -> None:
        """BD_ADDR + Page_Scan_Repetition_Mode + Class_of_Device + Clock_Offset per response"""
        num_responses = _u8(data, 0) or 0
        packet.parameters["num_responses"] = num_responses
        responses = []
        for index in range(num_responses):
            base = 1 + index * 14
            bd_addr = self._format_bd_addr(data[base:base + 6]) if len(data) >= base + 14 else None
            if bd_addr is None:
                break
            responses.append({
                "bd_addr": bd_addr,
                "page_scan_repetition_mode": _enum(_u8(data, base + 6), PAGE_SCAN_REPETITION_MODES),
                "class_of_device": f'0x{_u24(data, base + 9):06x}',
                "clock_offset": f'0x{_u16(data, base + 12):04x}',
            })
        if responses:
            packet.parameters["responses"] = responses
            packet.bd_addr = responses[0]["bd_addr"]
        self.num_found += len(responses)

    def _evt_inquiry_result_with_rssi(self, packet: HCIUartPacket, data: bytes) -> None:
        """Same as Inquiry_Result but one reserved byte less and an RSSI per response"""
        num_responses = _u8(data, 0) or 0
        packet.parameters["num_responses"] = num_responses
        responses = []
        for index in range(num_responses):
            base = 1 + index * 14
            bd_addr = self._format_bd_addr(data[base:base + 6]) if len(data) >= base + 14 else None
            if bd_addr is None:
                break
            responses.append({
                "bd_addr": bd_addr,
                "page_scan_repetition_mode": _enum(_u8(data, base + 6), PAGE_SCAN_REPETITION_MODES),
                "class_of_device": f'0x{_u24(data, base + 8):06x}',
                "clock_offset": f'0x{_u16(data, base + 11):04x}',
                "rssi": _s8(data, base + 13),
            })
        if responses:
            packet.parameters["responses"] = responses
            packet.bd_addr = responses[0]["bd_addr"]
        self.num_found += len(responses)

    def _evt_extended_inquiry_result(self, packet: HCIUartPacket, data: bytes) -> None:
        """Always carries a single response followed by up to 240 bytes of EIR data"""
        packet.parameters["num_responses"] = _u8(data, 0)
        self._set_bd_addr(packet, data, 1)
        self._put(packet, "page_scan_repetition_mode",
                  _enum(_u8(data, 7), PAGE_SCAN_REPETITION_MODES))
        class_of_device = _u24(data, 9)
        if class_of_device is not None:
            packet.parameters["class_of_device"] = f'0x{class_of_device:06x}'
        clock_offset = _u16(data, 12)
        if clock_offset is not None:
            packet.parameters["clock_offset"] = f'0x{clock_offset:04x}'
        self._put(packet, "rssi", _s8(data, 14))
        if len(data) > 15:
            packet.parameters["eir_data"] = data[15:].hex()
        self.num_found += 1

    def _evt_page_scan_repetition_mode_change(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_bd_addr(packet, data, 0)
        self._put(packet, "page_scan_repetition_mode",
                  _enum(_u8(data, 6), PAGE_SCAN_REPETITION_MODES))

    # ------------------------------------------------------------------
    # Connection management events
    # ------------------------------------------------------------------

    def _evt_connection_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._set_bd_addr(packet, data, 3)
        self._put(packet, "link_type", _enum(_u8(data, 9), LINK_TYPES))
        self._put(packet, "encryption_enabled", _enum(_u8(data, 10), ENCRYPTION_STATES))
        self._log_connection(packet)

    def _evt_connection_request(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_bd_addr(packet, data, 0)
        class_of_device = _u24(data, 6)
        if class_of_device is not None:
            packet.parameters["class_of_device"] = f'0x{class_of_device:06x}'
        self._put(packet, "link_type", _enum(_u8(data, 9), LINK_TYPES))
        self._log_connection(packet)

    def _evt_disconnection_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._set_reason(packet, data, 3)
        self._log_connection(packet)

    def _evt_role_change(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_bd_addr(packet, data, 1)
        self._put(packet, "new_role", _enum(_u8(data, 7), ROLES))
        self._log_connection(packet)

    def _evt_mode_change(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "current_mode", _enum(_u8(data, 3), CURRENT_MODES))
        self._put(packet, "interval", _u16(data, 4))

    def _evt_max_slots_change(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_handle(packet, data, 0)
        self._put(packet, "lmp_max_slots", _u8(data, 2))

    def _evt_read_clock_offset_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        clock_offset = _u16(data, 3)
        if clock_offset is not None:
            packet.parameters["clock_offset"] = f'0x{clock_offset:04x}'

    def _evt_connection_packet_type_changed(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        packet_type = _u16(data, 3)
        if packet_type is not None:
            packet.parameters["packet_type"] = f'0x{packet_type:04x}'

    def _evt_synchronous_connection_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._set_bd_addr(packet, data, 3)
        self._put(packet, "link_type", _enum(_u8(data, 9), LINK_TYPES))
        self._put(packet, "transmission_interval", _u8(data, 10))
        self._put(packet, "retransmission_window", _u8(data, 11))
        self._put(packet, "rx_packet_length", _u16(data, 12))
        self._put(packet, "tx_packet_length", _u16(data, 14))
        self._put(packet, "air_mode", _enum(_u8(data, 16), AIR_MODES))
        self._log_connection(packet)

    def _evt_synchronous_connection_changed(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "transmission_interval", _u8(data, 3))
        self._put(packet, "retransmission_window", _u8(data, 4))
        self._put(packet, "rx_packet_length", _u16(data, 5))
        self._put(packet, "tx_packet_length", _u16(data, 7))

    def _evt_sniff_subrating(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "max_tx_latency", _u16(data, 3))
        self._put(packet, "max_rx_latency", _u16(data, 5))
        self._put(packet, "min_remote_timeout", _u16(data, 7))
        self._put(packet, "min_local_timeout", _u16(data, 9))

    def _evt_link_supervision_timeout_changed(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_handle(packet, data, 0)
        self._put(packet, "link_supervision_timeout", _u16(data, 2))

    # ------------------------------------------------------------------
    # Security / pairing events
    # ------------------------------------------------------------------

    def _evt_authentication_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._log_connection(packet)

    def _evt_remote_name_request_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_bd_addr(packet, data, 1)
        if len(data) > 7:
            remote_name = data[7:].split(b'\x00')[0]
            packet.parameters["remote_name"] = remote_name.decode('utf-8', errors='replace')

    def _evt_encryption_change(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "encryption_enabled", _enum(_u8(data, 3), ENCRYPTION_STATES))
        self._log_connection(packet)

    def _evt_encryption_change_v2(self, packet: HCIUartPacket, data: bytes) -> None:
        self._evt_encryption_change(packet, data)
        self._put(packet, "encryption_key_size", _u8(data, 4))

    def _evt_link_key_type_changed(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "key_flag", _u8(data, 3))

    def _evt_link_key_notification(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_bd_addr(packet, data, 0)
        self._put(packet, "link_key", _hex(data, 6, 16))
        self._put(packet, "key_type", _enum(_u8(data, 22), LINK_KEY_TYPES))

    def _evt_io_capability_response(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_bd_addr(packet, data, 0)
        self._put(packet, "io_capability", _enum(_u8(data, 6), IO_CAPABILITIES))
        self._put(packet, "oob_data_present", _enum(_u8(data, 7), OOB_DATA_PRESENT))
        self._put(packet, "authentication_requirements",
                  _enum(_u8(data, 8), AUTHENTICATION_REQUIREMENTS))

    def _evt_user_confirmation_request(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_bd_addr(packet, data, 0)
        self._put(packet, "numeric_value", _u32(data, 6))

    def _evt_simple_pairing_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_bd_addr(packet, data, 1)
        self._log_connection(packet)

    def _evt_user_passkey_notification(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_bd_addr(packet, data, 0)
        self._put(packet, "passkey", _u32(data, 6))

    def _evt_keypress_notification(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_bd_addr(packet, data, 0)
        self._put(packet, "notification_type", _enum(_u8(data, 6), KEYPRESS_NOTIFICATION_TYPES))

    def _evt_remote_host_supported_features(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_bd_addr(packet, data, 0)
        self._put(packet, "host_supported_features", _hex(data, 6, 8))

    # ------------------------------------------------------------------
    # Remote device information events
    # ------------------------------------------------------------------

    def _evt_read_remote_supported_features_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "lmp_features", _hex(data, 3, 8))

    def _evt_read_remote_extended_features_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "page_number", _u8(data, 3))
        self._put(packet, "maximum_page_number", _u8(data, 4))
        self._put(packet, "extended_lmp_features", _hex(data, 5, 8))

    def _evt_read_remote_version_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "version", _u8(data, 3))
        self._put(packet, "manufacturer_name", _u16(data, 4))
        self._put(packet, "subversion", _u16(data, 6))

    # ------------------------------------------------------------------
    # Controller / flow control events
    # ------------------------------------------------------------------

    def _evt_command_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._put(packet, "num_hci_command_packets", _u8(data, 0))
        opcode = _u16(data, 1)
        if opcode is not None:
            packet.parameters["command_opcode"] = f'0x{opcode:04x}'
            packet.parameters["command_name"] = get_command_name(opcode)
        # Nearly every command returns Status as its first return parameter
        if len(data) > 3:
            self._set_status(packet, data, 3)
        if len(data) > 4:
            packet.parameters["return_parameters"] = data[4:].hex()

    def _evt_command_status(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._put(packet, "num_hci_command_packets", _u8(data, 1))
        opcode = _u16(data, 2)
        if opcode is not None:
            packet.parameters["command_opcode"] = f'0x{opcode:04x}'
            packet.parameters["command_name"] = get_command_name(opcode)

    def _evt_hardware_error(self, packet: HCIUartPacket, data: bytes) -> None:
        hardware_code = _u8(data, 0)
        if hardware_code is not None:
            packet.parameters["hardware_code"] = f'0x{hardware_code:02x}'

    def _evt_data_buffer_overflow(self, packet: HCIUartPacket, data: bytes) -> None:
        self._put(packet, "link_type", _enum(_u8(data, 0), LINK_TYPES))

    def _evt_number_of_completed_packets(self, packet: HCIUartPacket, data: bytes) -> None:
        num_handles = _u8(data, 0)
        if num_handles is None:
            return
        packet.parameters["number_of_handles"] = num_handles
        completed_packets = []
        for index in range(num_handles):
            base = 1 + index * 4
            handle = _u16(data, base)
            completed = _u16(data, base + 2)
            if handle is None or completed is None:
                break
            # Connection_Handle is 12 bits, bits 12-15 are reserved
            completed_packets.append({
                "connection_handle": f'0x{handle & 0x0FFF:04x}',
                "hc_num_of_completed_packets": completed
            })
        if completed_packets:
            packet.parameters["completed_packets"] = completed_packets

    def _evt_vendor_specific(self, packet: HCIUartPacket, data: bytes) -> None:
        vendor_type = _u8(data, 0)
        if vendor_type is None:
            return
        packet.parameters["vendor_event_type"] = f'0x{vendor_type:02x}'
        if vendor_type == 0x90:
            packet.event_name = "Enhanced_DBFW_Event"
        if len(data) > 1:
            packet.parameters["raw_parameters"] = data[1:].hex()

    # ------------------------------------------------------------------
    # LE meta event (0x3E) and its subevents
    # ------------------------------------------------------------------

    def _evt_le_meta(self, packet: HCIUartPacket, data: bytes) -> None:
        subevent_code = _u8(data, 0)
        if subevent_code is None:
            return
        packet.parameters["subevent_code"] = f'0x{subevent_code:02x}'
        packet.parameters["subevent_name"] = get_subevent_name(subevent_code)

        payload = data[1:]
        parser = self._le_subevent_parsers.get(subevent_code)
        if parser:
            parser(packet, payload)
        elif payload:
            packet.parameters["raw_parameters"] = payload.hex()

    def _le_connection_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "role", _enum(_u8(data, 3), ROLES))
        self._put(packet, "peer_address_type", _enum(_u8(data, 4), LE_ADDRESS_TYPES))
        self._set_bd_addr(packet, data, 5)
        self._put(packet, "connection_interval", _u16(data, 11))
        self._put(packet, "peripheral_latency", _u16(data, 13))
        self._put(packet, "supervision_timeout", _u16(data, 15))
        self._put(packet, "central_clock_accuracy", _enum(_u8(data, 17), CLOCK_ACCURACY))
        self._log_connection(packet, packet.parameters.get("subevent_name"))

    def _le_enhanced_connection_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "role", _enum(_u8(data, 3), ROLES))
        self._put(packet, "peer_address_type", _enum(_u8(data, 4), LE_ADDRESS_TYPES))
        self._set_bd_addr(packet, data, 5)
        if len(data) >= 17:
            packet.parameters["local_resolvable_private_address"] = self._format_bd_addr(data[11:17])
        if len(data) >= 23:
            packet.parameters["peer_resolvable_private_address"] = self._format_bd_addr(data[17:23])
        self._put(packet, "connection_interval", _u16(data, 23))
        self._put(packet, "peripheral_latency", _u16(data, 25))
        self._put(packet, "supervision_timeout", _u16(data, 27))
        self._put(packet, "central_clock_accuracy", _enum(_u8(data, 29), CLOCK_ACCURACY))
        self._log_connection(packet, packet.parameters.get("subevent_name"))

    def _le_advertising_report(self, packet: HCIUartPacket, data: bytes) -> None:
        num_reports = _u8(data, 0) or 0
        packet.parameters["num_reports"] = num_reports
        reports = []
        offset = 1
        for _ in range(num_reports):
            data_length = _u8(data, offset + 8)
            if data_length is None or len(data) < offset + 10 + data_length:
                break
            reports.append({
                "event_type": _enum(_u8(data, offset), LE_ADV_EVENT_TYPES),
                "address_type": _enum(_u8(data, offset + 1), LE_ADDRESS_TYPES),
                "address": self._format_bd_addr(data[offset + 2:offset + 8]),
                "data_length": data_length,
                "data": data[offset + 9:offset + 9 + data_length].hex(),
                "rssi": _s8(data, offset + 9 + data_length),
            })
            offset += 10 + data_length
        if reports:
            packet.parameters["reports"] = reports

    def _le_directed_advertising_report(self, packet: HCIUartPacket, data: bytes) -> None:
        num_reports = _u8(data, 0) or 0
        packet.parameters["num_reports"] = num_reports
        reports = []
        for index in range(num_reports):
            base = 1 + index * 16
            if len(data) < base + 16:
                break
            reports.append({
                "event_type": _enum(_u8(data, base), LE_ADV_EVENT_TYPES),
                "address_type": _enum(_u8(data, base + 1), LE_ADDRESS_TYPES),
                "address": self._format_bd_addr(data[base + 2:base + 8]),
                "direct_address_type": _enum(_u8(data, base + 8), LE_ADDRESS_TYPES),
                "direct_address": self._format_bd_addr(data[base + 9:base + 15]),
                "rssi": _s8(data, base + 15),
            })
        if reports:
            packet.parameters["reports"] = reports

    def _le_extended_advertising_report(self, packet: HCIUartPacket, data: bytes) -> None:
        num_reports = _u8(data, 0) or 0
        packet.parameters["num_reports"] = num_reports
        reports = []
        offset = 1
        for _ in range(num_reports):
            data_length = _u8(data, offset + 23)
            if data_length is None or len(data) < offset + 24 + data_length:
                break
            event_type = _u16(data, offset)
            reports.append({
                "event_type": f'0x{event_type:04x}',
                "event_type_flags": self._ext_adv_event_type_flags(event_type),
                "address_type": _enum(_u8(data, offset + 2), LE_ADDRESS_TYPES),
                "address": self._format_bd_addr(data[offset + 3:offset + 9]),
                "primary_phy": _enum(_u8(data, offset + 9), LE_PHY_TYPES),
                "secondary_phy": _enum(_u8(data, offset + 10), LE_PHY_TYPES),
                "advertising_sid": _u8(data, offset + 11),
                "tx_power": _s8(data, offset + 12),
                "rssi": _s8(data, offset + 13),
                "periodic_advertising_interval": _u16(data, offset + 14),
                "direct_address_type": _enum(_u8(data, offset + 16), LE_ADDRESS_TYPES),
                "direct_address": self._format_bd_addr(data[offset + 17:offset + 23]),
                "data_length": data_length,
                "data": data[offset + 24:offset + 24 + data_length].hex(),
            })
            offset += 24 + data_length
        if reports:
            packet.parameters["reports"] = reports

    @staticmethod
    def _ext_adv_event_type_flags(event_type: int) -> List[str]:
        """Decode the Event_Type bit field of an extended advertising report"""
        flags = []
        for bit, name in enumerate(("connectable", "scannable", "directed",
                                    "scan_response", "legacy")):
            if event_type & (1 << bit):
                flags.append(name)
        data_status = (event_type >> 5) & 0x03
        flags.append(("complete", "incomplete_more_to_come",
                      "incomplete_truncated", "reserved")[data_status])
        return flags

    def _le_connection_update_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "connection_interval", _u16(data, 3))
        self._put(packet, "peripheral_latency", _u16(data, 5))
        self._put(packet, "supervision_timeout", _u16(data, 7))

    def _le_read_remote_features_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "le_features", _hex(data, 3, 8))

    def _le_long_term_key_request(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_handle(packet, data, 0)
        self._put(packet, "random_number", _hex(data, 2, 8))
        encrypted_diversifier = _u16(data, 10)
        if encrypted_diversifier is not None:
            packet.parameters["encrypted_diversifier"] = f'0x{encrypted_diversifier:04x}'

    def _le_remote_connection_parameter_request(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_handle(packet, data, 0)
        self._put(packet, "interval_min", _u16(data, 2))
        self._put(packet, "interval_max", _u16(data, 4))
        self._put(packet, "max_latency", _u16(data, 6))
        self._put(packet, "timeout", _u16(data, 8))

    def _le_data_length_change(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_handle(packet, data, 0)
        self._put(packet, "max_tx_octets", _u16(data, 2))
        self._put(packet, "max_tx_time", _u16(data, 4))
        self._put(packet, "max_rx_octets", _u16(data, 6))
        self._put(packet, "max_rx_time", _u16(data, 8))

    def _le_phy_update_complete(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "tx_phy", _enum(_u8(data, 3), LE_PHY_TYPES))
        self._put(packet, "rx_phy", _enum(_u8(data, 4), LE_PHY_TYPES))

    def _le_periodic_advertising_sync_established(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        sync_handle = _u16(data, 1)
        if sync_handle is not None:
            packet.parameters["sync_handle"] = f'0x{sync_handle:04x}'
        self._put(packet, "advertising_sid", _u8(data, 3))
        self._put(packet, "advertiser_address_type", _enum(_u8(data, 4), LE_ADDRESS_TYPES))
        self._set_bd_addr(packet, data, 5)
        self._put(packet, "advertiser_phy", _enum(_u8(data, 11), LE_PHY_TYPES))
        self._put(packet, "periodic_advertising_interval", _u16(data, 12))
        self._put(packet, "advertiser_clock_accuracy", _enum(_u8(data, 14), CLOCK_ACCURACY))

    def _le_periodic_advertising_sync_lost(self, packet: HCIUartPacket, data: bytes) -> None:
        sync_handle = _u16(data, 0)
        if sync_handle is not None:
            packet.parameters["sync_handle"] = f'0x{sync_handle:04x}'

    def _le_advertising_set_terminated(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._put(packet, "advertising_handle", _u8(data, 1))
        self._set_handle(packet, data, 2)
        self._put(packet, "num_completed_extended_advertising_events", _u8(data, 4))

    def _le_scan_request_received(self, packet: HCIUartPacket, data: bytes) -> None:
        self._put(packet, "advertising_handle", _u8(data, 0))
        self._put(packet, "scanner_address_type", _enum(_u8(data, 1), LE_ADDRESS_TYPES))
        self._set_bd_addr(packet, data, 2)

    def _le_channel_selection_algorithm(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_handle(packet, data, 0)
        self._put(packet, "channel_selection_algorithm", _u8(data, 2))

    def _le_cis_request(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_handle(packet, data, 0)
        cis_handle = _u16(data, 2)
        if cis_handle is not None:
            packet.parameters["cis_connection_handle"] = f'0x{cis_handle:04x}'
        self._put(packet, "cig_id", _u8(data, 4))
        self._put(packet, "cis_id", _u8(data, 5))

    def _le_transmit_power_reporting(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "reason", _u8(data, 3))
        self._put(packet, "phy", _enum(_u8(data, 4), LE_PHY_TYPES))
        self._put(packet, "tx_power_level", _s8(data, 5))
        self._put(packet, "tx_power_level_flag", _u8(data, 6))
        self._put(packet, "delta", _s8(data, 7))

    def _le_subrate_change(self, packet: HCIUartPacket, data: bytes) -> None:
        self._set_status(packet, data, 0)
        self._set_handle(packet, data, 1)
        self._put(packet, "subrate_factor", _u16(data, 3))
        self._put(packet, "peripheral_latency", _u16(data, 5))
        self._put(packet, "continuation_number", _u16(data, 7))
        self._put(packet, "supervision_timeout", _u16(data, 9))


    def parse_cfa_file(self, cfa_path: str) -> List[HCIUartPacket]:
        """
        Parse .cfa file and extract all HCI UART packets.
        Exactly following get_HCI_VOC_log from BTHelper.py
        
        Args:
            cfa_path: Path to the .cfa file
            
        Returns:
            List of HCIUartPacket objects
        """
        self.packets = []
        self.frame_count = 0
        self.is_br_scanning = False
        self.num_found = 0
        self.scan_br_log = []
        self.hci_connection_log = []
        self.l2cap.reset()

        BtSnoopHeaderLen = 15  # Same as BTHelper.py
        TimeStampLen = 8
        PacketTypeLen = 1
        
        try:
            with open(cfa_path, "rb") as snoop_file:
                # Read BTSnoop header (15 bytes) - same as BTHelper.py
                header_bytes = snoop_file.read(BtSnoopHeaderLen)
                if not header_bytes:
                    print("Error: Empty file")
                    return self.packets
                    
                # Validate header
                for i in range(len(header_bytes)):
                    if header_bytes[i] != BtUtil.BTSNOOP_HEADER[i]:
                        print("Warning: Not a standard snoop file")
                        break

                # Skip 1 byte after header (same as BTHelper.py)
                snoop_file.seek(1, 1)

                while True:
                    self.frame_count += 1
                    
                    # BTSnoop record header (16 bytes): original length,
                    # included length, packet flags, cumulative drops.
                    # Packet flags bit 0 holds the direction.
                    record_header = snoop_file.read(16)
                    if len(record_header) < 16:
                        break
                    packet_flags = int.from_bytes(record_header[8:12], byteorder='big')
                    direction = "RECEIVED" if packet_flags & 0x01 else "SENT"

                    # Read timestamp (8 bytes)
                    time_buffer = snoop_file.read(TimeStampLen)
                    if not time_buffer or len(time_buffer) < TimeStampLen:
                        break
                        
                    # Read packet type (1 byte)
                    packet_type_bytes = snoop_file.read(PacketTypeLen)
                    if not packet_type_bytes:
                        break
                        
                    packet_type = packet_type_bytes[0]
                    
                    # Convert timestamp
                    packet_time = self._to_time(time_buffer)
                    timeline = packet_time if packet_time > 0 else 0
                    
                    # Parse based on packet type - same as BTHelper.py
                    if packet_type == self.HCI_COMMAND_PACKET:
                        hci_packet = self._parse_hci_command(snoop_file, timeline)
                        if hci_packet:
                            self.packets.append(hci_packet)

                    elif packet_type == self.HCI_ACL_DATA_PACKET:
                        hci_packet = self._parse_hci_acl_data(snoop_file, timeline, direction)
                        if hci_packet:
                            self.packets.append(hci_packet)

                    elif packet_type == self.HCI_SCO_DATA_PACKET:
                        # Skip SCO packets
                        continue

                    elif packet_type == self.HCI_EVENT_PACKET:
                        hci_packet = self._parse_hci_event(snoop_file, timeline)
                        if hci_packet:
                            self.packets.append(hci_packet)
                            
                    else:
                        # Unknown packet type - end of file
                        print(f"Unknown packet type: {packet_type} at frame {self.frame_count}")
                        break

        except FileNotFoundError:
            print(f"Error: File not found: {cfa_path}")
        except Exception as e:
            print(f"Error parsing CFA file: {e}")
            import traceback
            traceback.print_exc()
            
        return self.packets
    
    
    def export_hci_log_json(self, output_path: str) -> None:
        """
        Export HCI log - only packets array without metadata.
        
        Args:
            output_path: Path to output JSON file
        """
        # Export only packets array
        packets_list = [p.to_dict() for p in self.packets]
            
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(packets_list, f, indent=2, ensure_ascii=False)
            
        print(f"Exported HCI log to {output_path}")
        print(f"  - Total packets: {len(self.packets)}")


# Example usage
if __name__ == "__main__":
    # Test with sample file
    parser = HCIUartParser()
    
    cfa_file = "test/btsnoop_hci_202607241205.cfa"
    output_file = "test/hci_uart_packets.json"
    
    if os.path.exists(cfa_file):
        parser.parse_cfa_file(cfa_file)
        parser.export_hci_log_json(output_file)
    else:
        print(f"Test file not found: {cfa_file}")
