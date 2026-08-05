"""
L2CAP and upper protocol definitions used to classify HCI ACL data.

Covers the decode chain: ACL -> L2CAP -> (fixed CID protocol | PSM based
protocol) -> profile, following the Bluetooth Core Specification and the
profile specs (A2DP/AVRCP/HFP/HID/PAN).
"""

# ---------------------------------------------------------------------------
# ACL header
# ---------------------------------------------------------------------------

# Packet_Boundary_Flag (bits 12-13 of the ACL handle field)
ACL_PB_FLAGS = {
    0x00: "First_Non_Automatically_Flushable",
    0x01: "Continuing_Fragment",
    0x02: "First_Automatically_Flushable",
    0x03: "Complete_PDU_Automatically_Flushable",
}

# Broadcast_Flag (bits 14-15 of the ACL handle field)
ACL_BC_FLAGS = {
    0x00: "Point_To_Point",
    0x01: "BR_EDR_Broadcast",
    0x02: "Reserved",
    0x03: "Reserved",
}

ACL_CONTINUATION_PB_FLAG = 0x01

# ---------------------------------------------------------------------------
# L2CAP channels
# ---------------------------------------------------------------------------

L2CAP_FIXED_CIDS = {
    0x0000: "Null",
    0x0001: "L2CAP_Signaling",
    0x0002: "Connectionless",
    0x0003: "AMP_Manager",
    0x0004: "ATT",
    0x0005: "LE_L2CAP_Signaling",
    0x0006: "SMP",
    0x0007: "BR_EDR_SMP",
    0x003F: "AMP_Test_Manager",
}

# Protocol carried by each fixed channel
L2CAP_FIXED_CID_PROTOCOLS = {
    0x0001: "L2CAP_Signaling",
    0x0002: "L2CAP_Connectionless",
    0x0003: "AMP_Manager",
    0x0004: "ATT",
    0x0005: "L2CAP_Signaling",
    0x0006: "SMP",
    0x0007: "SMP",
}

L2CAP_DYNAMIC_CID_START = 0x0040

L2CAP_SIGNALING_CODES = {
    0x01: "Command_Reject",
    0x02: "Connection_Request",
    0x03: "Connection_Response",
    0x04: "Configuration_Request",
    0x05: "Configuration_Response",
    0x06: "Disconnection_Request",
    0x07: "Disconnection_Response",
    0x08: "Echo_Request",
    0x09: "Echo_Response",
    0x0A: "Information_Request",
    0x0B: "Information_Response",
    0x0C: "Create_Channel_Request",
    0x0D: "Create_Channel_Response",
    0x0E: "Move_Channel_Request",
    0x0F: "Move_Channel_Response",
    0x10: "Move_Channel_Confirmation",
    0x11: "Move_Channel_Confirmation_Response",
    0x12: "Connection_Parameter_Update_Request",
    0x13: "Connection_Parameter_Update_Response",
    0x14: "LE_Credit_Based_Connection_Request",
    0x15: "LE_Credit_Based_Connection_Response",
    0x16: "LE_Flow_Control_Credit",
    0x17: "L2CAP_Credit_Based_Connection_Request",
    0x18: "L2CAP_Credit_Based_Connection_Response",
    0x19: "L2CAP_Credit_Based_Reconfigure_Request",
    0x1A: "L2CAP_Credit_Based_Reconfigure_Response",
}

L2CAP_CONNECTION_RESULTS = {
    0x0000: "Successful",
    0x0001: "Pending",
    0x0002: "PSM_Not_Supported",
    0x0003: "Security_Block",
    0x0004: "No_Resources_Available",
    0x0006: "Invalid_Source_CID",
    0x0007: "Source_CID_Already_Allocated",
}

# ---------------------------------------------------------------------------
# PSM -> protocol -> profile
# ---------------------------------------------------------------------------

L2CAP_PSMS = {
    0x0001: "SDP",
    0x0003: "RFCOMM",
    0x0005: "TCS_BIN",
    0x0007: "TCS_BIN_CORDLESS",
    0x000F: "BNEP",
    0x0011: "HID_Control",
    0x0013: "HID_Interrupt",
    0x0015: "UPnP",
    0x0017: "AVCTP",
    0x0019: "AVDTP",
    0x001B: "AVCTP_Browsing",
    0x001D: "UDI_C_Plane",
    0x001F: "ATT",
    0x0021: "3DSP",
    0x0023: "LE_PSM_IPSP",
    0x0025: "OTS",
    0x0027: "EATT",
}

# Protocol spoken on a channel opened with the given PSM
PSM_PROTOCOLS = {
    0x0001: "SDP",
    0x0003: "RFCOMM",
    0x000F: "BNEP",
    0x0011: "HIDP",
    0x0013: "HIDP",
    0x0017: "AVCTP",
    0x0019: "AVDTP",
    0x001B: "AVCTP_Browsing",
    0x001F: "ATT",
    0x0027: "ATT",
}

# Profile a decoded protocol belongs to
PROTOCOL_PROFILES = {
    "L2CAP_Signaling": "L2CAP",
    "L2CAP_Connectionless": "L2CAP",
    "AMP_Manager": "AMP",
    "ATT": "GATT",
    "SMP": "Security_Manager",
    "SDP": "SDP",
    "RFCOMM": "RFCOMM",
    "BNEP": "PAN",
    "HIDP": "HID",
    "AVDTP": "A2DP",
    "AVDTP_Media": "A2DP",
    "AVCTP": "AVRCP",
    "AVCTP_Browsing": "AVRCP",
}

# ---------------------------------------------------------------------------
# ATT (GATT)
# ---------------------------------------------------------------------------

ATT_OPCODES = {
    0x01: "Error_Response",
    0x02: "Exchange_MTU_Request",
    0x03: "Exchange_MTU_Response",
    0x04: "Find_Information_Request",
    0x05: "Find_Information_Response",
    0x06: "Find_By_Type_Value_Request",
    0x07: "Find_By_Type_Value_Response",
    0x08: "Read_By_Type_Request",
    0x09: "Read_By_Type_Response",
    0x0A: "Read_Request",
    0x0B: "Read_Response",
    0x0C: "Read_Blob_Request",
    0x0D: "Read_Blob_Response",
    0x0E: "Read_Multiple_Request",
    0x0F: "Read_Multiple_Response",
    0x10: "Read_By_Group_Type_Request",
    0x11: "Read_By_Group_Type_Response",
    0x12: "Write_Request",
    0x13: "Write_Response",
    0x16: "Prepare_Write_Request",
    0x17: "Prepare_Write_Response",
    0x18: "Execute_Write_Request",
    0x19: "Execute_Write_Response",
    0x1B: "Handle_Value_Notification",
    0x1D: "Handle_Value_Indication",
    0x1E: "Handle_Value_Confirmation",
    0x20: "Read_Multiple_Variable_Request",
    0x21: "Read_Multiple_Variable_Response",
    0x23: "Multiple_Handle_Value_Notification",
    0x52: "Write_Command",
    0xD2: "Signed_Write_Command",
}

ATT_ERROR_CODES = {
    0x01: "Invalid_Handle",
    0x02: "Read_Not_Permitted",
    0x03: "Write_Not_Permitted",
    0x04: "Invalid_PDU",
    0x05: "Insufficient_Authentication",
    0x06: "Request_Not_Supported",
    0x07: "Invalid_Offset",
    0x08: "Insufficient_Authorization",
    0x09: "Prepare_Queue_Full",
    0x0A: "Attribute_Not_Found",
    0x0B: "Attribute_Not_Long",
    0x0C: "Insufficient_Encryption_Key_Size",
    0x0D: "Invalid_Attribute_Value_Length",
    0x0E: "Unlikely_Error",
    0x0F: "Insufficient_Encryption",
    0x10: "Unsupported_Group_Type",
    0x11: "Insufficient_Resources",
    0x12: "Database_Out_Of_Sync",
    0x13: "Value_Not_Allowed",
}

# ATT opcodes whose first parameter is a 2 byte attribute handle
ATT_OPCODES_WITH_HANDLE = (0x0A, 0x0B, 0x0C, 0x12, 0x16, 0x1B, 0x1D, 0x52, 0xD2)

# ---------------------------------------------------------------------------
# SMP
# ---------------------------------------------------------------------------

SMP_OPCODES = {
    0x01: "Pairing_Request",
    0x02: "Pairing_Response",
    0x03: "Pairing_Confirm",
    0x04: "Pairing_Random",
    0x05: "Pairing_Failed",
    0x06: "Encryption_Information",
    0x07: "Central_Identification",
    0x08: "Identity_Information",
    0x09: "Identity_Address_Information",
    0x0A: "Signing_Information",
    0x0B: "Security_Request",
    0x0C: "Pairing_Public_Key",
    0x0D: "Pairing_DHKey_Check",
    0x0E: "Pairing_Keypress_Notification",
}

SMP_FAILURE_REASONS = {
    0x01: "Passkey_Entry_Failed",
    0x02: "OOB_Not_Available",
    0x03: "Authentication_Requirements",
    0x04: "Confirm_Value_Failed",
    0x05: "Pairing_Not_Supported",
    0x06: "Encryption_Key_Size",
    0x07: "Command_Not_Supported",
    0x08: "Unspecified_Reason",
    0x09: "Repeated_Attempts",
    0x0A: "Invalid_Parameters",
    0x0B: "DHKey_Check_Failed",
    0x0C: "Numeric_Comparison_Failed",
    0x0D: "BR_EDR_Pairing_In_Progress",
    0x0E: "Cross_Transport_Key_Derivation_Not_Allowed",
    0x0F: "Key_Rejected",
}

SMP_IO_CAPABILITIES = {
    0x00: "DisplayOnly",
    0x01: "DisplayYesNo",
    0x02: "KeyboardOnly",
    0x03: "NoInputNoOutput",
    0x04: "KeyboardDisplay",
}

# ---------------------------------------------------------------------------
# SDP
# ---------------------------------------------------------------------------

SDP_PDU_IDS = {
    0x01: "Error_Response",
    0x02: "Service_Search_Request",
    0x03: "Service_Search_Response",
    0x04: "Service_Attribute_Request",
    0x05: "Service_Attribute_Response",
    0x06: "Service_Search_Attribute_Request",
    0x07: "Service_Search_Attribute_Response",
}

# ---------------------------------------------------------------------------
# RFCOMM
# ---------------------------------------------------------------------------

# Control field with the Poll/Final bit (0x10) masked out
RFCOMM_FRAME_TYPES = {
    0x2F: "SABM",
    0x63: "UA",
    0x0F: "DM",
    0x43: "DISC",
    0xEF: "UIH",
    0x03: "UI",
}

RFCOMM_PF_BIT = 0x10

# Multiplexer control channel (DLCI 0) message types, value = type field >> 2
RFCOMM_MCC_TYPES = {
    0x04: "Non_Supported_Command",
    0x08: "Test",
    0x14: "Remote_Line_Status",
    0x18: "Flow_Control_Off",
    0x20: "DLC_Parameter_Negotiation",
    0x24: "Remote_Port_Negotiation",
    0x28: "Flow_Control_On",
    0x34: "Service_Negotiation",
    0x38: "Modem_Status",
}

# ---------------------------------------------------------------------------
# AVDTP (A2DP)
# ---------------------------------------------------------------------------

AVDTP_PACKET_TYPES = {
    0x00: "Single",
    0x01: "Start",
    0x02: "Continue",
    0x03: "End",
}

AVDTP_MESSAGE_TYPES = {
    0x00: "Command",
    0x01: "General_Reject",
    0x02: "Response_Accept",
    0x03: "Response_Reject",
}

AVDTP_SIGNAL_IDS = {
    0x01: "AVDTP_DISCOVER",
    0x02: "AVDTP_GET_CAPABILITIES",
    0x03: "AVDTP_SET_CONFIGURATION",
    0x04: "AVDTP_GET_CONFIGURATION",
    0x05: "AVDTP_RECONFIGURE",
    0x06: "AVDTP_OPEN",
    0x07: "AVDTP_START",
    0x08: "AVDTP_CLOSE",
    0x09: "AVDTP_SUSPEND",
    0x0A: "AVDTP_ABORT",
    0x0B: "AVDTP_SECURITY_CONTROL",
    0x0C: "AVDTP_GET_ALL_CAPABILITIES",
    0x0D: "AVDTP_DELAYREPORT",
}

# ---------------------------------------------------------------------------
# AVCTP / AVRCP
# ---------------------------------------------------------------------------

AVCTP_PACKET_TYPES = {
    0x00: "Single",
    0x01: "Start",
    0x02: "Continue",
    0x03: "End",
}

AVCTP_PROFILE_IDS = {
    0x110E: "AV_Remote_Control",
    0x110F: "AV_Remote_Control_Controller",
    0x1124: "HID",
}

AVC_CTYPES = {
    0x00: "CONTROL",
    0x01: "STATUS",
    0x02: "SPECIFIC_INQUIRY",
    0x03: "NOTIFY",
    0x04: "GENERAL_INQUIRY",
    0x08: "NOT_IMPLEMENTED",
    0x09: "ACCEPTED",
    0x0A: "REJECTED",
    0x0B: "IN_TRANSITION",
    0x0C: "IMPLEMENTED_STABLE",
    0x0D: "CHANGED",
    0x0F: "INTERIM",
}

AVC_SUBUNIT_TYPES = {
    0x00: "Monitor",
    0x04: "Audio",
    0x05: "Panel",
    0x09: "Panel",
    0x1C: "Vendor_Unique",
    0x1F: "Unit",
}

AVC_OPCODES = {
    0x00: "VENDOR_DEPENDENT",
    0x30: "UNIT_INFO",
    0x31: "SUBUNIT_INFO",
    0x7C: "PASS_THROUGH",
}

AVRCP_PDU_IDS = {
    0x10: "GetCapabilities",
    0x11: "ListPlayerApplicationSettingAttributes",
    0x12: "ListPlayerApplicationSettingValues",
    0x13: "GetCurrentPlayerApplicationSettingValue",
    0x14: "SetPlayerApplicationSettingValue",
    0x15: "GetPlayerApplicationSettingAttributeText",
    0x16: "GetPlayerApplicationSettingValueText",
    0x17: "InformDisplayableCharacterSet",
    0x18: "InformBatteryStatusOfCT",
    0x20: "GetElementAttributes",
    0x30: "GetPlayStatus",
    0x31: "RegisterNotification",
    0x40: "RequestContinuingResponse",
    0x41: "AbortContinuingResponse",
    0x50: "SetAbsoluteVolume",
    0x60: "SetAddressedPlayer",
    0x70: "SetBrowsedPlayer",
    0x71: "GetFolderItems",
    0x72: "ChangePath",
    0x73: "GetItemAttributes",
    0x74: "PlayItem",
    0x75: "GetTotalNumberOfItems",
    0x80: "Search",
    0x90: "AddToNowPlaying",
}

AVRCP_EVENT_IDS = {
    0x01: "PLAYBACK_STATUS_CHANGED",
    0x02: "TRACK_CHANGED",
    0x03: "TRACK_REACHED_END",
    0x04: "TRACK_REACHED_START",
    0x05: "PLAYBACK_POS_CHANGED",
    0x06: "BATT_STATUS_CHANGED",
    0x07: "SYSTEM_STATUS_CHANGED",
    0x08: "PLAYER_APPLICATION_SETTING_CHANGED",
    0x09: "NOW_PLAYING_CONTENT_CHANGED",
    0x0A: "AVAILABLE_PLAYERS_CHANGED",
    0x0B: "ADDRESSED_PLAYER_CHANGED",
    0x0C: "UIDS_CHANGED",
    0x0D: "VOLUME_CHANGED",
}

AVRCP_PASS_THROUGH_OPERATIONS = {
    0x41: "VOLUME_UP",
    0x42: "VOLUME_DOWN",
    0x43: "MUTE",
    0x44: "PLAY",
    0x45: "STOP",
    0x46: "PAUSE",
    0x47: "RECORD",
    0x48: "REWIND",
    0x49: "FAST_FORWARD",
    0x4A: "EJECT",
    0x4B: "FORWARD",
    0x4C: "BACKWARD",
}

BLUETOOTH_SIG_COMPANY_ID = 0x001958

# ---------------------------------------------------------------------------
# HID (HIDP)
# ---------------------------------------------------------------------------

HIDP_TRANSACTION_TYPES = {
    0x00: "HANDSHAKE",
    0x01: "HID_CONTROL",
    0x04: "GET_REPORT",
    0x05: "SET_REPORT",
    0x06: "GET_PROTOCOL",
    0x07: "SET_PROTOCOL",
    0x08: "GET_IDLE",
    0x09: "SET_IDLE",
    0x0A: "DATA",
    0x0B: "DATC",
}

HIDP_REPORT_TYPES = {
    0x00: "Other",
    0x01: "Input",
    0x02: "Output",
    0x03: "Feature",
}

# ---------------------------------------------------------------------------
# BNEP (PAN)
# ---------------------------------------------------------------------------

BNEP_PACKET_TYPES = {
    0x00: "General_Ethernet",
    0x01: "Control",
    0x02: "Compressed_Ethernet",
    0x03: "Compressed_Ethernet_Source_Only",
    0x04: "Compressed_Ethernet_Dest_Only",
}

# ---------------------------------------------------------------------------
# Media stream (RTP inside AVDTP)
# ---------------------------------------------------------------------------

RTP_VERSION = 0x02
RTP_DYNAMIC_PAYLOAD_TYPES = range(96, 128)


def get_fixed_cid_name(cid: int) -> str:
    """Name of a fixed L2CAP channel, or a placeholder for dynamic CIDs."""
    if cid in L2CAP_FIXED_CIDS:
        return L2CAP_FIXED_CIDS[cid]
    if cid >= L2CAP_DYNAMIC_CID_START:
        return "Dynamic"
    return f"Reserved_0x{cid:04x}"


def get_psm_name(psm: int) -> str:
    """Name of a PSM value."""
    return L2CAP_PSMS.get(psm, f"Unknown_PSM_0x{psm:04x}")


def get_profile(protocol: str) -> str:
    """Profile that a protocol belongs to."""
    return PROTOCOL_PROFILES.get(protocol, "Unknown")
