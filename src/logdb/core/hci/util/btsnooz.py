import base64
import os
import struct
import zlib


SNOOZ_FILE = "snooz_VOC.cfa"
QC_ENH_SNOOZ_FILE = "snooz_qc_enh.cfa"
LSI_FW_SNOOZ_FILE = "snooz_lsi.cfa"

BT_PERMANENT_LOG_FILE = "BT_PERMANENT_LOG.log"

class BtSnooz:
  # Enumeration of the values the 'type' field can take in a btsnooz
  # header. These values come from the Bluetooth stack's internal
  # representation of packet types.
  TYPE_IN_EVT = 0x10
  TYPE_IN_ACL = 0x11
  TYPE_IN_SCO = 0x12
  TYPE_OUT_CMD = 0x20
  TYPE_OUT_ACL = 0x21
  TYPE_OUT_SCO = 0x22

  def type_to_direction(self, type):
    """
    Returns the inbound/outbound direction of a packet given its type.
    0 = sent packet
    1 = received packet
    """
    if type in [self.TYPE_IN_EVT, self.TYPE_IN_ACL, self.TYPE_IN_SCO]:
      return 1
    return 0


  def type_to_hci(self, type):
    """
    Returns the HCI type of a packet given its btsnooz type.
    """
    if type == self.TYPE_OUT_CMD:
      return b'\x01'
    if type == self.TYPE_IN_ACL or type == self.TYPE_OUT_ACL:
      return b'\x02'
    if type == self.TYPE_IN_SCO or type == self.TYPE_OUT_SCO:
      return b'\x03'
    if type == self.TYPE_IN_EVT:
      return b'\x04'


  def decode_snooz(self, snooz, output):
    """
    Decodes all known versions of a btsnooz file into a btsnoop file.
    """
    version, last_timestamp_ms = struct.unpack_from('=bQ', snooz)

    if version != 1 and version != 2:
      print('Unsupported btsnooz version: %s\n' % version)
      exit(1)
    try:
      # Oddly, the file header (9 bytes) is not compressed, but the rest is.
      decompressed = zlib.decompress(snooz[9:])

      output.write(b'btsnoop\x00\x00\x00\x00\x01\x00\x00\x03\xea')

      if version == 1:
        self.decode_snooz_v1(decompressed, last_timestamp_ms, output)
      elif version == 2:
        self.decode_snooz_v2(decompressed, last_timestamp_ms, output)
    except:
      print("btsnooz.py : decode_snooz : exception", output)


  def decode_snooz_v1(self, decompressed, last_timestamp_ms, output):
    """
    Decodes btsnooz v1 files into a btsnoop file.
    """
    # An unfortunate consequence of the file format design: we have to do a
    # pass of the entire file to determine the timestamp of the first packet.
    first_timestamp_ms = last_timestamp_ms + 0x00dcddb30f2f8000
    offset = 0
    while offset < len(decompressed):
      length, delta_time_ms, type = struct.unpack_from('=HIb', decompressed, offset)
      offset += 7 + length - 1
      first_timestamp_ms -= delta_time_ms

    # Second pass does the actual writing out to stdout.
    offset = 0
    while offset < len(decompressed):
      length, delta_time_ms, type = struct.unpack_from('=HIb', decompressed, offset)
      first_timestamp_ms += delta_time_ms
      offset += 7
      output.write(struct.pack('>II', length, length))
      output.write(struct.pack('>II', self.type_to_direction(type), 0))
      output.write(struct.pack('>II', (first_timestamp_ms >> 32), (first_timestamp_ms & 0xFFFFFFFF)))
      output.write(self.type_to_hci(type))
      output.write(decompressed[offset : offset + length - 1])
      offset += length - 1


  def decode_snooz_v2(self, decompressed, last_timestamp_ms, output):
    """
    Decodes btsnooz v2 files into a btsnoop file.
    """
    # An unfortunate consequence of the file format design: we have to do a
    # pass of the entire file to determine the timestamp of the first packet.
    first_timestamp_ms = last_timestamp_ms + 0x00dcddb30f2f8000
    offset = 0
    while offset < len(decompressed):
      length, packet_length, delta_time_ms, snooz_type = struct.unpack_from('=HHIb', decompressed, offset)
      offset += 9 + length - 1
      first_timestamp_ms -= delta_time_ms

    # Second pass does the actual writing out to stdout.
    offset = 0

    while offset < len(decompressed):
      length, packet_length, delta_time_ms, snooz_type = struct.unpack_from('=HHIb', decompressed, offset)
      first_timestamp_ms += delta_time_ms
      offset += 9

      output.write(struct.pack('>II', packet_length, length))
      output.write(struct.pack('>II', self.type_to_direction(snooz_type), 0))
      output.write(struct.pack('>II', (first_timestamp_ms >> 32), (first_timestamp_ms & 0xFFFFFFFF)))
      output.write(self.type_to_hci(snooz_type))
      output.write(decompressed[offset : offset + length - 1])
      offset += length - 1

  def Convert(self, dump_path, type):

    print("btsnooz.py : Convert :", type)
    outputFile = os.path.join(dump_path, SNOOZ_FILE)

    begin_token = '--- BEGIN:BTSNOOP_LOG_SUMMARY'
    end_token = '--- END:BTSNOOP_LOG_SUMMARY'
    target = 'btsnooz'

    #if (type == BtUtils.TYPE_QC_DBG):
    #    outputFile = os.path.join(dump_path, QC_ENH_SNOOZ_FILE)
    #    begin_token = '--- BEGIN:QCENH_LOG_SUMMARY'
    #    end_token = '--- END:QCENH_LOG_SUMMARY'
    #    target = 'qcom enh'
    #elif (type == BtUtils.TYPE_LSI_DBG):
    #    outputFile = os.path.join(dump_path, LSI_FW_SNOOZ_FILE)
    #    begin_token = '--- BEGIN:SLSI_FW_LOG_SUMMARY'
    #    end_token = '--- END:SLSI_FW_LOG_SUMMARY'
    #    target = 'lsi enh'

    found = False
    base64_string = ""
    with open(os.path.join(dump_path, BT_PERMANENT_LOG_FILE), 'r', errors='replace', encoding='utf-8') as log:
      while True:
        line = log.readline()
        if not line: break
        if(found):
          if(line.find(end_token) != -1):
            snooz = open(outputFile, 'wb')
            self.decode_snooz(base64.standard_b64decode(base64_string), snooz)
            snooz.close()
            break
          elif(line.find('---------') != -1):
            print('No ' + target + ' section is broken.\n')
            break

          base64_string += line.strip()

        if(line.find(begin_token) != -1):
          found = True

      if(found != True):
        print('No ' + target + ' section found in bugreport!')
