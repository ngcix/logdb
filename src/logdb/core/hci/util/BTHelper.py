import os
from common.btsnooz import BtSnooz
from datetime import datetime, timedelta
from common.utility import BtUtil
import time
import re
from collections import deque



BT_SNOOZ_LOG_VOC = "snooz_VOC.cfa"


class BTHelper:

    log_time = 0
    from_time = 0
    year_log = 0
    
    def get_BT_PERMANENT_LOG_FILE(self, dump_path):
        print("BT Helper ---- get_BT_PERMANENT_LOG_FILE")

        global log_time
        global from_time
        global year_log

        outputResult = ""
        isFound = False
        start_line = "DUMP OF SERVICE bluetooth_manager:"
        end_line = "was the duration of dumpsys bluetooth_manager"

        try:
            with open(os.path.join(dump_path, "latest_dumpstate.log"), encoding="utf8", errors='ignore') as dumpstatelog:
                while True:
                    line = dumpstatelog.readline()
                    if line.startswith("== dumpstate: 2"):
                        year_log = int(line[14:18])
                        temp_time = str(line[14:len(line)-1]).strip()
                        log_time = int(datetime.strptime(temp_time, "%Y-%m-%d %H:%M:%S").timestamp())
                        from_time = int((datetime.strptime(temp_time, "%Y-%m-%d %H:%M:%S")-timedelta(days=1)).timestamp())
                    if line.startswith(start_line):
                        isFound = True
                    if isFound:
                        outputResult += line
                    if end_line in line:
                        break
                dumpstatelog.close()

            with open(os.path.join(dump_path, 'BT_PERMANENT_LOG.log'), 'w', encoding="utf8", errors='ignore') as outputfile:
                outputfile.write(outputResult)
                outputfile.close()

        except Exception as e:
            print(e)



    def get_BT_SNOOZ_LOG_VOC(self, dump_path):
        snooz = BtSnooz()
        snooz.Convert(dump_path,1) #BtUtils.TYPE_SNOOZ

    

    def get_HCI_VOC_log(self, dump_path):
        BtSnoopHeaderLen = 15
        TimeStampLen = 8
        PacketTypeLen = 1

        HCI_Command_Packet = 1
        HCI_ACL_Data_Packet = 2
        HCI_Event_Packet = 4
    
        #Advertisement Packet Content Filter
        APCF_Enable = 0x00
        APCF_Set_Filtering_Param = 0x01
        APCF_Service_UUID = 0x03
        APCF_Manufacturer_Data = 0x06
        APCF_Service_Data = 0x07

        result = ''
        frame = 0
        scanBR_log = ""
        HCI_log = ""
        hci_uart = ""

        # Calculate logging time

        with open(os.path.join(dump_path, BT_SNOOZ_LOG_VOC), "rb") as snoop_file:
            bytes = snoop_file.read(BtSnoopHeaderLen)
            
            if not bytes:
                print("not byte")
            for i in range(0,BtSnoopHeaderLen):
                if(bytes[i] != BtUtil.BTSNOOP_HEADER[i]):
                    print("Not completed snoop")

            snoop_file.seek(1, 1)

            LE_Extended_Advertising_Report_count = 0
            Core_Dump_Frame_count = 0
            QC_Core_Dump_Frame_count = 0
            LE_Batch_Scan_Command_count = 0
            LE_APCF_Command = 0
            mAPCF_Enable = 0
            mAPCF_Set_Filtering_Param = 0
            mAPCF_Service_UUID = 0
            mAPCF_Manufacturer_Data = 0
            mAPCF_Service_Data = 0
            Enhanced_DBFW_Event_count = 0

            numFound = 0
            isBRScanning = False

            while True:
                hci_uart = ""
                snoop_file.seek(16, 1)
                timeBuffer = snoop_file.read(TimeStampLen)
                HCI_Packet_type = snoop_file.read(PacketTypeLen)

                Packet_logging_time = BtUtil.toTime(int.from_bytes(timeBuffer, byteorder='big'))
                if Packet_logging_time > 0:
                    timeline = datetime.utcfromtimestamp(Packet_logging_time)
                else:
                    timeline = 0

                frame+=1

# parsing HCI_Command_Packet
                if not HCI_Packet_type:
                    break
                elif(HCI_Packet_type[0] == HCI_Command_Packet):
                    packet = snoop_file.read(2)
                    length = snoop_file.read(1)[0] & 0x00FF

            		#Command: HCI_Create_Connection
                    if ((packet[0] & 0x00FF) == 0x05) and ((packet[1] & 0x00FF) == 0x04):
                        bd_addr = snoop_file.read(6)
                        bd_addr = "-".join(f'{byte:02x}' for byte in reversed(bd_addr))
                        hci_uart += str(timeline) + "     C     HCI_Create_Connection     BD_ADDR: " + bd_addr
                        HCI_log += hci_uart + "\n"
                        length -= 6

                    #Command: HCI_Authentication_Requested
                    elif ((packet[0] & 0x00FF) == 0x11) and ((packet[1] & 0x00FF) == 0x04):
                        temp = snoop_file.read(2)
                        temp = temp[0] | temp[1] << 8
                        connection_handle = f'0x{temp:04x}'
                        hci_uart += str(timeline) + "     C     HCI_Authentication_Requested     Handle: " + connection_handle
                        HCI_log += hci_uart + "\n"
                        length = 0

                    #Command: HCI_Accept_Connection_Request
                    elif ((packet[0] & 0x00FF) == 0x09) and ((packet[1] & 0x00FF) == 0x04):
                        bd_addr = snoop_file.read(6)
                        bd_addr = "-".join(f'{byte:02x}' for byte in reversed(bd_addr))
                        hci_uart += str(timeline) + "     C     HCI_Accept_Connection_Request     BD_ADDR: " + bd_addr
                        HCI_log += hci_uart + "\n"
                        length -= 6

                    #Command: HCI_Inquiry
                    elif ((packet[0] & 0x00FF) == 0x01) and ((packet[1] & 0x00FF) == 0x04):
                        isBRScanning = True
                        numFound = 0
                        hci_uart += str(timeline) + "     C     HCI_Inquiry"
                        scanBR_log += hci_uart + "\n"

                    #Command: HCI_Inquiry_Cancel
                    elif ((packet[0] & 0x00FF) == 0x02) and ((packet[1] & 0x00FF) == 0x04):
                        scanBR_log += "Num of founded BR/EDR device : " + str(numFound) + "\n"
                        hci_uart += str(timeline) + "     C     HCI_Inquiry_Cancel"
                        scanBR_log += hci_uart + "\n\n"
                        isBRScanning = False



                    elif ((packet[1] & 0x00FF) == 0xFD) and ((packet[0] & 0x00FF) == 0x56):
                        LE_Batch_Scan_Command_count +=1
                    elif ((packet[1] & 0x00FF) == 0xFD) and ((packet[0] & 0x00FF) == 0x57):
                        LE_APCF_Command += 1
                        opcode = snoop_file.read(1)[0] & 0x00FF
                        length = length - 1
                        if (opcode == APCF_Enable):
                            mAPCF_Enable += 1
                        elif (opcode == APCF_Set_Filtering_Param):
                            mAPCF_Set_Filtering_Param += 1
                        elif (opcode == APCF_Service_UUID):
                            mAPCF_Service_UUID += 1
                        elif (opcode == APCF_Manufacturer_Data):
                            mAPCF_Manufacturer_Data += 1
                        elif (opcode == APCF_Service_Data):
                            mAPCF_Service_Data += 1

                    snoop_file.seek(length, 1)
                elif(HCI_Packet_type[0] == HCI_ACL_Data_Packet):
                    ACL_handle = snoop_file.read(2)
                    if ((ACL_handle[1] & 0x00FF) == 0x2F) and ((ACL_handle[0] & 0x00FF) == 0xF1):
                        Core_Dump_Frame_count += 1
                    if ((ACL_handle[1] & 0x00FF) == 0x2E) and ((ACL_handle[0] & 0x00FF) == 0xDC):
                        QC_Core_Dump_Frame_count +=1
                    temp = snoop_file.read(2)
                    length_2byte = ((temp[1] & 0x00FF) << 8) + (temp[0] & 0x00FF)
                    snoop_file.seek(length_2byte, 1)
                elif(HCI_Packet_type[0] == 3):
                    continue
                    #print(" SCO data")
                elif(HCI_Packet_type[0] == HCI_Event_Packet):
                    hci_uart = ""
                    event_code = snoop_file.read(1)[0] & 0x00FF
                    length = snoop_file.read(1)[0] & 0x00FF
                    if (event_code == 0x3E):
                        LE_Extended_Advertising_Report_count += 1
                    elif (event_code == 0xFF):
                        vendor_event_type = snoop_file.read(1)[0] & 0x00FF
                        if (event_code == 0xFF) and (vendor_event_type == 0x90):
                            Enhanced_DBFW_Event_count += 1
                        length = length-1

                    
                    #Event: HCI_Command_Status
                    elif (event_code == 0x0F):
                        more_data = snoop_file.read(length)
                        #if (more_data[2] == 0x05) and (more_data[3] == 0x04) and ((Packet_logging_time > PowerConsumtion_start_time) and (Packet_logging_time < PowerConsumtion_end_time)):
                        #    status = more_data[0] & 0x00FF
                        #    status = BtUtil.statusCodeToString(status)
                        #    hci_uart += str(Packet_logging_time) + "   E   HCI_Create_Connection   HCI_Command_Status    Status: " + status
                        #    HCI_log += hci_uart + "\n"
                        length = 0

                    #Event: HCI_Connection_Complete
                    elif (event_code == 0x03): 
                        status = snoop_file.read(1)[0] & 0x00FF
                        status = BtUtil.statusCodeToString(status)
                        temp = snoop_file.read(2)
                        temp = temp[0] | temp[1] << 8
                        connection_handle = f'0x{temp:04x}'
                        bd_addr = snoop_file.read(6)
                        bd_addr = "-".join(f'{byte:02x}' for byte in reversed(bd_addr))
                        hci_uart += str(timeline) + "     E     HCI_Connection_Complete     BD_ADDR: " + bd_addr + "     Status: " + status + "     Handle: " + connection_handle
                        HCI_log += hci_uart + "\n"
                        length -=9

                    elif (event_code == 0x04): #Event: HCI_Connection_Request
                        bd_addr = snoop_file.read(6)
                        bd_addr = "-".join(f'{byte:02x}' for byte in reversed(bd_addr))
                        hci_uart += str(timeline) + "     E     HCI_Connection_Request   BD_ADDR: " + bd_addr
                        HCI_log += hci_uart + "\n"      
                        length -=6           

		            #Event: HCI_Disconnection_Complete
                    elif (event_code == 0x05):
                        status = snoop_file.read(1)
                        temp = snoop_file.read(2)
                        temp = temp[0] | temp[1] << 8
                        connection_handle = f'0x{temp:04x}'
                        reason = snoop_file.read(1)[0] & 0x00FF
                        reason = BtUtil.statusCodeToString(reason)
                        hci_uart += str(timeline) + "     E     HCI_Disconnection_Complete     Handle: " + connection_handle + "     Reason: " + reason
                        HCI_log += hci_uart + "\n"   
                        length = 0

                    #Event: HCI_Authentication_Complete
                    elif (event_code == 0x06):
                        status = snoop_file.read(1)[0] & 0x00FF
                        temp = snoop_file.read(2)
                        temp = temp[0] | temp[1] << 8
                        connection_handle = f'0x{temp:04x}'
                        hci_uart += str(timeline) + "     E     HCI_Authentication_Complete     Status: " + BtUtil.statusCodeToString(status) + "     Handle: " + connection_handle
                        HCI_log += hci_uart + "\n"  
                        length = 0

                    #Event: HCI_Extended_Inquiry_Result
                    elif (event_code == 0x2F):
                        numFound +=1 

                    #Event: HCI_Inquiry_Complete
                    elif (event_code == 0x01):
                        scanBR_log += "Num of founded device : " + str(numFound) + "\n"
                        hci_uart += str(timeline) + "     E     HCI_Inquiry_Complete"
                        scanBR_log += hci_uart + "\n\n"
                        isBRScanning = False



                    snoop_file.seek(length, 1)
                    continue



        resultStr = "***** HCI Log VOC *****\n"
        resultStr += "1. BR/EDR Scan Log\n"
        resultStr += scanBR_log + "\n\n\n"

        resultStr += "2. Connect Log\n"
        resultStr += HCI_log + "\n"

        with open(os.path.join(dump_path, 'decoded_hci_VOC.log'), 'w', encoding="utf8", errors='ignore') as outputFile:
            outputFile.write(resultStr)
            outputFile.close()



    def get_BT_Connection_log(self, dump_path):
        print("BT Helper ---- get_BT_Connection_log")
        connection_log = "1. DUMP log" + "\n"
        CON_PERM_log = deque(maxlen=30)
        try:
            with open(os.path.join(dump_path, "BT_PERMANENT_LOG.log"), encoding="utf8", errors='ignore') as PERMlog:
                lines = PERMlog.readlines()
                for i in range(len(lines)):
                    if "ACTION_ACL_" in lines[i]:
                        temp_time = str(year_log) + "-"
                        temp_time += str(lines[i][:14]).strip()
                        time_stamp = int(datetime.strptime(temp_time, "%Y-%m-%d %H:%M:%S").timestamp())
                        if time_stamp <= log_time and time_stamp >= from_time:
                            detail = lines[i][46:].strip()
                            resStr = temp_time + " " + detail + "\n"
                            CON_PERM_log.append(resStr)
                    if "BluetoothDataManager -- CONNECTION INFO" in lines[i]:
                        match = re.search(r'"RE_NAM"\s*:\s*"([^"]+)"', lines[i])
                        if match:
                            dev_name = match.group(1)
                            temp_time = str(year_log) + "-"
                            temp_time += str(lines[i][:14]).strip()
                            resStr = temp_time + " CONNECTION INFO   Device name: " + dev_name + "\n"
                            CON_PERM_log.append(resStr)

                connection_log += "".join(CON_PERM_log) + "\n"
                PERMlog.close()


            connection_log += "\n\n2. HCI log" + "\n"
            CON_HCI_LOG = deque(maxlen=30)
            with open(os.path.join(dump_path, "decoded_hci_VOC.log"), encoding="utf8", errors='ignore') as HCIlog:
                lines = HCIlog.readlines()
                for i in range(len(lines)):
                    if "2. Connect Log" in lines[i]:
                        for j in range(i+1, len(lines)):
                            resStr = lines[j]
                            CON_HCI_LOG.append(resStr)

                connection_log += "".join(CON_HCI_LOG)
                HCIlog.close()

            with open(os.path.join(dump_path, 'VOC_CONNECTION_LOG.log'), 'w', encoding="utf8", errors='ignore') as outputLog:
                outputLog.write(connection_log)
                outputLog.close()

        except Exception as e:
            print(e)



    def get_BT_scan_log(self, dump_path):
        print("BT Helper ---- get_BT_scan_log")
        scan_log = "1. HCI log"
        try:
            with open(os.path.join(dump_path, "decoded_hci_VOC.log"), encoding="utf8", errors='ignore') as HCIlog:
                lines = HCIlog.readlines()
                for i in range(len(lines)):
                    if "1. BR/EDR Scan Log" in lines[i]:
                        for j in range(i+1, len(lines)):
                            if lines[j].startswith("\n") and lines[j+1].startswith("\n"):
                                break
                            scan_log += lines[j]
                HCIlog.close()

            with open(os.path.join(dump_path, 'VOC_SCAN_LOG.log'), 'w', encoding="utf8", errors='ignore') as outputLog:
                outputLog.write(scan_log)
                outputLog.close()

        except Exception as e:
            print(e)
