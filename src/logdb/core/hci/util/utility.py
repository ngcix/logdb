import sys
import os
class BtUtil:
    @staticmethod
    def getFileName(path):
        onlyFileName = path.rsplit('/', 1)
        if(len(onlyFileName) == 2):
            return onlyFileName[1]

        print("BtUtil.getFileName() path has no \'/\' char")
        return ""

    basePath = ""

    BTSNOOP_HEADER = [98, 116, 115, 110, 111, 111, 112, 0, 0, 0, 0, 1, 0, 0, 3, 234]
    CFA_HEADER = [0x04, 0xf9, 0x10, 0x33, 0xb1, 0x4c, 0x00, 0x00, 0xc0, 0x01, 0x17, 0x20, 0x01, 0x93, 0xda, 0x4d, 0x20, 0x1f, 0x00, 0xee, 0x90, 0xb1, 0x52, 0xb8, 0xca, 0x08, 0x76, 0xf7, 0xff, 0x48, 0x1e, 0xd6, 0xce, 0xe6, 0x04, 0x44, 0x4c, 0x00, 0x00, 0xc0, 0x01, 0x17, 0x00, 0x01, 0x37, 0xd3, 0x1c, 0xce, 0x7b, 0x64, 0xee, 0x90, 0xb1, 0x52, 0xb8, 0xca, 0x08, 0x76, 0xf7, 0xff, 0x48, 0x1e, 0xd6, 0xce, 0xe6, 0x04]
    CFA_PREFIX = [0x44, 0x04, 0x07, 0x0b, 0x25, 0x33, 0xb1, 0x04, 0xd, 0x20, 0x40, 0x31, 0x01]

    def toTime(time):
        time = time - 62168256000000000
        time /= 1000000
        return time

    @staticmethod
    def charToInt(c):
        if(c=='0'):
            return 0
        elif(c=='1'):
            return 1
        elif (c == '2'):
            return 2
        elif (c == '3'):
            return 3
        elif (c == '4'):
            return 4
        elif (c == '5'):
            return 5
        elif (c == '6'):
            return 6
        elif (c == '7'):
            return 7
        elif (c == '8'):
            return 8
        elif (c == '9'):
            return 9
        elif (c == 'a') or (c == 'A'):
            return 10
        elif (c == 'b') or (c == 'B'):
            return 11
        elif (c == 'c') or (c == 'C'):
            return 12
        elif (c == 'd') or (c == 'D'):
            return 13
        elif (c == 'e') or (c == 'E'):
            return 14
        elif (c == 'f') or (c == 'F'):
            return 15
        else:
            return -1

    @staticmethod
    def intToHex(i):
        if (i == 0) :
            return '0'
        elif (i == 1):
            return '1'
        elif (i == 2):
            return '2'
        elif (i == 3):
            return '3'
        elif (i == 4):
            return '4'
        elif (i == 5):
            return '5'
        elif (i == 6):
            return '6'
        elif (i == 7):
            return '7'
        elif (i == 8):
            return '8'
        elif (i == 9):
            return '9'
        elif (i == 10):
            return 'A'
        elif (i == 11):
            return 'B'
        elif (i == 12):
            return 'C'
        elif (i == 13):
            return 'D'
        elif (i == 14):
            return 'E'
        elif (i == 15):
            return 'F'
        return 'X'

    @staticmethod
    def stringToByte(s):
        b = ((BtUtil.charToInt(s[0])) << 4)
        b += BtUtil.charToInt(s[1])
        return b

    @staticmethod
    def charIsdigit(c):
        if(c == '1' or c == '2' or c == '3' or c == '4' or c == '5' or c == '6' or c == '7' or c == '8' or c == '9' or c == '0'):
            return True
        return False

 

    @staticmethod
    def byteToHexString(b):
        ret = ""
        tmp = (b & 0xf0) >> 4
        ret += (BtUtil.intToHex(tmp))
        tmp = b & 0x0f
        ret += (BtUtil.intToHex(tmp))
        return ret
    
    def statusCodeToString(statusCode):
        if (statusCode == 0x00):
            return "Success"
        elif (statusCode == 0x04):
            return "Page Timeout"
        elif (statusCode == 0x05):
            return "Authentication Failure"
        elif (statusCode == 0x06):
            return "PIN or Key Missing"
        elif (statusCode == 0x08):
            return "Connection Timeout"
        elif (statusCode == 0x13):
            return "Remote User Terminated Connection"
        elif (statusCode == 0x16):
            return "Connection Terminated by Local Host"
        elif (statusCode == 0x18):
            return "Pairing not Allowed"
        elif (statusCode == 0x22):
            return "LMP Response Timeout"
        else:
            return "Invalid"

class ALog():
    @staticmethod
    def e(str):
        print(str)

    @staticmethod
    def d(str):
        print(str)

    @staticmethod
    def w(str):
        print(str)

    @staticmethod
    def exception(str):
        print(str)
