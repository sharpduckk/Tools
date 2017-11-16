#-*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:        patchcode.py
# Purpose:
#
# Author:      LDK
#
# Created:     00-00-2017
# Copyright:   (c) ETHAN 2017
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import os, sys
import pefile
import mmap
import re
import struct
import binascii
import ConfigParser


# Set default path (for fail to get "*.ini" config file)
dic_default_env = dict(hexSkipType1_raw="5060E8EDFFFFFFC20400",
                       hexSkipType2_raw="508B44240483C004508B442404C20800",
                       hexSkipType1_PatchLen=2,
                       hexSkipType2_PatchLen=4)
strIni = 'patchcode.ini'
cls_basicInfo_env = ConfigParser.ConfigParser(defaults=dic_default_env)
cls_basicInfo_env.read(filenames=strIni)

# ini [Code]
hexSkipType1_raw = cls_basicInfo_env.get('Code', 'hexSkipType1_raw')
hexSkipType2_raw = cls_basicInfo_env.get('Code', 'hexSkipType2_raw')
hexSkipType1_PatchLen = cls_basicInfo_env.get('Code', 'hexSkipType1_PatchLen')
hexSkipType2_PatchLen = cls_basicInfo_env.get('Code', 'hexSkipType2_PatchLen')


# Function: "functionHexCmp()"
# Arg1 "textVcodeBody" -> Search Target
# Argf2 "suspAntiFuncAddr"-> found Call offset (basement: textVcodeStart)
# return: Anti Skip length if null, nothing
def functionHexCmp(textVcodeBody, suspAntiFuncAddr):
    foundBin = textVcodeBody[suspAntiFuncAddr:suspAntiFuncAddr+0x10]
    hexFoundBin= binascii.b2a_hex(foundBin)
    if ( hexFoundBin.find(hexSkipType1_raw.lower()) != -1):
        print hexFoundBin
        return int(hexSkipType1_PatchLen)
    elif ( hexFoundBin.find(hexSkipType2_raw.lower()) != -1):
        print hexFoundBin
        return int(hexSkipType2_PatchLen)
    else:
        return None


def patcFuncMain(inputPath):
    with open(inputPath, "r+b") as f:
        # memory-map the file, size 0 means whole file
        mm = mmap.mmap(f.fileno(), 0)

        # PointToRawData
        flagFileCodeBase = 0
        hPE = pefile.PE(inputPath)
        EP = hPE.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in hPE.sections:
            if (section.VirtualAddress <= EP and section.VirtualAddress + section.Misc_VirtualSize > EP):
                PointToRawData = section.PointerToRawData
                textVcodeStart = PointToRawData
                textVcodeEnd = PointToRawData + section.SizeOfRawData
                flagFileCodeBase = 1
        if flagFileCodeBase == 0:
            print "PointToRawData not found in file"
            return False
        else:
            print "PointToRawData: ", PointToRawData


        textVcodeBody = mm[textVcodeStart:textVcodeEnd]
        patchCount = 0

        # regular ex
        pattern = "\xE8(..)\xFF\xFF"
        # pattern = "\x55\x8b"
        regex = re.compile(pattern)
        for match_obj in regex.finditer(textVcodeBody):
            offset = match_obj.start()
            print "decimal: {}".format(offset)
            print "hex(): " + hex(offset)
            E8_operand_raw = textVcodeBody[offset+1:offset+5]
            E8_operand = struct.unpack('<I', E8_operand_raw)[0]

            # from VcodeStart to relative address, and remove overflow
            print hex(offset+E8_operand-0x100000000)
            suspCallAddr = (offset+E8_operand-0x100000000+5)
            retSkip = functionHexCmp(textVcodeBody, suspCallAddr)

            # Nop Patch(0x90)
            if retSkip != None:
                print "taken skip function"
                for i in range(0, retSkip):
                    print i
                    editVar = binascii.unhexlify("90")
                    mm[PointToRawData + offset + 5 + i] = editVar  # 0x90
                    patchCount += 1
            print "patchCount", patchCount

    mm.seek(0)

    # close the map
    mm.close()
    pass

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error Message : Invalid Parameter")
        print("Usage: python [Target Folder]")
        sys.exit(-1)

    # Get Parameter Argument
    print "argument: ", sys.argv[1]
    inputPath = sys.argv[1]

    for filename in os.listdir(inputPath):
        print inputPath+filename
        # check is directory
        if os.path.isdir(inputPath+filename):
            print inputPath+filename+"dir"
            continue
        else:
            filePath = inputPath+filename
            patcFuncMain(filePath)

    sys.exit(1)




