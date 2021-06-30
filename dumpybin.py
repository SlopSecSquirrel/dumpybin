#!/usr/bin/python3
import argparse
import struct
import sys
from os import path

parser = argparse.ArgumentParser(description='Processes a DLL file and outputs the exported functions and function ordinals, just like the Big Boy Dumpbin does.')
parser.add_argument('DLL', metavar='DLL', type=str, help='The path to the DLL which should be processed by dumpybin.')
parser.add_argument('--debug', default="--no-debug", dest='debugMode',action=argparse.BooleanOptionalAction, help='supply this option to output a bunch of debugging data for nerds.')


args = parser.parse_args()
DLL = args.DLL
debugMode = args.debugMode

# Check if the file even exists
if not path.exists(DLL):
    print("[-] The supplied DLL path doesn't seem to exist.")
    sys.exit()

print("[+] DLL exists, about to read it.")

# Get the file bytes, and error out if the file's not readable
fileBytes = b""
try:
    with open(DLL, "rb") as fileObj:
        fileBytes = fileObj.read()
except IOError as x:
    print(f"[-] Failed to read the DLL file, make it readable with chmod +r {DLL} (or the Windows equivalent command).")
    sys.exit()

print(f"[+] Successfully read all {len(fileBytes)} bytes from the DLL, about to check that the file is a valid PE file.")

# Parse the magic number and make sure that it's a valid Windows PE
if(struct.unpack(">i", fileBytes[0:4])[0] != 0x4d5a9000):
    print("[-] The magic bytes don't match a valid PE file, quitting.")
    sys.exit()

print("[+] File is a valid PE file, proceeding to dump it.")

# Attempt to skip over the DOS header and DOS stubs
PE_FILE_START_OFFSET = fileBytes.find(struct.pack(">i",0x50450000))

if(PE_FILE_START_OFFSET < 0):
    print("[-] The supplied PE file is corrupted, it has no signature bytes.")
    sys.exit()

# Rebase the file bytes to skip over the DOS header, DOS stub and signature bytes
fileBytes = fileBytes[PE_FILE_START_OFFSET+4:]

# Process the COFF header
COFF_HEADER_LENGTH = 20
COFF_HEADER_MACHINE = struct.unpack(">H",fileBytes[0:2])[0]
COFF_HEADER_NUMBER_SECTIONS = struct.unpack(">H",fileBytes[2:4])[0]
COFF_HEADER_TIME_DATE_STAMP = struct.unpack(">i",fileBytes[4:8])[0]
COFF_HEADER_POINTER_TO_SYM_TABLE = struct.unpack(">i",fileBytes[8:12])[0] # Deprecated
COFF_HEADER_NUMBER_OF_SYMBOL_TABLE = struct.unpack(">i",fileBytes[12:16])[0] # Deprecated
COFF_HEADER_SIZE_OF_OPTIONAL_HEADER = struct.unpack(">H",fileBytes[16:18])[0]
COFF_HEADER_CHARACTERISTICS = struct.unpack(">H",fileBytes[18:20])[0]

if debugMode:
    print("COFF HEADER FIELDS = \n===========================")
    print("COFF_HEADER_LENGTH = " + hex(COFF_HEADER_LENGTH))
    print("COFF_HEADER_MACHINE = " + hex(COFF_HEADER_MACHINE))
    print("COFF_HEADER_NUMBER_SECTIONS = " + hex(COFF_HEADER_NUMBER_SECTIONS))
    print("COFF_HEADER_TIME_DATE_STAMP = " + hex(COFF_HEADER_TIME_DATE_STAMP))
    print("COFF_HEADER_POINTER_TO_SYM_TABLE = " + hex(COFF_HEADER_POINTER_TO_SYM_TABLE))
    print("COFF_HEADER_NUMBER_OF_SYMBOL_TABLE = " + hex(COFF_HEADER_NUMBER_OF_SYMBOL_TABLE))
    print("COFF_HEADER_SIZE_OF_OPTIONAL_HEADER = " + hex(COFF_HEADER_SIZE_OF_OPTIONAL_HEADER))
    print("COFF_HEADER_CHARACTERISTICS = " + hex(COFF_HEADER_CHARACTERISTICS))

# Rebase the file bytes to skip over the COFF header
fileBytes = fileBytes[COFF_HEADER_LENGTH:]

COFF_FIELD_LENGTH = 28
COFF_FIELD_MAGIC = struct.unpack(">H",fileBytes[0:2])[0]
COFF_FIELD_MAJOR_LINKER_VERSION = struct.unpack("B",fileBytes[2:3])[0]
COFF_FIELD_MINOR_LINKER_VERSION = struct.unpack("B",fileBytes[3:4])[0]
COFF_FIELD_SIZE_OF_CODE = struct.unpack(">i",fileBytes[4:8])[0]
COFF_FIELD_SIZE_OF_INITIALIZED_DATA = struct.unpack(">i",fileBytes[8:12])[0]
COFF_FIELD_SIZE_OF_UNINITIALIZED_DATA = struct.unpack(">i",fileBytes[12:16])[0]
COFF_FIELD_ADDRESS_OF_ENTRY_POINT_RVA = struct.unpack(">L",fileBytes[16:20])[0]
COFF_FIELD_BASE_OF_CODE_RVA = struct.unpack(">i",fileBytes[20:24])[0]
COFF_FIELD_BASE_OF_DATA_RVA = struct.unpack(">i",fileBytes[24:28])[0]

if debugMode:
    print()
    print("COFF BODY FIELDS = \n===========================")
    print("COFF_FIELD_LENGTH = " + hex(COFF_FIELD_LENGTH))
    print("COFF_FIELD_MAGIC = " + hex(COFF_FIELD_MAGIC))
    print("COFF_FIELD_MAJOR_LINKER_VERSION = " + hex(COFF_FIELD_MAJOR_LINKER_VERSION))
    print("COFF_FIELD_MINOR_LINKER_VERSION = " + hex(COFF_FIELD_MINOR_LINKER_VERSION))
    print("COFF_FIELD_SIZE_OF_CODE = " + hex(COFF_FIELD_SIZE_OF_CODE))
    print("COFF_FIELD_SIZE_OF_INITIALIZED_DATA = " + hex(COFF_FIELD_SIZE_OF_INITIALIZED_DATA))
    print("COFF_FIELD_SIZE_OF_UNINITIALIZED_DATA = " + hex(COFF_FIELD_SIZE_OF_UNINITIALIZED_DATA))
    print("COFF_FIELD_ADDRESS_OF_ENTRY_POINT_RVA = " + hex(COFF_FIELD_ADDRESS_OF_ENTRY_POINT_RVA))
    print("COFF_FIELD_BASE_OF_CODE_RVA = " + hex(COFF_FIELD_BASE_OF_CODE_RVA))
    print("COFF_FIELD_BASE_OF_DATA_RVA = " + hex(COFF_FIELD_BASE_OF_DATA_RVA))


# Rebase the file bytes to skip over the COFF fields
fileBytes = fileBytes[COFF_FIELD_LENGTH:]

WINDOWS_FIELDS_FIELD_LENGTH = 68
WINDOWS_FIELDS_IMAGE_BASE  = struct.unpack(">i", fileBytes[0:4])[0]
WINDOWS_FIELDS_SECTION_ALIGNMENT = struct.unpack(">i", fileBytes[4:8])[0]
WINDOWS_FIELDS_FILE_ALIGNMENT = struct.unpack(">i", fileBytes[8:12])[0]
WINDOWS_FIELDS_MAJOR_OPERATING_SYSTEM_VERSION = struct.unpack(">H", fileBytes[12:14])[0]
WINDOWS_FIELDS_MINOR_OPERATING_SYSTEM_VERSION = struct.unpack(">H", fileBytes[14:16])[0]
WINDOWS_FIELDS_MAJOR_IMAGE_VERSION = struct.unpack(">H", fileBytes[16:18])[0]
WINDOWS_FIELDS_MINOR_IMAGE_VERSION = struct.unpack(">H", fileBytes[18:20])[0]
WINDOWS_FIELDS_MAJOR_SUBSYSTEM_VERSION = struct.unpack(">H", fileBytes[20:22])[0]
WINDOWS_FIELDS_MINOR_SUBSYSTEM_VERSION = struct.unpack(">H", fileBytes[22:24])[0]
WINDOWS_FIELDS_WIN32_VERSION_VALUE = struct.unpack(">i", fileBytes[24:28])[0]
WINDOWS_FIELDS_SIZE_OF_IMAGE = struct.unpack(">i", fileBytes[28:32])[0]
WINDOWS_FIELDS_SIZE_OF_HEADERS = struct.unpack(">i", fileBytes[32:36])[0]
WINDOWS_FIELDS_CHECKSUM = struct.unpack(">i", fileBytes[36:40])[0]
WINDOWS_FIELDS_SUBSYSTEM = struct.unpack(">H", fileBytes[40:42])[0]
WINDOWS_FIELDS_DLL_CHARACTERISTICS = struct.unpack(">H", fileBytes[42:44])[0]
WINDOWS_FIELDS_SIZE_OF_STACK_RESERVE = struct.unpack(">i", fileBytes[44:48])[0]
WINDOWS_FIELDS_SIZE_OF_STACK_COMMIT = struct.unpack(">i", fileBytes[48:52])[0]
WINDOWS_FIELDS_SIZE_OF_HEAP_RESERVE = struct.unpack(">i", fileBytes[52:56])[0]
WINDOWS_FIELDS_SIZE_OF_HEAP_COMMIT = struct.unpack(">i", fileBytes[56:60])[0]
WINDOWS_FIELDS_LOADER_FLAGS = struct.unpack(">i", fileBytes[60:64])[0]
WINDOWS_FIELDS_NUMBER_OF_RVA_AND_SIZES = struct.unpack(">i", fileBytes[64:68])[0]

if debugMode:
    print()
    print("WINDOWS SPECIFIC FIELDS = \n===========================")
    print("WINDOWS_FIELDS_FIELD_LENGTH = " + hex(WINDOWS_FIELDS_FIELD_LENGTH))
    print("WINDOWS_FIELDS_IMAGE_BASE = " + hex(WINDOWS_FIELDS_IMAGE_BASE))
    print("WINDOWS_FIELDS_SECTION_ALIGNMENT = " + hex(WINDOWS_FIELDS_SECTION_ALIGNMENT))
    print("WINDOWS_FIELDS_FILE_ALIGNMENT = " + hex(WINDOWS_FIELDS_FILE_ALIGNMENT))
    print("WINDOWS_FIELDS_MAJOR_OPERATING_SYSTEM_VERSION = " + hex(WINDOWS_FIELDS_MAJOR_OPERATING_SYSTEM_VERSION))
    print("WINDOWS_FIELDS_MINOR_OPERATING_SYSTEM_VERSION = " + hex(WINDOWS_FIELDS_MINOR_OPERATING_SYSTEM_VERSION))
    print("WINDOWS_FIELDS_MAJOR_IMAGE_VERSION = " + hex(WINDOWS_FIELDS_MAJOR_IMAGE_VERSION))
    print("WINDOWS_FIELDS_MINOR_IMAGE_VERSION = " + hex(WINDOWS_FIELDS_MINOR_IMAGE_VERSION))
    print("WINDOWS_FIELDS_MAJOR_SUBSYSTEM_VERSION = " + hex(WINDOWS_FIELDS_MAJOR_SUBSYSTEM_VERSION))
    print("WINDOWS_FIELDS_MINOR_SUBSYSTEM_VERSION = " + hex(WINDOWS_FIELDS_MINOR_SUBSYSTEM_VERSION))
    print("WINDOWS_FIELDS_WIN32_VERSION_VALUE = " + hex(WINDOWS_FIELDS_WIN32_VERSION_VALUE))
    print("WINDOWS_FIELDS_SIZE_OF_IMAGE = " + hex(WINDOWS_FIELDS_SIZE_OF_IMAGE))
    print("WINDOWS_FIELDS_SIZE_OF_HEADERS = " + hex(WINDOWS_FIELDS_SIZE_OF_HEADERS))
    print("WINDOWS_FIELDS_CHECKSUM = " + hex(WINDOWS_FIELDS_CHECKSUM))
    print("WINDOWS_FIELDS_SUBSYSTEM = " + hex(WINDOWS_FIELDS_SUBSYSTEM))
    print("WINDOWS_FIELDS_DLL_CHARACTERISTICS = " + hex(WINDOWS_FIELDS_DLL_CHARACTERISTICS))
    print("WINDOWS_FIELDS_SIZE_OF_STACK_RESERVE = " + hex(WINDOWS_FIELDS_SIZE_OF_STACK_RESERVE))
    print("WINDOWS_FIELDS_SIZE_OF_STACK_COMMIT = " + hex(WINDOWS_FIELDS_SIZE_OF_STACK_COMMIT))
    print("WINDOWS_FIELDS_SIZE_OF_HEAP_RESERVE = " + hex(WINDOWS_FIELDS_SIZE_OF_HEAP_RESERVE))
    print("WINDOWS_FIELDS_SIZE_OF_HEAP_COMMIT = " + hex(WINDOWS_FIELDS_SIZE_OF_HEAP_COMMIT))
    print("WINDOWS_FIELDS_LOADER_FLAGS = " + hex(WINDOWS_FIELDS_LOADER_FLAGS))
    print("WINDOWS_FIELDS_NUMBER_OF_RVA_AND_SIZES = " + hex(WINDOWS_FIELDS_NUMBER_OF_RVA_AND_SIZES))

# Rebase the file bytes to skip over the windows specific fields
fileBytes = fileBytes[WINDOWS_FIELDS_FIELD_LENGTH:]