#!/usr/bin/python3
import argparse
import struct
import sys
from os import path
from datetime import datetime
import binascii 

def processString(binary_bytes):
    chars = []
    counter = 0
    while True:
        c = binary_bytes[counter]
        if c == 0x0:
            return "".join(chars)
        chars.append(chr(binary_bytes[counter]))
        counter += 1

parser = argparse.ArgumentParser(description='Processes a DLL file and outputs the exported functions and function ordinals, just like the Big Boy Dumpbin does.')
parser.add_argument('DLL', metavar='DLL', type=str, help='The path to the DLL which should be processed by dumpybin.')
parser.add_argument('--debug', dest='debugMode',action="store_true", help='supply this option to output a bunch of debugging data for nerds.')
parser.add_argument("-s", "--sections", help="Dump out sections data", action="store_true")
parser.add_argument("-i", "--imports", help="Dump out import data", action="store_true")
parser.add_argument("-e", "--exports", help="Dump out export data", action="store_true")

args = parser.parse_args()
DLL = args.DLL
debugMode = args.debugMode
dumpSections = args.sections
dumpImports = args.imports
dumpExports = args.exports

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
# We need an independent copy of fileBytes because we'll use it for RVA offset lookups later.
originalFileBytes = fileBytes
print(f"[+] Successfully read all {len(fileBytes)} bytes from the DLL, about to check that the file is a valid PE file.")

# Parse the magic number and make sure that it's a valid Windows PE
if(struct.unpack(">L", fileBytes[0:4])[0] != 0x4d5a9000):
    print("[-] The magic bytes don't match a valid PE file, quitting.")
    sys.exit()

print("[+] File is a valid PE file, proceeding to dump it.")

# Attempt to skip over the DOS header and DOS stubs
PE_FILE_START_OFFSET = fileBytes.find(struct.pack("<L",0x00004550))

if(PE_FILE_START_OFFSET < 0):
    print("[-] The supplied PE file is corrupted, it has no signature bytes.")
    sys.exit()

# Rebase the file bytes to skip over the DOS header, DOS stub and signature bytes
fileBytes = fileBytes[PE_FILE_START_OFFSET+4:]

# Process the COFF header
COFF_HEADER_LENGTH = 20
COFF_HEADER_MACHINE = struct.unpack("<H",fileBytes[0:2])[0]
COFF_HEADER_NUMBER_SECTIONS = struct.unpack("<H",fileBytes[2:4])[0]
COFF_HEADER_TIME_DATE_STAMP = struct.unpack("<L",fileBytes[4:8])[0]
COFF_HEADER_POINTER_TO_SYM_TABLE = struct.unpack("<L",fileBytes[8:12])[0] # Deprecated
COFF_HEADER_NUMBER_OF_SYMBOL_TABLE = struct.unpack("<L",fileBytes[12:16])[0] # Deprecated
COFF_HEADER_SIZE_OF_OPTIONAL_HEADER = struct.unpack("<H",fileBytes[16:18])[0]
COFF_HEADER_CHARACTERISTICS = struct.unpack("<H",fileBytes[18:20])[0]

print(f"[+] PE was compiled on {datetime.fromtimestamp(COFF_HEADER_TIME_DATE_STAMP)}")

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
COFF_FIELD_MAGIC = struct.unpack("<H",fileBytes[0:2])[0]
COFF_FIELD_MAJOR_LINKER_VERSION = struct.unpack("B",fileBytes[2:3])[0]
COFF_FIELD_MINOR_LINKER_VERSION = struct.unpack("B",fileBytes[3:4])[0]
COFF_FIELD_SIZE_OF_CODE = struct.unpack("<L",fileBytes[4:8])[0]
COFF_FIELD_SIZE_OF_INITIALIZED_DATA = struct.unpack("<L",fileBytes[8:12])[0]
COFF_FIELD_SIZE_OF_UNINITIALIZED_DATA = struct.unpack("<L",fileBytes[12:16])[0]
COFF_FIELD_ADDRESS_OF_ENTRY_POINT_RVA = struct.unpack("<L",fileBytes[16:20])[0]
COFF_FIELD_BASE_OF_CODE_RVA = struct.unpack("<L",fileBytes[20:24])[0]
COFF_FIELD_BASE_OF_DATA_RVA = struct.unpack("<L",fileBytes[24:28])[0]

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
WINDOWS_FIELDS_IMAGE_BASE  = struct.unpack("<L", fileBytes[0:4])[0]
WINDOWS_FIELDS_SECTION_ALIGNMENT = struct.unpack("<L", fileBytes[4:8])[0]
WINDOWS_FIELDS_FILE_ALIGNMENT = struct.unpack("<L", fileBytes[8:12])[0]
WINDOWS_FIELDS_MAJOR_OPERATING_SYSTEM_VERSION = struct.unpack("<H", fileBytes[12:14])[0]
WINDOWS_FIELDS_MINOR_OPERATING_SYSTEM_VERSION = struct.unpack("<H", fileBytes[14:16])[0]
WINDOWS_FIELDS_MAJOR_IMAGE_VERSION = struct.unpack("<H", fileBytes[16:18])[0]
WINDOWS_FIELDS_MINOR_IMAGE_VERSION = struct.unpack("<H", fileBytes[18:20])[0]
WINDOWS_FIELDS_MAJOR_SUBSYSTEM_VERSION = struct.unpack("<H", fileBytes[20:22])[0]
WINDOWS_FIELDS_MINOR_SUBSYSTEM_VERSION = struct.unpack("<H", fileBytes[22:24])[0]
WINDOWS_FIELDS_WIN32_VERSION_VALUE = struct.unpack("<L", fileBytes[24:28])[0]
WINDOWS_FIELDS_SIZE_OF_IMAGE = struct.unpack("<L", fileBytes[28:32])[0]
WINDOWS_FIELDS_SIZE_OF_HEADERS = struct.unpack("<L", fileBytes[32:36])[0]
WINDOWS_FIELDS_CHECKSUM = struct.unpack("<L", fileBytes[36:40])[0]
WINDOWS_FIELDS_SUBSYSTEM = struct.unpack("<H", fileBytes[40:42])[0]
WINDOWS_FIELDS_DLL_CHARACTERISTICS = struct.unpack("<H", fileBytes[42:44])[0]
WINDOWS_FIELDS_SIZE_OF_STACK_RESERVE = struct.unpack("<L", fileBytes[44:48])[0]
WINDOWS_FIELDS_SIZE_OF_STACK_COMMIT = struct.unpack("<L", fileBytes[48:52])[0]
WINDOWS_FIELDS_SIZE_OF_HEAP_RESERVE = struct.unpack("<L", fileBytes[52:56])[0]
WINDOWS_FIELDS_SIZE_OF_HEAP_COMMIT = struct.unpack("<L", fileBytes[56:60])[0]
WINDOWS_FIELDS_LOADER_FLAGS = struct.unpack("<L", fileBytes[60:64])[0]
WINDOWS_FIELDS_NUMBER_OF_RVA_AND_SIZES = struct.unpack("<L", fileBytes[64:68])[0]

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
DATA_DIRECTORY_LENGTH = 128
DATA_DIRECTORY_EXPORT_TABLE = struct.unpack("<L", fileBytes[0:4])[0]
DATA_DIRECTORY_SIZE_OF_EXPORT_TABLE = struct.unpack("<L", fileBytes[4:8])[0]
DATA_DIRECTORY_IMPORT_TABLE = struct.unpack("<L", fileBytes[8:12])[0]
DATA_DIRECTORY_SIZE_OF_IMPORT_TABLE = struct.unpack("<L", fileBytes[12:16])[0]
DATA_DIRECTORY_RESOURCE_TABLE = struct.unpack("<L", fileBytes[16:20])[0]
DATA_DIRECTORY_SIZE_OF_RESOURCE_TABLE = struct.unpack("<L", fileBytes[20:24])[0]
DATA_DIRECTORY_EXCEPTION_TABLE = struct.unpack("<L", fileBytes[24:28])[0]
DATA_DIRECTORY_SIZE_OF_EXCEPTION_TABLE = struct.unpack("<L", fileBytes[28:32])[0]
DATA_DIRECTORY_CERTIFICATE_TABLE = struct.unpack("<L", fileBytes[32:36])[0]
DATA_DIRECTORY_SIZE_OF_CERTIFICATE_TABLE = struct.unpack("<L", fileBytes[36:40])[0]
DATA_DIRECTORY_BASE_RELOCATION_TABLE = struct.unpack("<L", fileBytes[40:44])[0]
DATA_DIRECTORY_SIZE_OF_BASE_RELOCATION_TABLE = struct.unpack("<L", fileBytes[44:48])[0]
DATA_DIRECTORY_DEBUG = struct.unpack("<L", fileBytes[48:52])[0]
DATA_DIRECTORY_SIZE_OF_DEBUG = struct.unpack("<L", fileBytes[52:56])[0]
DATA_DIRECTORY_ARCHITECTURE_DATA = struct.unpack("<L", fileBytes[56:60])[0]
DATA_DIRECTORY_SIZE_OF_ARCHITECTURE_DATA = struct.unpack("<L", fileBytes[60:64])[0]
DATA_DIRECTORY_GLOBAL_PTR = struct.unpack("<L", fileBytes[64:68])[0]
DATA_DIRECTORY_NULL_BYTES_1 = struct.unpack("<L", fileBytes[68:72])[0]
DATA_DIRECTORY_TLS_TABLE = struct.unpack("<L", fileBytes[72:76])[0]
DATA_DIRECTORY_SIZE_OF_TLS_TABLE = struct.unpack("<L", fileBytes[76:80])[0]
DATA_DIRECTORY_LOAD_CONFIG_TABLE = struct.unpack("<L", fileBytes[80:84])[0]
DATA_DIRECTORY_SIZE_OF_LOAD_CONFIG_TABLE = struct.unpack("<L", fileBytes[84:88])[0]
DATA_DIRECTORY_BOUND_IMPORT = struct.unpack("<L", fileBytes[88:92])[0]
DATA_DIRECTORY_SIZE_OF_BOUND_IMPORT = struct.unpack("<L", fileBytes[92:96])[0]
DATA_DIRECTORY_IMPORT_ADDRESS_TABLE = struct.unpack("<L", fileBytes[96:100])[0]
DATA_DIRECTORY_SIZE_OF_IMPORT_ADDRESS_TABLE = struct.unpack("<L", fileBytes[100:104])[0]
DATA_DIRECTORY_DELAY_IMPORT_DESCRIPTOR = struct.unpack("<L", fileBytes[104:108])[0]
DATA_DIRECTORY_SIZE_OF_DELAY_IMPORT_DESCRIPTOR = struct.unpack("<L", fileBytes[108:112])[0]
DATA_DIRECTORY_CLR_RUNTIME_HEADER = struct.unpack("<L", fileBytes[112:116])[0]
DATA_DIRECTORY_SIZE_OF_CLR_RUNTIME_HEADER = struct.unpack("<L", fileBytes[116:120])[0]
DATA_DIRECTORY_NULL_BYTES_2 = struct.unpack("<L", fileBytes[120:124])[0]
DATA_DIRECTORY_NULL_BYTES_3 = struct.unpack("<L", fileBytes[124:128])[0]

if debugMode:
    print()
    print("DATA DIRECTORY FIELDS = \n===========================")
    print("DATA_DIRECTORY_LENGTH =  " + hex(DATA_DIRECTORY_LENGTH))
    print("DATA_DIRECTORY_EXPORT_TABLE = " + hex(DATA_DIRECTORY_EXPORT_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_EXPORT_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_EXPORT_TABLE))
    print("DATA_DIRECTORY_IMPORT_TABLE = " + hex(DATA_DIRECTORY_IMPORT_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_IMPORT_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_IMPORT_TABLE))
    print("DATA_DIRECTORY_RESOURCE_TABLE = " + hex(DATA_DIRECTORY_RESOURCE_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_RESOURCE_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_RESOURCE_TABLE))
    print("DATA_DIRECTORY_EXCEPTION_TABLE = " + hex(DATA_DIRECTORY_EXCEPTION_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_EXCEPTION_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_EXCEPTION_TABLE))
    print("DATA_DIRECTORY_CERTIFICATE_TABLE = " + hex(DATA_DIRECTORY_CERTIFICATE_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_CERTIFICATE_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_CERTIFICATE_TABLE))
    print("DATA_DIRECTORY_BASE_RELOCATION_TABLE = " + hex(DATA_DIRECTORY_BASE_RELOCATION_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_BASE_RELOCATION_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_BASE_RELOCATION_TABLE))
    print("DATA_DIRECTORY_DEBUG = " + hex(DATA_DIRECTORY_DEBUG))
    print("DATA_DIRECTORY_SIZE_OF_DEBUG = " + hex(DATA_DIRECTORY_SIZE_OF_DEBUG))
    print("DATA_DIRECTORY_ARCHITECTURE_DATA = " + hex(DATA_DIRECTORY_ARCHITECTURE_DATA))
    print("DATA_DIRECTORY_SIZE_OF_ARCHITECTURE_DATA = " + hex(DATA_DIRECTORY_SIZE_OF_ARCHITECTURE_DATA))
    print("DATA_DIRECTORY_GLOBAL_PTR = " + hex(DATA_DIRECTORY_GLOBAL_PTR))
    print("DATA_DIRECTORY_TLS_TABLE = " + hex(DATA_DIRECTORY_TLS_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_TLS_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_TLS_TABLE))
    print("DATA_DIRECTORY_LOAD_CONFIG_TABLE = " + hex(DATA_DIRECTORY_LOAD_CONFIG_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_LOAD_CONFIG_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_LOAD_CONFIG_TABLE))
    print("DATA_DIRECTORY_BOUND_IMPORT = " + hex(DATA_DIRECTORY_BOUND_IMPORT))
    print("DATA_DIRECTORY_SIZE_OF_BOUND_IMPORT = " + hex(DATA_DIRECTORY_SIZE_OF_BOUND_IMPORT))
    print("DATA_DIRECTORY_IMPORT_ADDRESS_TABLE = " + hex(DATA_DIRECTORY_IMPORT_ADDRESS_TABLE))
    print("DATA_DIRECTORY_SIZE_OF_IMPORT_ADDRESS_TABLE = " + hex(DATA_DIRECTORY_SIZE_OF_IMPORT_ADDRESS_TABLE))
    print("DATA_DIRECTORY_DELAY_IMPORT_DESCRIPTOR = " + hex(DATA_DIRECTORY_DELAY_IMPORT_DESCRIPTOR))
    print("DATA_DIRECTORY_SIZE_OF_DELAY_IMPORT_DESCRIPTOR = " + hex(DATA_DIRECTORY_SIZE_OF_DELAY_IMPORT_DESCRIPTOR))
    print("DATA_DIRECTORY_CLR_RUNTIME_HEADER = " + hex(DATA_DIRECTORY_CLR_RUNTIME_HEADER))
    print("DATA_DIRECTORY_SIZE_OF_CLR_RUNTIME_HEADER = " + hex(DATA_DIRECTORY_SIZE_OF_CLR_RUNTIME_HEADER))

# Rebase the file bytes to skip over the data directory fields
fileBytes = fileBytes[DATA_DIRECTORY_LENGTH:]

# Making a dictionary from section name to raw data pointer (we need this to process imports and exports)
sections = {}
# Iterate over all of the sections in the PE, dumping their data.
for section in range(1, COFF_HEADER_NUMBER_SECTIONS+1):
    SECTION_NAME = str(fileBytes[0:8],"ascii").replace("\x00","")
    SECTION_VIRTUAL_SIZE = struct.unpack("<L", fileBytes[8:12])[0]
    SECTION_VIRTUAL_ADDRESS = struct.unpack("<L", fileBytes[12:16])[0]
    SECTION_SIZE_OF_RAW_DATA = struct.unpack("<L", fileBytes[16:20])[0]
    SECTION_POINTER_TO_RAW_DATA = struct.unpack("<L", fileBytes[20:24])[0]
    SECTION_POINTER_TO_RELOCATIONS = struct.unpack("<L", fileBytes[24:28])[0]
    SECTION_POINTER_TO_LINE_NUMBERS = struct.unpack("<L", fileBytes[28:32])[0]
    SECTION_NUMBER_OF_RELOCATIONS = struct.unpack("<H", fileBytes[32:34])[0]
    SECTION_NUMBER_OF_LINE_NUMBERS = struct.unpack("<H", fileBytes[34:36])[0]
    SECTION_CHARACTERISTICS = struct.unpack("<L", fileBytes[36:40])[0]
    sections[SECTION_NAME] = (SECTION_POINTER_TO_RAW_DATA, SECTION_VIRTUAL_ADDRESS, SECTION_VIRTUAL_SIZE)

    if(debugMode):
        print()
        print(f"Section {section} ({SECTION_NAME}) \n===========================")
        print("SECTION_NAME = "+SECTION_NAME)
        print("SECTION_VIRTUAL_SIZE = "+hex(SECTION_VIRTUAL_SIZE))
        print("SECTION_VIRTUAL_ADDRESS = "+hex(SECTION_VIRTUAL_ADDRESS))
        print("SECTION_SIZE_OF_RAW_DATA = "+hex(SECTION_SIZE_OF_RAW_DATA))
        print("SECTION_POINTER_TO_RAW_DATA = "+hex(SECTION_POINTER_TO_RAW_DATA))
        print("SECTION_POINTER_TO_RELOCATIONS = "+hex(SECTION_POINTER_TO_RELOCATIONS))
        print("SECTION_POINTER_TO_LINE_NUMBERS = "+hex(SECTION_POINTER_TO_LINE_NUMBERS))
        print("SECTION_NUMBER_OF_RELOCATIONS = "+hex(SECTION_NUMBER_OF_RELOCATIONS))
        print("SECTION_NUMBER_OF_LINE_NUMBERS = "+hex(SECTION_NUMBER_OF_LINE_NUMBERS))
        print("SECTION_CHARACTERISTICS = "+hex(SECTION_CHARACTERISTICS))
    
    # Rebase fileBytes to the next section.
    fileBytes = fileBytes[40:]

if(dumpSections):
    print("[+] Sections - ")
    for key in sections:
        print(f"    {key} - Raw Data Pointer: {hex(sections[key][0])} RVA: {hex(sections[key][1])}, Size: {hex(sections[key][2])}")
    print()


# Process the DLL Import Table. Rebase fileBytes back to 0 so that RVAs work correctly.
fileBytes = originalFileBytes

# In order to read the import table, there must be a section in the PE file named ".idata"
importTableOffset = 0
try:
    importTableOffset = sections[".idata"][0]

    fileBytes = originalFileBytes[importTableOffset:]
    dllImports = {}
    # Loop infinitely until the import directory table has been processed fully. (20 null bytes in a row.)
    while 1:
        IMPORT_DIRECTORY_ORIGINAL_FIRST_THUNK = struct.unpack("<L", fileBytes[0:4])[0]
        IMPORT_DIRECTORY_TIME_DATE_STAMP = struct.unpack("<L", fileBytes[4:8])[0]
        IMPORT_DIRECTORY_FORWARDER_CHAIN = struct.unpack("<L", fileBytes[8:12])[0]
        IMPORT_DIRECTORY_NAME = struct.unpack("<L", fileBytes[12:16])[0]
        IMPORT_DIRECTORY_FIRST_THUNK = struct.unpack("<L", fileBytes[16:20])[0]
        if(debugMode):
            print()
            print("IMPORT DIRECTORY FIELDS = \n===========================")
            print("IMPORT_DIRECTORY_ORIGINAL_FIRST_THUNK = " + hex(IMPORT_DIRECTORY_ORIGINAL_FIRST_THUNK))
            print("IMPORT_DIRECTORY_TIME_DATE_STAMP = " + hex(IMPORT_DIRECTORY_TIME_DATE_STAMP) + " ("+str(datetime.fromtimestamp(IMPORT_DIRECTORY_TIME_DATE_STAMP))+")")
            print("IMPORT_DIRECTORY_FORWARDER_CHAIN = " + hex(IMPORT_DIRECTORY_FORWARDER_CHAIN))
            print("IMPORT_DIRECTORY_NAME = " + hex(IMPORT_DIRECTORY_NAME))
            print("IMPORT_DIRECTORY_FIRST_THUNK = " + hex(IMPORT_DIRECTORY_FIRST_THUNK))
            print()
        
        # Subtracting DATA_DIRECTORY_IMPORT_TABLE from each field to go from RVA offset values to raw file offset values.
        IMPORT_DIRECTORY_ORIGINAL_FIRST_THUNK = IMPORT_DIRECTORY_ORIGINAL_FIRST_THUNK-DATA_DIRECTORY_IMPORT_TABLE
        IMPORT_DIRECTORY_FIRST_THUNK = IMPORT_DIRECTORY_FIRST_THUNK-DATA_DIRECTORY_IMPORT_TABLE
        IMPORT_DIRECTORY_NAME = IMPORT_DIRECTORY_NAME-DATA_DIRECTORY_IMPORT_TABLE

        # I fully acknowledge that this line looks insane, but IMPORT_DIRECTORY_NAME is (for example) 0x6153, DATA_DIRECTORY_IMPORT_TABLE is (for example) 0x6000
        # So importTableOffset + (0x6153-0x6000) gives us the offset in the raw data to where the DLL name string lives.
        importedDllName = (processString(originalFileBytes[importTableOffset+IMPORT_DIRECTORY_NAME:]))
        dllImports[importedDllName] = []
            
        # Start looping over the array of IMAGE_THUNK_DATA pointers, stopping when a null pointer is reached.
        thunkDataPointers = []
        offsetIntoArray = 0
        while 1:
            # import table + array of thunks + offset into array. Multiplied by 4 because the array is full of DWORDS
            offset = importTableOffset+IMPORT_DIRECTORY_ORIGINAL_FIRST_THUNK+(offsetIntoArray*4)      
            pointer = struct.unpack("<L",originalFileBytes[offset:offset+4])[0]
            # Once we reach a null pointer we've extracted all of the pointers successfully.
            if(pointer == 0):
                break
            # Rebase the pointer from RVA offset to raw file offset
            pointer = pointer - DATA_DIRECTORY_IMPORT_TABLE
            pointer = importTableOffset + pointer

            thunkDataPointers.append(pointer)
            offsetIntoArray += 1
        
        for pointer in thunkDataPointers:
            # Ordinals are shorts.
            ordinal = struct.unpack("<H", originalFileBytes[pointer:pointer+2])[0]
            importName = processString(originalFileBytes[pointer+2:])
            dllImports[importedDllName].append((ordinal, importName))

        # Advance file bytes to the next Import Directory record
        fileBytes = fileBytes[20:]

        # If the next Import Directory record is completely empty (full of nulls) then we've processed the entire directory.
        if(fileBytes[0:20] == (b"\x00"*20)):
            break

    if(dumpImports):
        print("[+] Imports - ")
        for key in dllImports:
            print("    Imported DLL name: " + key)
            print("    ======================================")
            for ordinal, importName in dllImports[key]:
                print(f"    Ordinal #{ordinal}, function name: {importName}")
            print()
except KeyError:
    if(dumpImports):
        print("[-] The supplied binary doesn't have a .idata section, can't process the Import Table.")


# Process the DLL Export Table. Rebase fileBytes back to 0 so that RVAs work correctly.
fileBytes = originalFileBytes

# In order to read the export table, there must be a section in the PE file named ".edata"
exportTableOffset = 0
try:
    exportTableOffset = sections[".edata"][0]

    fileBytes = originalFileBytes[exportTableOffset:]
    dllExports = {}

    EXPORT_DIRECTORY_LENGTH = 40
    EXPORT_DIRECTORY_CHARACTERISTICS = struct.unpack("<L", fileBytes[0:4])[0]
    EXPORT_DIRECTORY_TIME_DATE_STAMP = struct.unpack("<L", fileBytes[4:8])[0]
    EXPORT_DIRECTORY_MAJOR_VERSION = struct.unpack("<H", fileBytes[8:10])[0]
    EXPORT_DIRECTORY_MINOR_VERSION = struct.unpack("<H", fileBytes[10:12])[0]
    EXPORT_DIRECTORY_NAME = struct.unpack("<L", fileBytes[12:16])[0]
    EXPORT_DIRECTORY_BASE = struct.unpack("<L", fileBytes[16:20])[0]
    EXPORT_DIRECTORY_NUMBER_OF_FUNCTIONS = struct.unpack("<L", fileBytes[20:24])[0]
    EXPORT_DIRECTORY_NUMBER_OF_NAMES = struct.unpack("<L", fileBytes[24:28])[0]
    EXPORT_DIRECTORY_ADDRESS_OF_FUNCTIONS = struct.unpack("<L", fileBytes[28:32])[0]
    EXPORT_DIRECTORY_ADDRESS_OF_NAMES = struct.unpack("<L", fileBytes[32:36])[0]
    EXPORT_DIRECTORY_ADDRESS_OF_NAME_ORDINALS = struct.unpack("<L", fileBytes[36:40])[0]

    if(debugMode):
        print("EXPORT DIRECTORY FIELDS = \n===========================")
        print("EXPORT_DIRECTORY_LENGTH = " + hex(EXPORT_DIRECTORY_LENGTH))
        print("EXPORT_DIRECTORY_CHARACTERISTICS = " + hex(EXPORT_DIRECTORY_CHARACTERISTICS))
        print("EXPORT_DIRECTORY_TIME_DATE_STAMP = " + hex(EXPORT_DIRECTORY_TIME_DATE_STAMP) + " ("+str(datetime.fromtimestamp(EXPORT_DIRECTORY_TIME_DATE_STAMP))+")")
        print("EXPORT_DIRECTORY_MAJOR_VERSION = " + hex(EXPORT_DIRECTORY_MAJOR_VERSION))
        print("EXPORT_DIRECTORY_MINOR_VERSION = " + hex(EXPORT_DIRECTORY_MINOR_VERSION))
        print("EXPORT_DIRECTORY_NAME = " + hex(EXPORT_DIRECTORY_NAME))
        print("EXPORT_DIRECTORY_BASE = " + hex(EXPORT_DIRECTORY_BASE))
        print("EXPORT_DIRECTORY_NUMBER_OF_FUNCTIONS = " + hex(EXPORT_DIRECTORY_NUMBER_OF_FUNCTIONS))
        print("EXPORT_DIRECTORY_NUMBER_OF_NAMES = " + hex(EXPORT_DIRECTORY_NUMBER_OF_NAMES))
        print("EXPORT_DIRECTORY_ADDRESS_OF_FUNCTIONS = " + hex(EXPORT_DIRECTORY_ADDRESS_OF_FUNCTIONS))
        print("EXPORT_DIRECTORY_ADDRESS_OF_NAMES = " + hex(EXPORT_DIRECTORY_ADDRESS_OF_NAMES))
        print("EXPORT_DIRECTORY_ADDRESS_OF_NAME_ORDINALS = " + hex(EXPORT_DIRECTORY_ADDRESS_OF_NAME_ORDINALS))
    
    # Do the same subtraction trick as with imports to go from RVA-based offsets to file based offsets
    EXPORT_DIRECTORY_NAME -= DATA_DIRECTORY_EXPORT_TABLE
    EXPORT_DIRECTORY_ADDRESS_OF_FUNCTIONS -= DATA_DIRECTORY_EXPORT_TABLE
    EXPORT_DIRECTORY_ADDRESS_OF_NAMES -= DATA_DIRECTORY_EXPORT_TABLE
    EXPORT_DIRECTORY_ADDRESS_OF_NAME_ORDINALS -= DATA_DIRECTORY_EXPORT_TABLE

    exportedName = processString(originalFileBytes[exportTableOffset+EXPORT_DIRECTORY_NAME:])
    arrayOfNameOrdinalTuples = []
    
    # Quick sanity check to make sure that the number of names matches the number of functions (otherwise we're in trouble)
    if EXPORT_DIRECTORY_NUMBER_OF_FUNCTIONS != EXPORT_DIRECTORY_NUMBER_OF_NAMES:
        if(dumpExports):
            print("[-] The EXPORT_DIRECTORY_NUMBER_OF_FUNCTIONS field doesn't match EXPORT_DIRECTORY_NUMBER_OF_NAMES, cannot dump exports.")
        raise NameError

    i = 0
    while i < EXPORT_DIRECTORY_NUMBER_OF_FUNCTIONS:
        namePointerOffset = exportTableOffset+EXPORT_DIRECTORY_ADDRESS_OF_NAMES+(i*4) # These pointers are DWORDs, so i*4
        functionPointerOffset = exportTableOffset+EXPORT_DIRECTORY_ADDRESS_OF_FUNCTIONS+(i*4) # These pointers are DWORDs, so i*4
        nameOffset = struct.unpack("<L", originalFileBytes[namePointerOffset:namePointerOffset+4])[0]
        nameOffset -= DATA_DIRECTORY_EXPORT_TABLE
        ordinalOffset = exportTableOffset+EXPORT_DIRECTORY_ADDRESS_OF_NAME_ORDINALS+(i*2) # The name ordinals are WORDs, so i*2
        currFunctionName = processString(originalFileBytes[exportTableOffset+nameOffset:]) #
        currFunctionOrdinal = struct.unpack("<H", originalFileBytes[ordinalOffset:ordinalOffset+2])[0]
        currFunctionRVA =  struct.unpack("<L", originalFileBytes[functionPointerOffset:functionPointerOffset+4])[0]
        i+=1
        arrayOfNameOrdinalTuples.append((currFunctionOrdinal, currFunctionName, currFunctionRVA))

except KeyError:
    if(dumpExports):
        print("[-] The supplied binary doesn't have a .edata section, can't process the Export Table.")
except NameError: 
    pass

if dumpExports:
    print("[+] Exports - ")
    for currFunctionOrdinal, currFunctionName, currFunctionRVA in arrayOfNameOrdinalTuples:
        print(f"    Ordinal #{currFunctionOrdinal}, function name: {currFunctionName}, function RVA: { hex(currFunctionRVA) }")
    print()
