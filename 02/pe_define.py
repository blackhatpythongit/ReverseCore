# -*-coding:utf-8-*-
from ctypes import *

BYTE = c_ubyte
WORD = c_ushort
DWORD = c_ulong
LONG = c_ulong
ULONGLONG = c_ulonglong

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550

IMAGE_FILE_MACHINE_DICT = {
	0		:	"IMAGE_FILE_MACHINE_UNKNOWN",
	0x014c	:	"IMAGE_FILE_MACHINE_I386",
	0x0162	:	"IMAGE_FILE_MACHINE_R3000",
	0x0166	:	"IMAGE_FILE_MACHINE_R4000",
	0x0168	:	"IMAGE_FILE_MACHINE_R10000",
	0x0169	:	"IMAGE_FILE_MACHINE_WCEMIPSV2",
	0x0184	:	"IMAGE_FILE_MACHINE_ALPHA",
	0x01F0	:	"IMAGE_FILE_MACHINE_POWERPC",
	0x01a2	:	"IMAGE_FILE_MACHINE_SH3",
	0x01a4	:	"IMAGE_FILE_MACHINE_SH3E",
	0x01a6	:	"IMAGE_FILE_MACHINE_SH4",
	0x01c0	:	"IMAGE_FILE_MACHINE_ARM",
	0x01c2	:	"IMAGE_FILE_MACHINE_THUMB",
	0x0200	:	"IMAGE_FILE_MACHINE_IA64",
	0x0266	:	"IMAGE_FILE_MACHINE_MIPS16",
	0x0366	:	"IMAGE_FILE_MACHINE_MIPSFPU",
	0x0466	:	"IMAGE_FILE_MACHINE_MIPSFPU16",
	0x0284	:	"IMAGE_FILE_MACHINE_ALPHA64/IMAGE_FILE_MACHINE_AXP64",
	0x8664	:	"IMAGE_FILE_MACHINE_AMD64",
}

IMAGE_FILE_CHARACTERISTICS_DICT = {
	0x0001:"IMAGE_FILE_RELOCS_STRIPPED",
	0x0002:"IMAGE_FILE_EXECUTABLE_IMAGE",
	0x0004:"IMAGE_FILE_LINE_NUMS_STRIPPED",
	0x0008:"IMAGE_FILE_LOCAL_SYMS_STRIPPED",
	0x0010:"IMAGE_FILE_AGGRESIVE_WS_TRIM",
	0x0020:"IMAGE_FILE_LARGE_ADDRESS_AWARE",
	0x0080:"IMAGE_FILE_BYTES_REVERSED_LO",
	0x0100:"IMAGE_FILE_32BIT_MACHINE",
	0x0200:"IMAGE_FILE_DEBUG_STRIPPED",
	0x0400:"IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
	0x0800:"IMAGE_FILE_NET_RUN_FROM_SWAP",
	0x1000:"IMAGE_FILE_SYSTEM",
	0x2000:"IMAGE_FILE_DLL",
	0x4000:"IMAGE_FILE_UP_SYSTEM_ONLY",
	0x8000:"IMAGE_FILE_BYTES_REVERSED_HI",
}

IMAGE_SIZEOF_FILE_HEADER = 20

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

DataDirectory_Description = {
	0:"Export table address and size",
	1:"Import table address and size",
	2:"Resource table address and size",
	3:"Exception table address and size",
	4:"Certificate table address and size",
	5:"Base relocation table address and size",
	6:"Debugging information starting address and size",
	7:"Architecture-specific data address and size",
	8:"Global pointer register relative virtual address",
	9:"Thread local storage (TLS) table address and size",
	10:"Load configuration table address and size",
	11:"Bound import table address and size",
	12:"Import address table address and size",
	13:"Delay import descriptor address and size",
	14:"The CLR header address and size",
	15:"Reserved",
}

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

IMAGE_SIZEOF_NT_OPTIONAL32_HEADER = 224
IMAGE_SIZEOF_NT_OPTIONAL64_HEADER = 240

IMAGE_SIZEOF_SHORT_NAME = 8

IMAGE_SECTION_HEADER_CHARACTERISTICS_DICT = {
	0x00000008:"IMAGE_SCN_TYPE_NO_PAD",
	0x00000020:"IMAGE_SCN_CNT_CODE",
	0x00000040:"IMAGE_SCN_CNT_INITIALIZED_DATA",
	0x00000080:"IMAGE_SCN_CNT_UNINITIALIZED_DATA",
	0x00000100:"IMAGE_SCN_LNK_OTHER",
	0x00000200:"IMAGE_SCN_LNK_INFO",
	0x00000800:"IMAGE_SCN_LNK_REMOVE",
	0x00001000:"IMAGE_SCN_LNK_COMDAT",
	0x00004000:"IMAGE_SCN_NO_DEFER_SPEC_EXC",
	0x00008000:"IMAGE_SCN_GPREL",
	0x00008000:"IMAGE_SCN_MEM_FARDATA",
	0x00020000:"IMAGE_SCN_MEM_PURGEABLE",
	0x00020000:"IMAGE_SCN_MEM_16BIT",
	0x00040000:"IMAGE_SCN_MEM_LOCKED",
	0x00080000:"IMAGE_SCN_MEM_PRELOAD",
	0x00100000:"IMAGE_SCN_ALIGN_1BYTES",
	0x00200000:"IMAGE_SCN_ALIGN_2BYTES",
	0x00300000:"IMAGE_SCN_ALIGN_4BYTES",
	0x00400000:"IMAGE_SCN_ALIGN_8BYTES",
	0x00500000:"IMAGE_SCN_ALIGN_16BYTES",
	0x00600000:"IMAGE_SCN_ALIGN_32BYTES",
	0x00700000:"IMAGE_SCN_ALIGN_64BYTES",
	0x00800000:"IMAGE_SCN_ALIGN_128BYTES",
	0x00900000:"IMAGE_SCN_ALIGN_256BYTES",
	0x00A00000:"IMAGE_SCN_ALIGN_512BYTES",
	0x00B00000:"IMAGE_SCN_ALIGN_1024BYTES",
	0x00C00000:"IMAGE_SCN_ALIGN_2048BYTES",
	0x00D00000:"IMAGE_SCN_ALIGN_4096BYTES",
	0x00E00000:"IMAGE_SCN_ALIGN_8192BYTES",
	0x01000000:"IMAGE_SCN_LNK_NRELOC_OVFL",
	0x02000000:"IMAGE_SCN_MEM_DISCARDABLE",
	0x04000000:"IMAGE_SCN_MEM_NOT_CACHED",
	0x08000000:"IMAGE_SCN_MEM_NOT_PAGED",
	0x10000000:"IMAGE_SCN_MEM_SHARED",
	0x20000000:"IMAGE_SCN_MEM_EXECUTE",
	0x40000000:"IMAGE_SCN_MEM_READ",
	0x80000000:"IMAGE_SCN_MEM_WRITE",
	0x00000001:"IMAGE_SCN_SCALE_INDEX",
}

IMAGE_SIZEOF_SECTION_HEADER = 40

# IMAGE_DOS_HEADER大小固定0x40字节

# typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
#     WORD   e_magic;                     // Magic number
#     WORD   e_cblp;                      // Bytes on last page of file
#     WORD   e_cp;                        // Pages in file
#     WORD   e_crlc;                      // Relocations
#     WORD   e_cparhdr;                   // Size of header in paragraphs
#     WORD   e_minalloc;                  // Minimum extra paragraphs needed
#     WORD   e_maxalloc;                  // Maximum extra paragraphs needed
#     WORD   e_ss;                        // Initial (relative) SS value
#     WORD   e_sp;                        // Initial SP value
#     WORD   e_csum;                      // Checksum
#     WORD   e_ip;                        // Initial IP value
#     WORD   e_cs;                        // Initial (relative) CS value
#     WORD   e_lfarlc;                    // File address of relocation table
#     WORD   e_ovno;                      // Overlay number
#     WORD   e_res[4];                    // Reserved words
#     WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
#     WORD   e_oeminfo;                   // OEM information; e_oemid specific
#     WORD   e_res2[10];                  // Reserved words
#     LONG   e_lfanew;                    // File address of new exe header
#   } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

class IMAGE_DOS_HEADER(Structure):
	_fields_ = [
		("e_magic",		WORD),
		("e_cblp",		WORD),
		("e_cp",		WORD),
		("e_crlc",		WORD),
		("e_cparhdr",	WORD),
		("e_minalloc",	WORD),
		("e_maxalloc",	WORD),
		("e_ss",		WORD),
		("e_sp",		WORD),
		("e_csum",		WORD),
		("e_ip",		WORD),
		("e_cs",		WORD),
		("e_lfarlc",	WORD),
		("e_ovno",		WORD),
		("e_res",		WORD * 4),
		("e_oemid",		WORD),
		("e_oeminfo",	WORD),
		("e_res2",		WORD * 10),
		("e_lfanew",	LONG),
	]

	def display(self):
		print "e_magic : 0x%04x" % self.e_magic
		print "e_lfanew : 0x%08x" % self.e_lfanew

# IMAGE_FILE_HEADER大小固定20字节

# typedef struct _IMAGE_FILE_HEADER {
#     WORD    Machine;
#     WORD    NumberOfSections;
#     DWORD   TimeDateStamp;
#     DWORD   PointerToSymbolTable;
#     DWORD   NumberOfSymbols;
#     WORD    SizeOfOptionalHeader;
#     WORD    Characteristics;
# } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

class IMAGE_FILE_HEADER(Structure):
	_fields_ = [
		("Machine",					WORD),
		("NumberOfSections",		WORD),
		("TimeDateStamp",			DWORD),
		("PointerToSymbolTable",	DWORD),
		("NumberOfSymbols",			DWORD),
		("SizeOfOptionalHeader",	WORD),
		("Characteristics",			WORD),
	]

	def display(self):
		print "Machine : %s(0x%04x)" %(IMAGE_FILE_MACHINE_DICT[self.Machine], self.Machine)
		print "NumberOfSections : 0x%04x" %self.NumberOfSections
		print "SizeOfOptionalHeader : 0x%04x" %self.SizeOfOptionalHeader
		print "Characteristics : ",
		for each in IMAGE_FILE_CHARACTERISTICS_DICT:
			if each & self.Characteristics:
				print IMAGE_FILE_CHARACTERISTICS_DICT[each], "|",
		print "0x%04x" %self.Characteristics


# typedef struct _IMAGE_DATA_DIRECTORY {
#     DWORD   VirtualAddress;
#     DWORD   Size;
# } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

class IMAGE_DATA_DIRECTORY(Structure):
	_fields_ = [
		("VirtualAddress",	DWORD),
		("Size",			DWORD),
	]

# typedef struct _IMAGE_OPTIONAL_HEADER64 {
#     WORD        Magic;
#     BYTE        MajorLinkerVersion;
#     BYTE        MinorLinkerVersion;
#     DWORD       SizeOfCode;
#     DWORD       SizeOfInitializedData;
#     DWORD       SizeOfUninitializedData;
#     DWORD       AddressOfEntryPoint;
#     DWORD       BaseOfCode;
#     ULONGLONG   ImageBase;
#     DWORD       SectionAlignment;
#     DWORD       FileAlignment;
#     WORD        MajorOperatingSystemVersion;
#     WORD        MinorOperatingSystemVersion;
#     WORD        MajorImageVersion;
#     WORD        MinorImageVersion;
#     WORD        MajorSubsystemVersion;
#     WORD        MinorSubsystemVersion;
#     DWORD       Win32VersionValue;
#     DWORD       SizeOfImage;
#     DWORD       SizeOfHeaders;
#     DWORD       CheckSum;
#     WORD        Subsystem;
#     WORD        DllCharacteristics;
#     ULONGLONG   SizeOfStackReserve;
#     ULONGLONG   SizeOfStackCommit;
#     ULONGLONG   SizeOfHeapReserve;
#     ULONGLONG   SizeOfHeapCommit;
#     DWORD       LoaderFlags;
#     DWORD       NumberOfRvaAndSizes;
#     IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
# } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

class IMAGE_OPTIONAL_HEADER64(Structure):
	_fields_ = [
		("Magic",							WORD),
		("MajorLinkerVersion",				BYTE),
		("MinorLinkerVersion",				BYTE),
		("SizeOfCode",						DWORD),
		("SizeOfInitializedData",			DWORD),
		("SizeOfUninitializedData",			DWORD),
		("AddressOfEntryPoint",				DWORD),
		("BaseOfCode",						DWORD),
		("ImageBase",						ULONGLONG),
		("SectionAlignment",				DWORD),
		("FileAlignment",					DWORD),
		("MajorOperatingSystemVersion",		WORD),
		("MinorOperatingSystemVersion",		WORD),
		("MajorImageVersion",				WORD),
		("MinorImageVersion",				WORD),
		("MajorSubsystemVersion",			WORD),
		("MinorSubsystemVersion",			WORD),
		("Win32VersionValue",				DWORD),
		("SizeOfImage",						DWORD),
		("SizeOfHeaders",					DWORD),
		("CheckSum",						DWORD),
		("Subsystem",						WORD),
		("DllCharacteristics",				WORD),
		("SizeOfStackReserve",				ULONGLONG),
		("SizeOfStackCommit",				ULONGLONG),
		("SizeOfHeapReserve",				ULONGLONG),
		("SizeOfHeapCommit",				ULONGLONG),
		("LoaderFlags",						DWORD),
		("NumberOfRvaAndSizes",				DWORD),
		("DataDirectory",					IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
	]

	def display(self):
		print "Magic: 0x%04x" %self.Magic
		print "AddressOfEntryPoint: 0x%08x" %self.AddressOfEntryPoint
		print "ImageBase: 0x%016x" %self.ImageBase
		print "SectionAlignment: 0x%08x" %self.SectionAlignment
		print "FileAlignment: 0x%08x" %self.FileAlignment
		print "SizeOfImage: 0x%08x" %self.SizeOfImage
		print "SizeOfHeaders: 0x%08x" %self.SizeOfHeaders
		print "Subsystem: 0x%04x" %self.Subsystem
		print "NumberOfRvaAndSizes: 0x%08x" %self.NumberOfRvaAndSizes
		print "DataDirectory:"
		for i in range(self.NumberOfRvaAndSizes):
			print "%08x %08x (%s)" %(self.DataDirectory[i].VirtualAddress, self.DataDirectory[i].Size, DataDirectory_Description[i])



# typedef struct _IMAGE_OPTIONAL_HEADER {
#     //
#     // Standard fields.
#     //

#     WORD    Magic;
#     BYTE    MajorLinkerVersion;
#     BYTE    MinorLinkerVersion;
#     DWORD   SizeOfCode;
#     DWORD   SizeOfInitializedData;
#     DWORD   SizeOfUninitializedData;
#     DWORD   AddressOfEntryPoint;
#     DWORD   BaseOfCode;
#     DWORD   BaseOfData;

#     //
#     // NT additional fields.
#     //

#     DWORD   ImageBase;
#     DWORD   SectionAlignment;
#     DWORD   FileAlignment;
#     WORD    MajorOperatingSystemVersion;
#     WORD    MinorOperatingSystemVersion;
#     WORD    MajorImageVersion;
#     WORD    MinorImageVersion;
#     WORD    MajorSubsystemVersion;
#     WORD    MinorSubsystemVersion;
#     DWORD   Win32VersionValue;
#     DWORD   SizeOfImage;
#     DWORD   SizeOfHeaders;
#     DWORD   CheckSum;
#     WORD    Subsystem;
#     WORD    DllCharacteristics;
#     DWORD   SizeOfStackReserve;
#     DWORD   SizeOfStackCommit;
#     DWORD   SizeOfHeapReserve;
#     DWORD   SizeOfHeapCommit;
#     DWORD   LoaderFlags;
#     DWORD   NumberOfRvaAndSizes;
#     IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
# } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

class IMAGE_OPTIONAL_HEADER32(Structure):
	_fields_ = [
		("Magic",							WORD),
		("MajorLinkerVersion",				BYTE),
		("MinorLinkerVersion",				BYTE),
		("SizeOfCode",						DWORD),
		("SizeOfInitializedData",			DWORD),
		("SizeOfUninitializedData",			DWORD),
		("AddressOfEntryPoint",				DWORD),
		("BaseOfCode",						DWORD),
		("BaseOfData",						DWORD),
		("ImageBase",						DWORD),
		("SectionAlignment",				DWORD),
		("FileAlignment",					DWORD),
		("MajorOperatingSystemVersion",		WORD),
		("MinorOperatingSystemVersion",		WORD),
		("MajorImageVersion",				WORD),
		("MinorImageVersion",				WORD),
		("MajorSubsystemVersion",			WORD),
		("MinorSubsystemVersion",			WORD),
		("Win32VersionValue",				DWORD),
		("SizeOfImage",						DWORD),
		("SizeOfHeaders",					DWORD),
		("CheckSum",						DWORD),
		("Subsystem",						WORD),
		("DllCharacteristics",				WORD),
		("SizeOfStackReserve",				DWORD),
		("SizeOfStackCommit",				DWORD),
		("SizeOfHeapReserve",				DWORD),
		("SizeOfHeapCommit",				DWORD),
		("LoaderFlags",						DWORD),
		("NumberOfRvaAndSizes",				DWORD),
		("DataDirectory",					IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
	]

	def display(self):
		print "Magic: 0x%04x" %self.Magic
		print "AddressOfEntryPoint: 0x%08x" %self.AddressOfEntryPoint
		print "ImageBase: 0x%08x" %self.ImageBase
		print "SectionAlignment: 0x%08x" %self.SectionAlignment
		print "FileAlignment: 0x%08x" %self.FileAlignment
		print "SizeOfImage: 0x%08x" %self.SizeOfImage
		print "SizeOfHeaders: 0x%08x" %self.SizeOfHeaders
		print "Subsystem: 0x%04x" %self.Subsystem
		print "NumberOfRvaAndSizes: 0x%08x" %self.NumberOfRvaAndSizes
		print "DataDirectory:"
		for i in range(self.NumberOfRvaAndSizes):
			print "%08x %08x (%s)" %(self.DataDirectory[i].VirtualAddress, self.DataDirectory[i].Size, DataDirectory_Description[i])

# typedef struct _IMAGE_NT_HEADERS64 {
#     DWORD Signature;
#     IMAGE_FILE_HEADER FileHeader;
#     IMAGE_OPTIONAL_HEADER64 OptionalHeader;
# } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

# typedef struct _IMAGE_NT_HEADERS {
#     DWORD Signature;
#     IMAGE_FILE_HEADER FileHeader;
#     IMAGE_OPTIONAL_HEADER32 OptionalHeader;
# } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

class IMAGE_NT_HEADERS64(Structure):
	_fields_ = [
		("Signature",		DWORD),
		("FileHeader",		IMAGE_FILE_HEADER),
		("OptionalHeader", 	IMAGE_OPTIONAL_HEADER64),
	]

	def display(self):
		self.FileHeader.display()
		self.OptionalHeader.display()

class IMAGE_NT_HEADERS32(Structure):
	_fields_ = [
		("Signature",		DWORD),
		("FileHeader",		IMAGE_FILE_HEADER),
		("OptionalHeader",	IMAGE_OPTIONAL_HEADER32),
	]

	def display(self):
		self.FileHeader.display()
		self.OptionalHeader.display()

# typedef struct _IMAGE_SECTION_HEADER {
#     BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
#     union {
#             DWORD   PhysicalAddress;
#             DWORD   VirtualSize;
#     } Misc;
#     DWORD   VirtualAddress;
#     DWORD   SizeOfRawData;
#     DWORD   PointerToRawData;
#     DWORD   PointerToRelocations;
#     DWORD   PointerToLinenumbers;
#     WORD    NumberOfRelocations;
#     WORD    NumberOfLinenumbers;
#     DWORD   Characteristics;
# } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


class U(Union):
	_fields_ = [
		("PhysicalAddress",	DWORD),
		("VirtualSize",		DWORD),
	]

class IMAGE_SECTION_HEADER(Structure):
	_fields_ = [
		("Name",					BYTE * IMAGE_SIZEOF_SHORT_NAME),
		("Misc",					U),
		("VirtualAddress",			DWORD),
		("SizeOfRawData",			DWORD),
		("PointerToRawData",		DWORD),
		("PointerToRelocations",	DWORD),
		("PointerToLinenumbers",	DWORD),
		("NumberOfRelocations",		WORD),
		("NumberOfLinenumbers",		WORD),
		("Characteristics",			DWORD),
	]

	def display(self):
		print "Name: %s" %c_char_p(''.join([chr(c) for c in self.Name])).value
		print "VirtualSize: 0x%08x" %self.Misc.VirtualSize
		print "VirtualAddress: 0x%08x" %self.VirtualAddress
		print "SizeOfRawData: 0x%08x" %self.SizeOfRawData
		print "PointerToRawData: 0x%08x" %self.PointerToRawData
		print "Characteristics:",
		for each in IMAGE_SECTION_HEADER_CHARACTERISTICS_DICT:
			if each & self.Characteristics:
				print IMAGE_SECTION_HEADER_CHARACTERISTICS_DICT[each], "|",
		print "0x%04x" %self.Characteristics

# typedef struct _IMAGE_IMPORT_BY_NAME {
#     WORD    Hint;
#     BYTE    Name[1];
# } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

# typedef struct _IMAGE_IMPORT_DESCRIPTOR {
#     union {
#         DWORD   Characteristics;            // 0 for terminating null import descriptor
#         DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
#     };
#     DWORD   TimeDateStamp;                  // 0 if not bound,
#                                             // -1 if bound, and real date\time stamp
#                                             //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
#                                             // O.W. date/time stamp of DLL bound to (Old BIND)

#     DWORD   ForwarderChain;                 // -1 if no forwarders
#     DWORD   Name;
#     DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
# } IMAGE_IMPORT_DESCRIPTOR;

class IMAGE_IMPORT_BY_NAME(Structure):
	_fields_ = [
		("Hint", WORD),
		("Name", BYTE),
	]

class _U(Union):
	_fields_= [
		("Characteristics",		DWORD),
		("OriginalFirstThunk",	DWORD),
	]

class IMAGE_IMPORT_DESCRIPTOR(Structure):
	_anonymous_ = ("u",)
	_fields_ = [
		("u",				_U),
		("TimeDateStamp",	DWORD),
		("ForwarderChain",	DWORD),
		("Name",			DWORD),
		("FirstThunk",		DWORD),
	]

	def display(self):
		print "OriginalFirstThunk: 0x%08x" %self.OriginalFirstThunk
		print "Name: 0x%08x" %self.Name
		print "FirstThunk: 0x%08x" %self.FirstThunk

class IMAGE_EXPORT_DIRECTORY(Structure):
	_fields_=[
		("Characteristics",			DWORD),
		("TimeDateStamp",			DWORD),
		("MajorVersion",			WORD),
		("MinorVersion",			WORD),
		("Name",					DWORD),
		("Base",					DWORD),
		("NumberOfFunctions",		DWORD),
		("NumberOfNames",			DWORD),
		("AddressOfFunctions",		DWORD),
		("AddressOfNames",			DWORD),
		("AddressOfNameOrdinals",	DWORD),
	]

	def display(self):
		print "NumberOfFunctions: 0x%08x" %self.NumberOfFunctions
		print "NumberOfNames: 0x%08x" %self.NumberOfNames
		print "AddressOfFunctions: 0x%08x" %self.AddressOfFunctions
		print "AddressOfNames: 0x%08x" %self.AddressOfNames
		print "AddressOfNameOrdinals: 0x%08x" %self.AddressOfNameOrdinals


class PE:
	def __init__(self, filename):
		with open(filename, "rb") as f:
			self.idh, self.inh, self.ishs, self.iids, self.ied = None, None, None, None, None
			self.content = f.read()
			self.idh = IMAGE_DOS_HEADER.from_buffer_copy(self.content)
			assert IMAGE_DOS_SIGNATURE == self.idh.e_magic
			sign = DWORD.from_buffer_copy(self.content[self.idh.e_lfanew:])
			assert IMAGE_NT_SIGNATURE == sign.value
			ifh = IMAGE_FILE_HEADER.from_buffer_copy(self.content[self.idh.e_lfanew + 4:])
			magic = WORD.from_buffer_copy(self.content[self.idh.e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER:]).value
			if IMAGE_NT_OPTIONAL_HDR64_MAGIC == magic:
				ioh = IMAGE_OPTIONAL_HEADER64.from_buffer_copy(self.content[self.idh.e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER:])
				self.inh = IMAGE_NT_HEADERS64(sign, ifh, ioh)
			elif IMAGE_NT_OPTIONAL_HDR32_MAGIC == magic:
				ioh = IMAGE_OPTIONAL_HEADER32.from_buffer_copy(self.content[self.idh.e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER:])
				self.inh = IMAGE_NT_HEADERS32(sign, ifh, ioh)
			IMAGE_SECTION_HEADERS = IMAGE_SECTION_HEADER * self.inh.FileHeader.NumberOfSections
			self.ishs = IMAGE_SECTION_HEADERS.from_buffer_copy(self.content[self.idh.e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + ifh.SizeOfOptionalHeader:])
			IMAGE_IMPORT_DESCRIPTORS = IMAGE_IMPORT_DESCRIPTOR * (self.inh.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1)
			self.iids = IMAGE_IMPORT_DESCRIPTORS.from_buffer_copy(self.content[self.RVAtoRAW(self.inh.OptionalHeader.DataDirectory[1].VirtualAddress):])
			if self.inh.OptionalHeader.DataDirectory[0].Size:
				self.ied = IMAGE_EXPORT_DIRECTORY.from_buffer_copy(self.content[self.RVAtoRAW(self.inh.OptionalHeader.DataDirectory[0].VirtualAddress):])

	def display(self):
		if self.idh:
			self.idh.display()
		
		if self.inh:
			self.inh.display()
		
		if self.ishs:
			for ish in self.ishs:
				ish.display()
		
		if self.iids:
			for iid in self.iids:
				iid.display()
			for iid in self.iids:
				print c_char_p(self.content[self.RVAtoRAW(iid.Name):]).value
				i = 0
				while True:
					INT_i = DWORD.from_buffer_copy(self.content[self.RVAtoRAW(iid.OriginalFirstThunk) + i * 4:]).value
					if INT_i:
						print "0x%04x %s" %(WORD.from_buffer_copy(self.content[self.RVAtoRAW(INT_i):]).value, c_char_p(self.content[self.RVAtoRAW(INT_i) + 2:]).value)
					else:
						break
					i += 1

		if self.ied:
			self.ied.display()
			print c_char_p(self.content[self.RVAtoRAW(self.ied.Name):]).value
			for i in range(self.ied.NumberOfNames):
				ORD_i = WORD.from_buffer_copy(self.content[self.RVAtoRAW(self.ied.AddressOfNameOrdinals) + i * 2:]).value
				ENT_i = DWORD.from_buffer_copy(self.content[self.RVAtoRAW(self.ied.AddressOfNames) + i * 4:]).value
				print "0x%04x %s" %(ORD_i, c_char_p(self.content[self.RVAtoRAW(ENT_i):]).value)

	def RVAtoRAW(self, rva):
		for i in range(1, len(self.ishs)):
			if self.ishs[i-1].VirtualAddress <= rva < self.ishs[i].VirtualAddress:
				if rva - self.ishs[i-1].VirtualAddress <= self.ishs[i-1].SizeOfRawData:
					return DWORD(rva - self.ishs[i-1].VirtualAddress + self.ishs[i-1].PointerToRawData).value
				else:
					break
		if rva >= self.ishs[i].VirtualAddress:
			if rva - self.ishs[i].VirtualAddress <= self.ishs[i].SizeOfRawData:
				return DWORD(rva - self.ishs[i].VirtualAddress + self.ishs[i].PointerToRawData).value
		return None
