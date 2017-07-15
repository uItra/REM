#pragma once
#include "typedefs.h"

typedef struct _UNICODE_STRING {
	uint16_t Length;
	uint16_t MaximumLength;
	wchar_t* Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	uint16_t   e_magic;                     // Magic number
	uint16_t   e_cblp;                      // Bytes on last page of file
	uint16_t   e_cp;                        // Pages in file
	uint16_t   e_crlc;                      // Relocations
	uint16_t   e_cparhdr;                   // Size of header in paragraphs
	uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
	uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
	uint16_t   e_ss;                        // Initial (relative) SS value
	uint16_t   e_sp;                        // Initial SP value
	uint16_t   e_csum;                      // Checksum
	uint16_t   e_ip;                        // Initial IP value
	uint16_t   e_cs;                        // Initial (relative) CS value
	uint16_t   e_lfarlc;                    // File address of relocation table
	uint16_t   e_ovno;                      // Overlay number
	uint16_t   e_res[4];                    // Reserved words
	uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
	uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
	uint16_t   e_res2[10];                  // Reserved words
	long       e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	uint32_t   VirtualAddress;
	uint32_t   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	uint16_t        Magic;
	uint8_t         MajorLinkerVersion;
	uint8_t         MinorLinkerVersion;
	uint32_t        SizeOfCode;
	uint32_t        SizeOfInitializedData;
	uint32_t        SizeOfUninitializedData;
	uint32_t        AddressOfEntryPoint;
	uint32_t        BaseOfCode;
	size_t          ImageBase;
	uint32_t        SectionAlignment;
	uint32_t        FileAlignment;
	uint16_t        MajorOperatingSystemVersion;
	uint16_t        MinorOperatingSystemVersion;
	uint16_t        MajorImageVersion;
	uint16_t        MinorImageVersion;
	uint16_t        MajorSubsystemVersion;
	uint16_t        MinorSubsystemVersion;
	uint32_t        Win32VersionValue;
	uint32_t        SizeOfImage;
	uint32_t        SizeOfHeaders;
	uint32_t        CheckSum;
	uint16_t        Subsystem;
	uint16_t        DllCharacteristics;
	size_t          SizeOfStackReserve;
	size_t          SizeOfStackCommit;
	size_t          SizeOfHeapReserve;
	size_t          SizeOfHeapCommit;
	uint32_t        LoaderFlags;
	uint32_t        NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
	//
	// Standard fields.
	//

	uint16_t    Magic;
	uint8_t    MajorLinkerVersion;
	uint8_t    MinorLinkerVersion;
	uint32_t   SizeOfCode;
	uint32_t   SizeOfInitializedData;
	uint32_t   SizeOfUninitializedData;
	uint32_t   AddressOfEntryPoint;
	uint32_t   BaseOfCode;
	uint32_t   BaseOfData;

	//
	// NT additional fields.
	//

	uint32_t   ImageBase;
	uint32_t   SectionAlignment;
	uint32_t   FileAlignment;
	uint16_t    MajorOperatingSystemVersion;
	uint16_t    MinorOperatingSystemVersion;
	uint16_t    MajorImageVersion;
	uint16_t    MinorImageVersion;
	uint16_t    MajorSubsystemVersion;
	uint16_t    MinorSubsystemVersion;
	uint32_t   Win32VersionValue;
	uint32_t   SizeOfImage;
	uint32_t   SizeOfHeaders;
	uint32_t   CheckSum;
	uint16_t    Subsystem;
	uint16_t    DllCharacteristics;
	uint32_t   SizeOfStackReserve;
	uint32_t   SizeOfStackCommit;
	uint32_t   SizeOfHeapReserve;
	uint32_t   SizeOfHeapCommit;
	uint32_t   LoaderFlags;
	uint32_t   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_FILE_HEADER {
	uint16_t    Machine;
	uint16_t    NumberOfSections;
	uint32_t   TimeDateStamp;
	uint32_t   PointerToSymbolTable;
	uint32_t   NumberOfSymbols;
	uint16_t    SizeOfOptionalHeader;
	uint16_t    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS32 {
	uint32_t Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
	uint32_t Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#ifdef _WIN64
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#else
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;

#endif
typedef struct _IMAGE_EXPORT_DIRECTORY {
	uint32_t   Characteristics;
	uint32_t   TimeDateStamp;
	uint16_t    MajorVersion;
	uint16_t    MinorVersion;
	uint32_t   Name;
	uint32_t   Base;
	uint32_t   NumberOfFunctions;
	uint32_t   NumberOfNames;
	uint32_t   AddressOfFunctions;     // RVA from base of image
	uint32_t   AddressOfNames;         // RVA from base of image
	uint32_t   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;



typedef union _LARGE_INTEGER {
	struct {
		uint32_t LowPart;
		long HighPart;
	}h;
	struct {
		uint32_t LowPart;
		long HighPart;
	} u;
	long long QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;


typedef struct _IMAGE_BASE_RELOCATION {
	uint32_t   VirtualAddress;
	uint32_t   SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_SECTION_HEADER {
	uint8_t    Name[8];
	union {
		uint32_t   PhysicalAddress;
		uint32_t   VirtualSize;
	} Misc;
	uint32_t   VirtualAddress;
	uint32_t   SizeOfRawData;
	uint32_t   PointerToRawData;
	uint32_t   PointerToRelocations;
	uint32_t   PointerToLinenumbers;
	uint16_t    NumberOfRelocations;
	uint16_t    NumberOfLinenumbers;
	uint32_t   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _OBJECT_ATTRIBUTES {
	uint32_t Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	uint32_t Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	}u;
	size_t Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _SYSTEM_PROCESS_INFO
{
	uint32_t                NextEntryOffset;
	uint32_t                NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	uint32_t                BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _OVERLAPPED {
	uint64_t Internal;
	uint64_t InternalHigh;
	union {
		struct {
			uint32_t Offset;
			uint32_t OffsetHigh;
		}u;
		PVOID  Pointer;
	}h;
	HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	PVOID    Section;
	PVOID    MappedBase;
	PVOID    ImageBase;
	uint32_t ImageSize;
	uint32_t Flags;
	uint16_t LoadOrderIndex;
	uint16_t InitOrderIndex;
	uint16_t LoadCount;
	uint16_t OffsetToFileName;
	char     FullPathName[256];
}RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	uint32_t NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _OSVERSIONINFOW {
	uint32_t dwOSVersionInfoSize;
	uint32_t dwMajorVersion;
	uint32_t dwMinorVersion;
	uint32_t dwBuildNumber;
	uint32_t dwPlatformId;
	wchar_t  szCSDVersion[128];
	uint16_t wServicePackMajor;
	uint16_t wServicePackMinor;
	uint16_t wSuiteMask;
	uint8_t  wProductType;
	uint8_t  wReserved;
} RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;

typedef struct _WINVEROFFSETS
{
	uint32_t directorytable;
	uint32_t peb;
	uint32_t peb_x86;
	uint32_t imagename;
	uint32_t processlinks;
	uint32_t objecttable;
}WINVEROFFSETS, *PWINVEROFFSETS;

#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (uint64_t)(&((type *)0)->field)))
#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)

#define GENERIC_READ                     (0x80000000L)
#define GENERIC_WRITE                    (0x40000000L)
#define SYNCHRONIZE                      (0x00100000L)
#define OPEN_EXISTING 3

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000

#ifdef _WIN64
#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG64
#else 
#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG32
#endif 

#define IMAGE_DOS_SIGNATURE                 0x5A4D     
#define IMAGE_NT_SIGNATURE                  0x00004550

#define IMAGE_FILE_MACHINE_I386              0x014c
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)

#define TRUE 1
#define FALSE 0


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

#define CURRENT_PROCESS             (HANDLE)-1
#define STATUS_SUCCESS              0l
#define STATUS_NOT_CABABLE          0xC0000429