#include "REM.h"
#include "secret\REM_structs.h"
#include "secret\NT_structs.h"

#include <string.h>
#include <malloc.h>

uint8_t
REM_UReadVirtualMemory(PREM_PROCESS Process, PVOID Adr, PVOID Buffer, size_t Lenght);

int32_t
REM_UIsWow64(PREM_PROCESS Process);

NTSTATUS
NtQuerySystemInformation(uint32_t Info, PVOID SystemInfo, uint32_t Lenght, uint32_t *ReturnLength);

char* REM_UCopyChar(const char* src);
PREM_MODULE REM_UAttachToModuleS(PREM_PROCESS Process, const char *ModuleName)
{
	PREM_MODULE Module = NULL;
	{
		//List kernel modules this way because ntoskrnl.exe PEB is 0x0

		uint32_t Lenght = 0;
		NtQuerySystemInformation(11, 0, 0, &Lenght);
		if (Lenght > 0)
		{
			PRTL_PROCESS_MODULES module_info = malloc(Lenght);
			if (NT_SUCCESS(NtQuerySystemInformation(11, module_info, Lenght, NULL)))
			{
				for (uint32_t i = 0; i < module_info->NumberOfModules; i++)
				{
					char* Name = module_info->Modules[i].FullPathName + module_info->Modules[i].OffsetToFileName;
					char* Path = module_info->Modules[i].FullPathName;
					PVOID BaseAddress = module_info->Modules[i].ImageBase;

					if ((ModuleName == NULL) || (!_strcmpi(Name, ModuleName)))
					{
						REM_MODULE     info;
						info.Process = Process;
						info.hModule = BaseAddress;
						info.Name    = REM_UCopyChar(Name);
						info.Path    = REM_UCopyChar(Path);
						Module = malloc(sizeof(info));
						memcpy(Module, &info, sizeof(info));
						break;
					}
				}
			}
			free(module_info);
		}
	}
	return Module;
}

/*
	we could easily use pointers instead of memcpy in current process,
	but it doesnt really matter because we dont need performance in this area and
	its making things more complicated.
*/

char* REM_UConvertToChar(const wchar_t* src);
PREM_MODULE REM_UAttachToModuleL(PREM_PROCESS Process, const wchar_t *ModuleName)
{
	PREM_MODULE Module = NULL;
	{
		uint8_t	read_size;
		uint8_t	ldr_data_offset;
		uint8_t	module_list_offset;
		uint8_t	dllname_offset;
		uint8_t fulldllname_offset;
		uint8_t	dll_base_offset;
		uint8_t	pointer_offset;

		//Parse LDR_DATA_TABLE_ENTRY structure so its combatible with x86 & x64 Windows
		if(REM_UIsWow64(Process))
		{
			read_size                = 8;
			ldr_data_offset          = 0x18;
			module_list_offset       = 0x20;
			dllname_offset           = 0x60;
			fulldllname_offset       = 0x50;
			dll_base_offset          = 0x30;
			pointer_offset           = 0x10;
		}
		else
		{
			read_size                = 4;
			ldr_data_offset          = 0xC;
			module_list_offset       = 0x14;
			dllname_offset           = 0x30;
			fulldllname_offset       = 0x28;
			dll_base_offset          = 0x18;
			pointer_offset           = 0x8;
		}

		uint8_t* ldr_data = NULL;
		if (!REM_UReadVirtualMemory(Process, (PVOID)((size_t)Process->Peb + ldr_data_offset), &ldr_data, read_size))
		{
			goto end;
		}

		uint8_t* item = NULL;
		if (!REM_UReadVirtualMemory(Process, ldr_data + module_list_offset, &item, read_size))
		{
			goto end;
		}

		uint8_t* last_item = NULL;
		if (!REM_UReadVirtualMemory(Process, (PVOID)(item + sizeof(PVOID)), &last_item, sizeof(last_item)))
		{
			goto end;
		}

		while (last_item != item)
		{
			uint8_t* entry = item - pointer_offset;


			uint8_t* BaseAddress = NULL;
			if (!REM_UReadVirtualMemory(Process, entry + dll_base_offset, &BaseAddress, read_size))
			{
				break;
			}

			wchar_t* NamePtr = NULL;
			if (!REM_UReadVirtualMemory(Process, entry + dllname_offset, &NamePtr, sizeof(NamePtr)))
			{
				break;
			}

			wchar_t* PathPtr = NULL;
			if (!REM_UReadVirtualMemory(Process, entry + fulldllname_offset, &PathPtr, sizeof(PathPtr)))
			{
				break;
			}

			wchar_t  Name[260];
			if (!REM_UReadVirtualMemory(Process, NamePtr, &Name, sizeof(Name)))
			{
				break;
			}

			wchar_t  Path[260];
			if (!REM_UReadVirtualMemory(Process, PathPtr, &Path, sizeof(Path)))
			{
				break;
			}
			
			if (ModuleName == NULL || (!_wcsicmp(Name, ModuleName)))
			{
				REM_MODULE info;
				info.Process = Process;
				info.hModule = BaseAddress;
				info.Name    = REM_UConvertToChar(Name);
				info.Path    = REM_UConvertToChar(Path);

				// Allocate memory buffer for module so we can free it as once.
				Module = malloc(sizeof(info));
				memcpy(Module, &info, sizeof(info));
				break;
			}
			if (!REM_UReadVirtualMemory(Process, item, &item, read_size))
			{
				break;
			}
		}
	}
end:
	return Module;
}

wchar_t* REM_UConvertToWChar(const char* src);
PREM_MODULE REM_UAttachToModule(PREM_PROCESS Process, const char* ModuleName)
{
	PREM_MODULE Module = NULL;
	{
		if (Process->Peb == NULL)
		{
			// ntoskrnl.exe
			Module = REM_UAttachToModuleS(Process, ModuleName);
		}
		else
		{
			const wchar_t* wchar_modulename = NULL;
			if (ModuleName != NULL && ModuleName != CURRENT_PROCESS)
			{
				wchar_modulename = REM_UConvertToWChar(ModuleName);
			}
			Module = REM_UAttachToModuleL(Process, wchar_modulename);	
		}
	}
	return Module;
}

PVOID REM_UGetProcAddress(PREM_MODULE Module, const char* FunctionName)
{
	HANDLE procAddress = NULL;
	{
		IMAGE_DOS_HEADER dos_header;
		if (!REM_UReadVirtualMemory(Module->Process, Module->hModule, &dos_header, sizeof(IMAGE_DOS_HEADER)))
		{
			goto end;
		}
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
		{
			goto end;
		}
		uint32_t virtual_address = 0;
		{
			IMAGE_NT_HEADERS64 nt_header;
			if (!REM_UReadVirtualMemory(Module->Process, (PVOID)((size_t)Module->hModule + dos_header.e_lfanew), &nt_header, sizeof(IMAGE_NT_HEADERS64)))
			{
				goto end;
			}
			if (nt_header.Signature != IMAGE_NT_SIGNATURE)
			{
				goto end;
			}


			switch (nt_header.FileHeader.Machine)
			{
				case IMAGE_FILE_MACHINE_I386:
				{
					IMAGE_NT_HEADERS32 nt_header_x86;
					if (!REM_UReadVirtualMemory(Module->Process, (PVOID)((size_t)Module->hModule + dos_header.e_lfanew), &nt_header_x86, sizeof(IMAGE_NT_HEADERS32)))
					{
						goto end;
					}
					if (nt_header.Signature != IMAGE_NT_SIGNATURE)
					{
						goto end;
					}
					virtual_address = nt_header_x86.OptionalHeader.DataDirectory[0].VirtualAddress;
					break;
				}
				case IMAGE_FILE_MACHINE_AMD64:
				{
					virtual_address = nt_header.OptionalHeader.DataDirectory[0].VirtualAddress;
					break;
				}
				default:
				{
					virtual_address = 0;
					break;
				}
			}
		}

		if (virtual_address == 0)
		{
			goto end;
		}

		IMAGE_EXPORT_DIRECTORY export_dir;
		if (!REM_UReadVirtualMemory(Module->Process, (PVOID)((size_t)Module->hModule + virtual_address), &export_dir, sizeof(IMAGE_EXPORT_DIRECTORY)))
		{
			goto end;
		}

		if (export_dir.NumberOfFunctions > 4096 || export_dir.NumberOfNames > 4096)
		{
			goto end;
		}

		for (uint32_t i = 0; i < export_dir.NumberOfFunctions; i++)
		{
			uint16_t name_ords = 0;
			if (!REM_UReadVirtualMemory(Module->Process, (PVOID)((size_t)Module->hModule + export_dir.AddressOfNameOrdinals + (i * 2)), &name_ords, sizeof(name_ords)))
			{
				break;
			}

			uint32_t address = 0;
			if (!REM_UReadVirtualMemory(Module->Process, (PVOID)((size_t)Module->hModule + export_dir.AddressOfFunctions + (name_ords * 4)), &address, sizeof(address)))
			{
				break;
			}

			uint32_t name_address = 0;
			if (!REM_UReadVirtualMemory(Module->Process, (PVOID)((size_t)Module->hModule + export_dir.AddressOfNames + (i * 4)), &name_address, sizeof(name_address)))
			{
				break;
			}

			char Name[260];
			if (!REM_UReadVirtualMemory(Module->Process, (PVOID)((size_t)Module->hModule + name_address), &Name, sizeof(Name)))
			{
				break;
			}

			if (!_strcmpi(Name, FunctionName))
			{
				procAddress = (HANDLE)((size_t)Module->hModule + address);
				break;
			}
		}
	}
end:
	return procAddress;
}

PVOID REM_UGetSystemBaseAddress()
{
	PVOID BaseAddress = NULL;
	{
		PREM_MODULE SYSTEM = REM_UAttachToModuleS(NULL, NULL);
		if (SYSTEM > NULL)
		{
			BaseAddress = REM_GetBaseAddress(SYSTEM);
			REM_DetachModule(SYSTEM);
		}
	}
	return BaseAddress;
}