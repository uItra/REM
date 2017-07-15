#include "REM.h"
#include "secret\REM_structs.h"
#include "secret\NT_structs.h"

#include <intrin.h>
#include <string.h>

PREM_DEVICE
REM_DAttachREMDevice();

uint8_t
REM_UGetDebugPrivs();

uint8_t
REM_DReadVirtualMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght);

uint8_t
REM_DWriteVirtualMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght);

uint8_t
REM_DReadSystemMemory(PREM_DEVICE Device, PVOID Address, PVOID Buffer, size_t Lenght);

uint8_t
REM_DWriteSystemMemory(PREM_DEVICE Device, PVOID Address, PVOID Buffer, size_t Lenght);

HANDLE
REM_LoadLibrary(const char* ModuleName);

int32_t
REM_FreeLibrary(HANDLE hModule);

PVOID
REM_UGetSystemBaseAddress();

static
PWINVEROFFSETS m_offsets = NULL;

uint8_t REM_UReadVirtualMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght)
{
	uint8_t status = 0;
	{
		if (Process->hProcess == CURRENT_PROCESS)
		{
			__try
			{
				if (memcpy(Buffer, Address, Lenght) > NULL)
				{
					status = 1;
				}
			}
			__except (1)
			{
				status = 0;
			}
		}
		else
		{
			status = REM_DReadVirtualMemory(Process, Address, Buffer, Lenght);
		}
	}
	return status;
}

uint8_t REM_UWriteVirtualMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght)
{
	uint8_t status = 0;
	{
		if (Process->hProcess == CURRENT_PROCESS)
		{
			__try
			{
				if (memcpy(Address, Buffer, Lenght) > NULL)
				{
					status = 1;
				}
			}
			__except (1)
			{
				status = 0;
			}
		}
		else
		{
			status = REM_DWriteVirtualMemory(Process, Address, Buffer, Lenght);
		}
	}
	return status;
}

static
PVOID REM_UGetPsInitialSystemProcess()
{
	static
	PVOID result = NULL;

	if (result == NULL)
	{	
		PREM_PROCESS current_process = REM_AttachToProcess(CURRENT_PROCESS);
		if (current_process > NULL)
		{
			PVOID KernelBase = REM_UGetSystemBaseAddress();
			if (KernelBase > NULL)
			{
				const char ntos_string[] =
				{
					110,116,111,115,107,114,
					110,108,46,101,120,101,0
				};

				HANDLE ntoskrnl = REM_LoadLibrary(ntos_string);
				if (ntoskrnl > NULL)
				{
					const char ps_init_string[] =
					{
						80,115,73,110,105,116,105,97,108,83,121,
						115,116,101,109,80,114,111,99,101,115,115,0
					};
					REM_MODULE info;
					info.Process = current_process;;
					info.hModule = ntoskrnl;
					info.Name    = NULL;
					info.Path    = NULL;

					result = REM_GetProcAddress(&info, ps_init_string);
					if (result > 0)
					{
						result = (PVOID)((size_t)result - (size_t)ntoskrnl + (size_t)KernelBase);
					}
					REM_FreeLibrary(ntoskrnl);
				}
			}
			REM_DetachProcess(current_process);
		}
	}
	return result;
}

int32_t REM_UIsWow64(PREM_PROCESS Process)
{
	int32_t result = -1;

	if (Process->hProcess == CURRENT_PROCESS)
	{
#ifdef _WIN64
		result = 1;
#else
		result = 0;
#endif
	}
	else
	{	
		size_t peb;
		if (!REM_DReadSystemMemory(Process->Device, (PVOID)((size_t)Process->Entry + m_offsets->peb_x86), &peb, sizeof(peb)))
		{
			peb = 0;
		}
		if (peb == 0)
		{
			result = 1;
		}
		else
		{
			result = 0;
		}
	}
	return result;
}

PREM_PROCESS REM_UAttachCurrentProcess()
{
	PREM_PROCESS Process = NULL;
	{
		REM_PROCESS info;
		info.Device = NULL;
		info.hProcess = CURRENT_PROCESS;
		info.Entry = NULL;
#if defined(_M_X64)
		info.Peb = (PVOID)__readgsqword(0x60);
#else
		info.Peb = (PVOID)__readfsdword(0x30);
#endif
		if (info.Peb > NULL)
		{
			Process = malloc(sizeof(info));
			memcpy(Process, &info, sizeof(info));
		}
	}
	return Process;
}

PWINVEROFFSETS
REM_UGetOffsets();

PREM_PROCESS REM_UAttachRemoteProcess(const char* ProcessName)
{

	PREM_PROCESS Process = NULL;	
	if (REM_UGetDebugPrivs())
	{
		PREM_DEVICE Device = REM_DAttachREMDevice();
		if (Device > NULL)
		{
			static
			uint8_t AttachedBefore = 0;

			if (m_offsets == NULL)
			{
				m_offsets = REM_UGetOffsets();
			}
			if (m_offsets > NULL)
			{
				PVOID PsInitial = REM_UGetPsInitialSystemProcess();
				if (PsInitial > NULL)
				{
					size_t item = 0;

					if (!REM_DReadSystemMemory(Device, (PVOID)PsInitial, &item, sizeof(item)))
					{
						goto end;
					}
					item += m_offsets->processlinks;
					size_t last_item = 0;
					if (!REM_DReadSystemMemory(Device, (PVOID)(item + sizeof(PVOID)), &last_item, sizeof(last_item)))
					{
						goto end;
					}

					while (item != last_item)
					{
						PVOID Entry = (PVOID)(item - m_offsets->processlinks);

						char ImageFileName[15];
						if (!REM_DReadSystemMemory(Device, (PVOID)((size_t)Entry + m_offsets->imagename), &ImageFileName, sizeof(ImageFileName)))
						{
							break;
						}

						if (!_strcmpi(ImageFileName, ProcessName))
						{
							REM_PROCESS info;
							info.Device = Device;
							info.Entry  = Entry;
							/* Get PEB */
							{
								size_t Peb;
								if (!REM_DReadSystemMemory(Device, (PVOID)((size_t)Entry + m_offsets->peb_x86), &Peb, sizeof(Peb)))
								{
									break;
								}
								if (Peb == 0)
								{
									if (!REM_DReadSystemMemory(Device, (PVOID)((size_t)Entry + m_offsets->peb), &Peb, sizeof(Peb)))
									{
										break;
									}
								}
								info.Peb = (PVOID)Peb;
							}

							/* Get DirectoryTable */
							{
								if (!REM_DReadSystemMemory(Device, (PVOID)((size_t)Entry + m_offsets->directorytable), &info.hProcess,sizeof(PVOID)))
								{
									break;
								}
							}
							Process = malloc(sizeof(info));
							memcpy(Process, &info, sizeof(info));
							AttachedBefore = 1;
							break;
						}
						if (!REM_DReadSystemMemory(Device, (PVOID)item, &item, sizeof(item)))
						{
							break;
						}
					}
				}
				end:
				if (Process == NULL && AttachedBefore == 0)
				{
					free(m_offsets);
					m_offsets = NULL;
					REM_UnloadDevice(Device);
				}
			}
		}
	}
	return Process;
}