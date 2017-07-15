#include "REM.h"
#include "secret\NT_structs.h"

PVOID * test = NULL;

static
NTSTATUS(__stdcall* _NtUnloadDriver)(PUNICODE_STRING);

static
NTSTATUS(__stdcall* _NtLoadDriver)(PUNICODE_STRING);

static
NTSTATUS(__stdcall* _NtOpenFile)(HANDLE, uint32_t, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, uint32_t, uint32_t);

static
NTSTATUS(__stdcall* _NtClose)(HANDLE);

static
NTSTATUS(__stdcall* _NtQuerySystemInformation)(uint32_t, PVOID, uint32_t, uint32_t*);

static
NTSTATUS(__stdcall* _NtSetSystemInformation)(uint32_t, PVOID, uint32_t);

static
NTSTATUS(__stdcall* _RtlGetVersion)(PRTL_OSVERSIONINFOW);

static
NTSTATUS(__stdcall* _RtlAdjustPrivilege)(uint32_t, uint8_t, uint8_t, uint8_t*);

static
void(__stdcall* _RtlInitUnicodeString)(PUNICODE_STRING, const wchar_t*);

static
int32_t(__stdcall* _DeviceIoControl)(HANDLE, uint32_t, PVOID, uint32_t, PVOID, uint32_t, uint32_t*, PVOID);

static
HANDLE(__stdcall* _LoadLibraryA)(const char*);

static
int(__stdcall* _FreeLibrary)(HANDLE);

static
uint8_t
REM_UApiInit();

NTSTATUS NtUnloadDriver(PUNICODE_STRING DriverServiceName)
{
	NTSTATUS status = STATUS_NOT_CABABLE;
	if (REM_UApiInit())
	{
		status = _NtUnloadDriver(DriverServiceName);
	}
	return status;
}

NTSTATUS NtLoadDriver(PUNICODE_STRING DriverServiceName)
{
	NTSTATUS status = STATUS_NOT_CABABLE;
	if (REM_UApiInit())
	{
		status = _NtLoadDriver(DriverServiceName);
	}
	return status;
}

NTSTATUS NtOpenFile(
	HANDLE                FileHandle,
	uint32_t              DesiredAccess,
	POBJECT_ATTRIBUTES    ObjectAttributes,
	PIO_STATUS_BLOCK      IoStatusBlock,
	uint32_t              ShareAccess,
	uint32_t              OpenOptions
)
{
	NTSTATUS status = STATUS_NOT_CABABLE;
	if (REM_UApiInit())
	{
		status = _NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	}
	return status;
}

NTSTATUS NtClose(HANDLE ObjHandle)
{
	NTSTATUS status = STATUS_NOT_CABABLE;
	if (REM_UApiInit())
	{
		status = _NtClose(ObjHandle);
	}
	return status;
}

NTSTATUS NtQuerySystemInformation(uint32_t Info, PVOID SystemInfo, uint32_t Lenght, uint32_t *ReturnLength)
{
	NTSTATUS status = STATUS_NOT_CABABLE;
	if (REM_UApiInit())
	{
		status = _NtQuerySystemInformation(Info, SystemInfo, Lenght, ReturnLength);
	}
	return status;
}

NTSTATUS NtSetSystemInformation(uint32_t Info, PVOID SystemInfo, uint32_t Lenght)
{
	NTSTATUS status = STATUS_NOT_CABABLE;
	if (REM_UApiInit())
	{
		status = _NtSetSystemInformation(Info, SystemInfo, Lenght);
	}
	return status;
}

NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation)
{
	NTSTATUS status = STATUS_NOT_CABABLE;
	if (REM_UApiInit())
	{
		status = _RtlGetVersion(lpVersionInformation);
	}
	return status;
}

NTSTATUS RtlAdjustPrivilege(uint32_t Privilege, uint8_t Enable, uint8_t CurrentThread, uint8_t* Enabled)
{
	NTSTATUS status = STATUS_NOT_CABABLE;
	if (REM_UApiInit())
	{
		status = _RtlAdjustPrivilege(Privilege, Enable, CurrentThread, Enabled);
	}
	return status;
}

void RtlInitUnicodeString(PUNICODE_STRING DestinationString, const wchar_t* SourceString)
{
	if (REM_UApiInit())
	{
		_RtlInitUnicodeString(DestinationString, SourceString);
	}
}

int32_t DeviceIoControl(
	HANDLE         hDevice,
	uint32_t       dwIoControlCode,
	PVOID          lpInBuffer,
	uint32_t       nInBufferSize,
	PVOID          lpOutBuffer,
	uint32_t       nOutBufferSize,
	uint32_t*      lpBytesReturned,
	PVOID          lpOverlapped
)
{
	int32_t status = -1;
	if (REM_UApiInit())
	{
		status = _DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
	}
	return status;
}

HANDLE REM_LoadLibrary(const char* ModuleName)
{
	HANDLE result = NULL;
	if (REM_UApiInit())
	{
		result = _LoadLibraryA(ModuleName);
	}
	return result;
}

int32_t REM_FreeLibrary(HANDLE hModule)
{
	int32_t status = -1;
	if (REM_UApiInit())
	{
		status = _FreeLibrary(hModule);
	}
	return status;
}

static
uint8_t REM_LoadImports()
{
	uint8_t status = 0;

	REM_PROCESS* current_process = REM_AttachToProcess(CURRENT_PROCESS);

	if (current_process > NULL)
	{
		/* import ntdll.dll */
		{

			const char ntdll_string[] = { 110,116,100,108,108,46,100,108,108,0 };
			REM_MODULE* ntdll = REM_AttachToModule(current_process, ntdll_string);
			if (ntdll > NULL)
			{
				/*NtClose*/
				{
					
					char fn[] = { 78,116,67,108,111,115,101,0 };
					if ((*(void**)&_NtClose = REM_GetProcAddress(ntdll, fn)) ==  NULL)
					{
						goto nt_end;
					}
				}

				/* NtQuerySystemInformation */
				{
					char fn[] = { 78,116,81,117,101,114,121,83,121,115,116,101,109,73,110,102,111,114,109,97,116,105,111,110,0 };
					if ((*(void**)&_NtQuerySystemInformation = REM_GetProcAddress(ntdll, fn)) == NULL)
					{
						goto nt_end;
					}
				}

				/* NtSetSystemInformation */
				{
					char fn[] = { 78,116,83,101,116,83,121,115,116,101,109,73,110,102,111,114,109,97,116,105,111,110,0 };
					if ((*(void**)&_NtSetSystemInformation = REM_GetProcAddress(ntdll, fn)) == NULL)
					{
						goto nt_end;
					}
				}

				/* NtLoadDriver */
				{
					char fn[] = { 78,116,76,111,97,100,68,114,105,118,101,114,0 };
					if ((*(void**)&_NtLoadDriver = REM_GetProcAddress(ntdll, fn)) == NULL)
					{
						goto nt_end;
					}
				}

				/* NtUnloadDriver */
				{
					char fn[] = { 78,116,85,110,108,111,97,100,68,114,105,118,101,114,0 };
					if ((*(void**)&_NtUnloadDriver = REM_GetProcAddress(ntdll, fn)) == NULL)
					{
						goto nt_end;
					}
				}

				/* NtOpenFile */
				{
					char fn[] = { 78,116,79,112,101,110,70,105,108,101,0 };
					if ((*(void**)&_NtOpenFile = REM_GetProcAddress(ntdll, fn)) == NULL)
					{
						goto nt_end;
					}
				}

				/*RtlGetVersion*/
				{
					char fn[] = { 82, 116, 108, 71, 101, 116, 86, 101, 114, 115, 105, 111, 110, 0 };
					if ((*(void**)&_RtlGetVersion = REM_GetProcAddress(ntdll, fn)) == NULL)
					{
						goto nt_end;
					}
				}

				/* RtlInitUnicodeString */
				{
					char fn[] = { 82,116,108,73,110,105,116,85,110,105,99,111,100,101,83,116,114,105,110,103,0 };
					if ((*(void**)&_RtlInitUnicodeString = REM_GetProcAddress(ntdll, fn)) == NULL)
					{
						goto nt_end;
					}
				}

				/* RtlAdjustPrivilege */
				{
					char fn[] = { 82,116,108,65,100,106,117,115,116,80,114,105,118,105,108,101,103,101,0 };
					if ((*(void**)&_RtlAdjustPrivilege = REM_GetProcAddress(ntdll, fn)) == NULL)
					{
						goto nt_end;
					}
				}
				status = 1;
			nt_end:
				REM_DetachModule(ntdll);
			}
		}

		/*kernel32.dll*/
		if (status == 1)
		{
			status = 0;
			char k32_string[] = { 107,101,114,110,101,108,51,50,46,100,108,108,0 };
			REM_MODULE* k32 = REM_AttachToModule(current_process, k32_string);
			if (k32 > NULL)
			{
				/* DeviceIoControl */
				{
					char fn[] = { 68,101,118,105,99,101,73,111,67,111,110,116,114,111,108,0 };
					if ((*(void**)&_DeviceIoControl = REM_GetProcAddress(k32, fn)) == NULL)
					{
						goto k32_end;
					}
				}

				/* LoadLibraryA */
				{
					char fn[] = { 76,111,97,100,76,105,98,114,97,114,121,65,0 };
					if ((*(void**)&_LoadLibraryA = REM_GetProcAddress(k32, fn)) == NULL)
					{
						goto k32_end;
					}
				}

				/* FreeLibrary */
				{
					char fn[] = { 70,114,101,101,76,105,98,114,97,114,121,0 };
					if ((*(void**)&_FreeLibrary = REM_GetProcAddress(k32, fn)) == NULL)
					{
						goto k32_end;
					}
				}
				status = 1;
			k32_end:
				REM_DetachModule(k32);
			}
		}
		REM_DetachProcess(current_process);
	}
	return status;
}

static
uint8_t m_Initialized = 0;

static
uint8_t REM_UApiInit()
{
	if (m_Initialized == 0)
	{
		m_Initialized = REM_LoadImports();
	}
	return m_Initialized;
}