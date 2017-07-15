#include "secret\NT_structs.h"
#include <string.h>

/* \\Registry\\Machine\\System\\CurrentControlSet\\Services\\  */
static
wchar_t S_registery_path[] = 
{
	92, 82, 101, 103, 105, 115, 116, 114, 121, 92, 77, 97, 99, 104, 105, 110, 101, 92, 83, 121, 115, 116,
	101, 109, 92, 67, 117, 114, 114, 101, 110, 116, 67, 111, 110, 116, 114, 111, 108, 83, 101, 116, 92, 83,
	101, 114, 118, 105, 99, 101, 115, 92, 0
};

NTSTATUS
NtOpenFile(
	HANDLE                FileHandle,
	uint32_t              DesiredAccess,
	POBJECT_ATTRIBUTES    ObjectAttributes,
	PIO_STATUS_BLOCK      IoStatusBlock,
	uint32_t              ShareAccess,
	uint32_t              OpenOptions
);

NTSTATUS
NtClose(HANDLE ObjHandle);

NTSTATUS
NtLoadDriver(PUNICODE_STRING DriverServiceName);

NTSTATUS
NtUnloadDriver(PUNICODE_STRING DriverServiceName);

void
RtlInitUnicodeString(PUNICODE_STRING DestinationString, const wchar_t* SourceString);

uint8_t REM_ULoadDriver(const char* ServiceName)
{
	uint8_t load_status = 0;
	{
		wchar_t ServicePath[260] = { 0 };
		{		
			for (size_t i = 0; i < wcslen(S_registery_path); i++)
			{
				ServicePath[i] = S_registery_path[i];
			}
			size_t current_lenght = wcslen(ServicePath);
			for (size_t i = 0; i < strlen(ServiceName); i++)
			{
				ServicePath[i + current_lenght] = (wchar_t)ServiceName[i];
			}		
		}
		UNICODE_STRING uname;
		RtlInitUnicodeString(&uname, ServicePath);

		switch (NtLoadDriver(&uname))
		{
			case STATUS_SUCCESS:
			{
				load_status = 1;
				break;
			}
			/*Device Already Running*/
			case 0xC000010E:
			{
				load_status = 1;
				break;
			}
			/*Device Already Running*/
			case 0xC0000035:
			{
				load_status = 1;
				break;
			}
			default:
			{
				load_status = 0;
				break;
			}
		}
	}
	return load_status;
}

uint8_t REM_UUnLoadDriver(const char* ServiceName)
{
	uint8_t status = 0;
	{
		wchar_t ServicePath[260] = { 0 };
		{
			for (size_t i = 0; i < wcslen(S_registery_path); i++)
			{
				ServicePath[i] = S_registery_path[i];
			}
			size_t current_lenght = wcslen(ServicePath);
			for (size_t i = 0; i < strlen(ServiceName); i++)
			{
				ServicePath[i + current_lenght] = (wchar_t)ServiceName[i];
			}
		}
		UNICODE_STRING uname;
		RtlInitUnicodeString(&uname, ServicePath);

		if (NT_SUCCESS(NtUnloadDriver(&uname)))
		{
			status = 1;
		}
	}
	return status;
}

HANDLE REM_UOpenDeviceHandle(const char* DeviceName)
{
	HANDLE hDevice = NULL;
	{
		UNICODE_STRING uname;
		{
			wchar_t wchar_devicename[260] = { 0 };
			for (size_t i = 0; i < strlen(DeviceName); i++)
			{
				wchar_devicename[i] = (wchar_t)DeviceName[i];
			}
			RtlInitUnicodeString(&uname, wchar_devicename);
		}
		if (uname.Length > 0 || uname.Buffer > NULL)
		{
			OBJECT_ATTRIBUTES obj;
			InitializeObjectAttributes(&obj, &uname, 0, NULL, NULL);

			IO_STATUS_BLOCK io_status;
			if (!NT_SUCCESS(NtOpenFile(&hDevice, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &obj, &io_status, 0, OPEN_EXISTING)))
			{
				hDevice = NULL;
			}
		}
	}
	return hDevice;
}

uint8_t REM_UCloseDeviceHandle(HANDLE hDevice)
{
	return NT_SUCCESS(NtClose(hDevice)) ? 1 : 0;
}