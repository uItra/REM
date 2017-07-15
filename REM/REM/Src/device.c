#include "REM.h"
#include "secret\REM_structs.h"
#include <string.h>
#include <malloc.h>

uint8_t
REM_UCreateService(const char* ServiceName, const char* DriverPath);

uint8_t
REM_UDeleteService(const char* ServiceName);

uint8_t
REM_ULoadDriver(const char* ServiceName);

uint8_t
REM_UUnLoadDriver(const char* ServiceName);

HANDLE
REM_UOpenDeviceHandle(const char* DeviceName);

uint8_t
REM_UCloseDeviceHandle(HANDLE hDevice);

PREM_DEVICE
REM_LoadDevice(const char* ServiceName, const char* DeviceName, const char* DevicePath)
{
	PREM_DEVICE device = NULL;
	{
		if (REM_UCreateService(ServiceName, DevicePath))
		{
			if (REM_ULoadDriver(ServiceName))
			{
				HANDLE hDevice = REM_UOpenDeviceHandle(DeviceName);
				if (hDevice > NULL)
				{
					REM_DEVICE info;
					info.FileName = DevicePath;
					info.ServiceName = ServiceName;
					info.hDevice = hDevice;
					device = malloc(sizeof(info));
					memcpy(device, &info, sizeof(info));
				}
				else
				{
					REM_UUnLoadDriver(ServiceName);
				}
			}
			REM_UDeleteService(ServiceName);
		}
	}
	return device;
}

uint8_t
REM_UnloadDevice(PREM_DEVICE device)
{
	uint8_t status = 0;
	{
		if (REM_UCloseDeviceHandle(device->hDevice))
		{
			if (REM_UCreateService(device->ServiceName, device->FileName))
			{
				if (REM_UUnLoadDriver(device->ServiceName))
				{
					status = 1;
				}
				REM_UDeleteService(device->ServiceName);
			}
		}
		free(device);
		device = NULL;
	}
	return status;
}

HANDLE
REM_GetDeviceHandle(PREM_DEVICE Device)
{
	return Device->hDevice;
}

const char*
REM_GetDeviceFileName(PREM_DEVICE Device)
{
	return Device->FileName;
}

const char*
REM_GetServiceName(PREM_DEVICE Device)
{
	return Device->ServiceName;
}