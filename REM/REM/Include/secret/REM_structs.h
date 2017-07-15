#pragma once
#include "..\typedefs.h"

typedef struct _REM_DEVICE
{
	HANDLE         hDevice;
	const char*    FileName;
	const char*    ServiceName;
}REM_DEVICE, *PREM_DEVICE;

typedef struct _REM_PROCESS
{
	PREM_DEVICE    Device;
	HANDLE         hProcess; /* aka dir table */
	PVOID          Entry;
	PVOID          Peb;
}REM_PROCESS, *PREM_PROCESS;

typedef struct _REM_MODULE
{
	PREM_PROCESS   Process;
	HANDLE         hModule;
	char*          Name;
	char*          Path;
}REM_MODULE, *PREM_MODULE;