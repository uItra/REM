#pragma once
#include "typedefs.h"

/*
	return values:
    Success: > ( 0 || NULL )
*/


/*
	Attach to current process example:
	PREM_PROCESS Process = REM_AttachToProcess(NULL);
*/

/*
	Attach to basemodule example:
	PREM_MODULE base_module = REM_AttachToModule(Process, NULL);
*/

/*
	Load Device example:
	PREM_DEVICE device = REM_LoadDevice("example", "\\device\\example", "%SystemRoot%\\Drivers\\example.sys);
*/

typedef struct _REM_PROCESS REM_PROCESS, *PREM_PROCESS;

PREM_PROCESS
REM_AttachToProcess(const char* ProcessName);

uint8_t
REM_DetachProcess(PREM_PROCESS Process);

PVOID
REM_GetProcessPEB(PREM_PROCESS Process);

uint8_t
REM_ReadMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght);

uint8_t
REM_WriteMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght);

typedef struct _REM_MODULE REM_MODULE, *PREM_MODULE;

PREM_MODULE
REM_AttachToModule(PREM_PROCESS Process, const char* ModuleName);

void
REM_DetachModule(PREM_MODULE Module);

PVOID
REM_GetBaseAddress(PREM_MODULE Module);

const char*
REM_GetBaseName(PREM_MODULE Module);

const char*
REM_GetBasePath(PREM_MODULE Module);

PVOID
REM_GetProcAddress(PREM_MODULE Module, const char* FunctionName);



typedef struct _REM_DEVICE REM_DEVICE, *PREM_DEVICE;

PREM_DEVICE
REM_LoadDevice(const char* ServiceName, const char* DeviceName, const char* DevicePath);

uint8_t
REM_UnloadDevice(PREM_DEVICE device);

HANDLE
REM_GetDeviceHandle(PREM_DEVICE Device);

const char*
REM_GetDeviceFileName(PREM_DEVICE Device);

const char*
REM_GetServiceName(PREM_DEVICE Device);