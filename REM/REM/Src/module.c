#pragma once
#include "REM.h"
#include "secret\REM_structs.h"
#include <malloc.h>
#include <string.h>
#include <stdio.h>


PREM_MODULE
REM_UAttachToModule(PREM_PROCESS Process, const char* ModuleName);

PVOID
REM_UGetProcAddress(PREM_MODULE Module, const char* FunctionName);


PREM_MODULE
REM_AttachToModule(PREM_PROCESS Process, const char* ModuleName)
{
	return REM_UAttachToModule(Process, ModuleName);
}

void
REM_DetachModule(PREM_MODULE Module)
{
	free(Module);
}

PVOID
REM_GetBaseAddress(PREM_MODULE Module)
{
	return Module->hModule;
}

const char*
REM_GetBaseName(PREM_MODULE Module)
{
	return Module->Name;
}

const char*
REM_GetBasePath(PREM_MODULE Module)
{
	return Module->Path;
}

PVOID
REM_GetProcAddress(PREM_MODULE Module, const char* FunctionName)
{
	return REM_UGetProcAddress(Module, FunctionName);
}