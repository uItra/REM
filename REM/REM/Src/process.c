#include "REM.h"
#include "secret\REM_structs.h"
#include <malloc.h>
#include <string.h>

PREM_PROCESS
REM_UAttachCurrentProcess();

PREM_PROCESS
REM_UAttachRemoteProcess(const char* ProcessName);


static
uint32_t m_remotecount = 0;

PREM_PROCESS
REM_AttachToProcess(const char* ProcessName)
{
	PREM_PROCESS Process = NULL;
	{
		if (ProcessName == NULL || ProcessName == CURRENT_PROCESS)
		{
			Process = REM_UAttachCurrentProcess();
		}
		else
		{
			Process = REM_UAttachRemoteProcess(ProcessName);
			if (Process > NULL)
			{
				m_remotecount++;
			}
		}
	}
	return Process;
}

uint8_t
REM_DetachProcess(PREM_PROCESS Process)
{
	uint8_t status = 1;
	m_remotecount--;
	if (m_remotecount == 0)
	{
		status = REM_UnloadDevice(Process->Device);
	}
	free(Process);
	return status;
}

PVOID
REM_GetProcessPEB(PREM_PROCESS Process)
{
	return Process->Peb;
}

uint8_t REM_UReadVirtualMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght);
uint8_t REM_UWriteVirtualMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght);

uint8_t REM_ReadMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght)
{
	return REM_UReadVirtualMemory(Process, Address, Buffer, Lenght);
}

uint8_t REM_WriteMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght)
{
	return REM_UWriteVirtualMemory(Process, Address, Buffer, Lenght);
}