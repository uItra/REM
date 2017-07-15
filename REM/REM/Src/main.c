#include "REM.h"
#include <stdio.h>

/*
	big credits to markhc!

	if you want protect this --> copy system process protected token & system privs.
*/

int main()
{
	REM_PROCESS* remote_process = REM_AttachToProcess("csrss.exe");
	if (remote_process > NULL)
	{
		printf("[*]Attached to Remote Process!\n");
		printf("[*]Remote Process PEB:    %p\n\n", REM_GetProcessPEB(remote_process));

		REM_MODULE* remote_module = REM_AttachToModule(remote_process, "kernel32.dll");
		if (remote_module > NULL)
		{
			printf("[*]Attached to Remote Module!\n");
			printf("[*]Remote Module Name:    %s\n", REM_GetBaseName(remote_module));
			printf("[*]Remote ModulePath:     %s\n", REM_GetBasePath(remote_module));
			printf("[*]Remote ModuleAddress:  %p\n\n", REM_GetBaseAddress(remote_module));

			PVOID Function = REM_GetProcAddress(remote_module, "LoadLibraryA");
			if (Function > NULL)
			{
				printf("[*]Remote LoadLibraryA:   %p\n", Function);

				PVOID ExampleRead;
				if (REM_ReadMemory(
					remote_process,
					REM_GetBaseAddress(remote_module),
					&ExampleRead,
					sizeof(ExampleRead)
				))
				{
					printf("[*]Read Virtual Example:  %p\n", ExampleRead);
				}
			}
			REM_DetachModule(remote_module);
		}
		REM_DetachProcess(remote_process);
	}
	else
	{
		return 0;
	}
	getchar();
}