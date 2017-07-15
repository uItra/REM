#include "typedefs.h"
#include <stdlib.h>
#include <string.h>

void
REM_UCombineString(wchar_t* adr, const wchar_t* src);

void
REM_UCombineStringA(char* adr, const char* src);

static
const char S_ConsoleClear[] = { 'c', 'l', 's', 0 };

//lets do dirty work through cmd so its look more legit imo
uint8_t REM_UCreateService(const char* ServiceName, const char* DriverPath)
{
	uint8_t status = 0;
	if (ServiceName > NULL && DriverPath > NULL)
	{
		if (strlen(ServiceName) > 2 && strlen(DriverPath) > 4)
		{
			/* add service & Path */
			char REG_ADD_TYPE[260] = { 0 };
			char REG_ADD_PATH[260] = { 0 };
			{
				/*REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\*/
				const char REG_ADD_STR[] =
				{
					82, 69, 71, 32, 65, 68, 68, 32, 72, 75, 76, 77, 92, 83, 89, 83, 84, 69, 77, 92, 67, 117, 114, 114, 101,
					110, 116, 67, 111, 110, 116, 114, 111, 108, 83, 101, 116, 92, 83, 101, 114, 118, 105, 99, 101, 115, 92, 0
				};

				REM_UCombineStringA(REG_ADD_TYPE, REG_ADD_STR);
				REM_UCombineStringA(REG_ADD_PATH, REG_ADD_STR);



				REM_UCombineStringA(REG_ADD_TYPE, ServiceName);
				REM_UCombineStringA(REG_ADD_PATH, ServiceName);

				/* /v type /t REG_DWORD /d 1 */
				const char REG_TYPE_STR[] =
				{
					32, 47, 118, 32, 116, 121, 112, 101, 32, 47, 116, 32, 82, 69,
					71, 95, 68, 87, 79, 82, 68, 32, 47, 100, 32, 49, 0
				};

				REM_UCombineStringA(REG_ADD_TYPE, REG_TYPE_STR);

				size_t name_len = strlen(REG_ADD_TYPE);
				REG_ADD_TYPE[name_len] = ' ';
				REG_ADD_TYPE[name_len + 1] = '/';
				REG_ADD_TYPE[name_len + 2] = 'f';

				/*  /v ImagePath /t REG_EXPAND_SZ /d \\??\\ */
				const char REG_ADD_PATH_STR[] =
				{
					32, 47, 118, 32, 73, 109, 97, 103, 101, 80, 97, 116, 104, 32, 47, 116, 32, 82, 69,
					71, 95, 69, 88, 80, 65, 78, 68, 95, 83, 90, 32, 47, 100, 32, 92, 63, 63, 92, 0
				};

				REM_UCombineStringA(REG_ADD_PATH, REG_ADD_PATH_STR);
				REM_UCombineStringA(REG_ADD_PATH, DriverPath);

				name_len = strlen(REG_ADD_PATH);
				REG_ADD_PATH[name_len] = ' ';
				REG_ADD_PATH[name_len + 1] = '/';
				REG_ADD_PATH[name_len + 2] = 'f';
			}
			system(REG_ADD_TYPE);
			system(REG_ADD_PATH);
			system(S_ConsoleClear);
			status = 1;
		}
	}
	return status;
}

uint8_t REM_UDeleteService(const char* ServiceName)
{
	uint8_t status = 0;
	if (ServiceName > NULL)
	{
		if (strlen(ServiceName) > 2)
		{
			char REG_DELETE[260] = { 0 };
			{
				/* REG DELETE HKLM\\SYSTEM\\CurrentControlSet\\Services\\  */
				const char REG_DELETE_STR[] =
				{
					82, 69, 71, 32, 68, 69, 76, 69, 84, 69, 32, 72, 75, 76, 77, 92, 83, 89, 83, 84, 69, 77, 92, 67, 117, 114,
					114, 101, 110, 116, 67, 111, 110, 116, 114, 111, 108, 83, 101, 116, 92, 83, 101, 114, 118, 105, 99, 101, 115, 92, 0,
				};
				REM_UCombineStringA(REG_DELETE, REG_DELETE_STR);
				REM_UCombineStringA(REG_DELETE, ServiceName);

				size_t del_len = strlen(REG_DELETE);
				REG_DELETE[del_len] = ' ';
				REG_DELETE[del_len + 1] = '/';
				REG_DELETE[del_len + 2] = 'f';
			}
			system(REG_DELETE);
			system(S_ConsoleClear);
			status = 1;
		}
	}
	return status;
}