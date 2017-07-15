#include "typedefs.h"

#include <string.h>
#include <stdio.h>

#include <stdlib.h>
#include <time.h>

void REM_UCombineString(wchar_t* adr, const wchar_t* src)
{
	size_t adr_len = wcslen(adr);
	for (size_t i = 0; i < wcslen(src); i++)
	{
		adr[i + adr_len] = src[i];
	}
}

void REM_UCombineStringA(char* adr, const char* src)
{
	size_t adr_len = strlen(adr);
	for (size_t i = 0; i < strlen(src); i++)
	{
		adr[i + adr_len] = src[i];
	}
}

char* REM_UCopyChar(const char* src)
{
	char* string = NULL;	
	if (src > NULL)
	{
		size_t src_lenght = (strlen(src) * sizeof(char)) + 1;
		string = malloc(src_lenght);
		memcpy(string, src, src_lenght);
	}	
	return string;
}

wchar_t* REM_UCopyWChar(const wchar_t* src)
{
	wchar_t* string = NULL;	
	if (src > NULL)
	{
		size_t src_lenght = (wcslen(src) * sizeof(wchar_t)) + 1;
		string = malloc(src_lenght);
		memcpy(string, src, src_lenght);
	
	}
	return string;
}

char* REM_UConvertToChar(const wchar_t* src)
{
	char* string = NULL;
	if (src > NULL)
	{
		size_t src_lenght = wcslen(src);
		string = malloc(src_lenght);
		for (size_t i = 0; i < src_lenght + 1; i++)
		{
			string[i] = (char)src[i];
		}
	}
	return string;
}

wchar_t* REM_UConvertToWChar(const char* src)
{
	wchar_t* string = NULL;
	if (src > NULL)
	{
		size_t src_lenght = strlen(src);
		string = malloc(src_lenght);
		for (size_t i = 0; i < src_lenght + 1; i++)
		{
			string[i] = (wchar_t)src[i];
		}
	}
	return string;
}

void REM_URandomName(char* result, size_t current_lenght)
{
	char abc[] = { 65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,88,89,90,0 };
	srand((uint32_t)time(0));

	int random_lenght = rand() % 24 + 5;

	for (int i = 0; i < random_lenght; i++)
	{
		int rand_letter = rand() % 25 + 0;
		result[i + current_lenght] = abc[rand_letter];
	}
	srand(0);
}

void REM_URandomTempName(char* result)
{

	char TEMP_STR[] = { 'T','M','P', 0 };
	char* tmpDir = NULL;
	if (_dupenv_s(&tmpDir, NULL, TEMP_STR) == 0 && tmpDir > NULL)
	{
		REM_URandomName(result, 0);
		for (size_t i = 0; i < strlen(tmpDir); i++)
		{
			result[i] = tmpDir[i];
		}
		free(tmpDir);

		size_t cur_lenght = strlen(result);
		result[cur_lenght] = '\\';

		REM_URandomName(result, cur_lenght + 1);	
	}
}

uint8_t REM_UWriteBinary(const char* FileName, PVOID buffer, size_t single_lenght, size_t array_count)
{
	uint8_t status = 0;
	{
		FILE* file;
		char wb[] = { 119,98,0 };
		if (fopen_s(&file, FileName, wb) == 0)
		{
			if (fwrite(buffer, single_lenght, array_count, file))
			{
				status = 1;
			}
			fclose(file);
		}
	}
	return status;
}

uint8_t REM_UDeleteFile(const char* FileName)
{
	return _unlink(FileName) == 0 ? 1 : 0;
}