#include "secret\NT_structs.h"
#include <malloc.h>

NTSTATUS
RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

enum windows_version
{
	win7_sp1 = 0x060101,
	win8     = 0x060200,
	win81    = 0x060300,
	win10    = 0x0A0000,
	win10_cu = 0x0A0002
};

PWINVEROFFSETS REM_UGetOffsets()
{
	PWINVEROFFSETS offsets = NULL;
	{
		RTL_OSVERSIONINFOW info = { sizeof(RTL_OSVERSIONINFOW) };
		if (NT_SUCCESS(RtlGetVersion(&info)))
		{
			uint32_t version_long = (info.dwMajorVersion << 16) | (info.dwMinorVersion << 8) | info.wServicePackMajor;

			switch (version_long)
			{
				case win7_sp1:
				{
					offsets = malloc(sizeof(WINVEROFFSETS));
					offsets->directorytable = 0x028;
					offsets->peb            = 0x0338;
					offsets->peb_x86        = 0x0320;
					offsets->imagename      = 0x02E0;
					offsets->processlinks   = 0x188;
					offsets->objecttable    = 0x200;
					break;
				}
				case win8:
				case win81:
				{
					offsets = malloc(sizeof(WINVEROFFSETS));
					offsets->directorytable = 0x028;
					offsets->peb = 0x03E8;
					offsets->peb_x86 = 0x0418;
					offsets->imagename = 0x0438;
					offsets->processlinks = 0x02E8;
					offsets->objecttable = 0x408;
					break;
				}
				case win10:
				{
					switch (info.dwBuildNumber)
					{
						case 10240:
						case 10586:
						case 14393:
						{
							offsets = malloc(sizeof(WINVEROFFSETS));
							offsets->directorytable = 0x028;
							offsets->peb = 0x03F8;
							offsets->peb_x86 = 0x0428;
							offsets->imagename = 0x448;
							offsets->processlinks = 0x2F0;
							offsets->objecttable = 0x418;
							break;
						}
						case 15063:
						{
							offsets = malloc(sizeof(WINVEROFFSETS));
							offsets->directorytable = 0x028;
							offsets->peb = 0x03E8;
							offsets->peb_x86 = 0x0418;
							offsets->imagename = 0x0438;
							offsets->processlinks = 0x02E8;
							offsets->objecttable = 0x418;
							break;
						}
					}
					break;
				}
			}
		}
	}
	return offsets;
}