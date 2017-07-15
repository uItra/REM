#pragma once
#include <inttypes.h>

typedef long  NTSTATUS;
typedef void* PVOID;
typedef void* HANDLE;
#define       NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define       CURRENT_PROCESS  (HANDLE)-1
#define       NULL             (void*)0
#define       PTR_MINUS        (void*)-1
