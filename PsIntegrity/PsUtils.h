#pragma once

extern HANDLE gProcHeap;

typedef struct _PROCESS_PID_PATH
{
	DWORD Pid;
	TCHAR Path[MAX_PATH];
}PROCESS_PID_PATH, *PPROCESS_PID_PATH;

DWORD
KaPsGetProcessCount(
	_Out_ PDWORD ProcessCount
	);

DWORD
KaPsGetProcessNameById(
	_In_ DWORD ProcessId,
	_Inout_ PTCHAR ProcessName,
	_Inout_ DWORD ProcessNameLength
	);

DWORD
KaPsGetProcessArray(
	_Out_ PPROCESS_PID_PATH *ProcessArray,
	_Out_ PDWORD ProcessArrayCount
	);

BOOL
KaPsSetProcessPrivilege(
	_In_ HANDLE hProcess,
	_In_ PTCHAR PrivilegeName,
	_In_ BOOL   EnablePrivilege
	);