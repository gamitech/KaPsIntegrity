#include "stdafx.h"

BOOL
KaPsSetProcessPrivilege(
	_In_ HANDLE hProcess,
	_In_ PTCHAR PrivilegeName,
	_In_ BOOL   EnablePrivilege
	)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivleges;
	LUID Luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		PrivilegeName,   // privilege to lookup 
		&Luid))        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		return FALSE;
	}

	TokenPrivleges.PrivilegeCount = 1;
	TokenPrivleges.Privileges[0].Luid = Luid;

	if (EnablePrivilege)
		TokenPrivleges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		TokenPrivleges.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&TokenPrivleges,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}

DWORD
KaPsGetProcessCount(
	_Out_ PDWORD ProcessCount
	)
{
	DWORD PidArray[1024] = { 0 };
	DWORD NeededLength = 0;

	if (!ProcessCount)
	{
		return ERROR_INVALID_PARAMETER;
	}

	if (!EnumProcesses(PidArray, sizeof(PidArray), &NeededLength))
	{
		return GetLastError();
	}

	*ProcessCount = sizeof(PidArray) / NeededLength;

	return ERROR_SUCCESS;
}

DWORD
KaPsGetProcessNameById(
	_In_ DWORD ProcessId,
	_Inout_ PTCHAR ProcessName,
	_Inout_ DWORD ProcessNameLength
	)
{
	HANDLE hProcess;
	HMODULE hMod;
	DWORD NeededLength;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);
	if (hProcess != NULL)
	{
		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &NeededLength))
		{
			GetModuleBaseName(hProcess, hMod, ProcessName, ProcessNameLength / sizeof(TCHAR));
		}

		CloseHandle(hProcess);
	}

	return GetLastError();
}

DWORD
KaPsGetProcessArray(
	_Out_ PPROCESS_PID_PATH *ProcessArray,
	_Out_ PDWORD ProcessArrayCount
	)
{
	DWORD ProcessCountLocal = 0;
	DWORD PidArray[1024] = { 0 };
	DWORD i;

	if (!ProcessArray || !ProcessArrayCount)
	{
		return ERROR_INVALID_PARAMETER;
	}

	if (!EnumProcesses(PidArray, sizeof(PidArray), &ProcessCountLocal))
	{
		return GetLastError();
	}

	ProcessCountLocal = sizeof(PidArray) / ProcessCountLocal;

	*ProcessArray = (PPROCESS_PID_PATH)HeapAlloc(gProcHeap, 0, sizeof(PROCESS_PID_PATH) * ProcessCountLocal);
	if (!*ProcessArray)
	{
		return GetLastError();
	}

	*ProcessArrayCount = ProcessCountLocal;

	for (i = 0; i < ProcessCountLocal; i++)
	{
		(*ProcessArray)[i].Pid = PidArray[i];
		KaPsGetProcessNameById(PidArray[i], (*ProcessArray)[i].Path, sizeof((*ProcessArray)[i].Path));
	}

	return ERROR_SUCCESS;
}
