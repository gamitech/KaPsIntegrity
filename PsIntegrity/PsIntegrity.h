#pragma once

extern HANDLE gProcHeap;

DWORD KaPsGetAccountSidName(
	_In_  PSID Sid,
	_In_  BOOLEAN IncludeDomain,
	_Out_ PTCHAR *AccountName,
	_Out_ PDWORD AccountNameLength
	);

DWORD
KaPsInitializeMandatoryLabelSacl(
	_Out_ PACL *Sacl,
	_In_ KA_OBJECT_INTEGRITY Integrity,
	_In_ DWORD PolicyMask
	);

DWORD
KaPsGetObjectIntegrityLabelByName(
	_In_  PTCHAR ObjectName,
	_In_ SE_OBJECT_TYPE ObjectType,
	_Out_ PBOOL DefaultIntegrity,
	_Out_ PDWORD IntegrityRID,
	_Out_opt_ PDWORD PolicyMask
	);

DWORD
KaPsSetObjectIntegrityLabelByName(
	_In_ PTCHAR ObjectName,
	_In_ SE_OBJECT_TYPE ObjectType,
	_In_ KA_OBJECT_INTEGRITY NewIntegrity
	);

DWORD
KaPsSetObjectIntegrityLabelWithPolicyMaskByName(
	_In_ PTCHAR ObjectName,
	_In_ SE_OBJECT_TYPE ObjectType,
	_In_ KA_OBJECT_INTEGRITY NewIntegrity,
	_In_ DWORD PolicyMask
	);

DWORD
KaPsGetProcessIntegrityLevelWithPolicyByPid(
	DWORD Pid,
	_Out_ PDWORD IntegrityRID,
	_Out_opt_ PDWORD PolicyMask
	);

DWORD
KaPsSetProcessIntegrityLevelWithPolicyMaskByPid(
	_In_ DWORD Pid,
	_In_ KA_OBJECT_INTEGRITY NewIntegrity,
	_In_ DWORD PolicyMask
	);

BOOL
KaPsCreateProcessWithIntegrityLevel(
	_In_ PTCHAR Path,
	_In_ KA_OBJECT_INTEGRITY Integrity,
	_In_ DWORD PolicyMask
	);