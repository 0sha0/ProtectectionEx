#pragma once
#include "Includes.hpp"

class Protection
{
public:
	NTSTATUS Init_Process_Callbacks();
	NTSTATUS Init_Thread_Callbacks();
	NTSTATUS InsertProtectionToPid(ULONG PID);
	std::vector<ULONG> _Pid_LIst;
private:
	NTSTATUS FindSignatureLevelOffsets(
			_Out_ PULONG SignatureLevelOffset,
			_Out_ PULONG SectionSignatureLevelOffset
		);
	NTSTATUS TokenLevelUp(ULONG PID);
	NTSTATUS ApcThreadLevelUp(ULONG PID);
	NTSTATUS InitPPL_Offset();
	NTSTATUS InsertPPL_SystemThread(PEPROCESS Process);
	OB_PREOP_CALLBACK_STATUS OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
	OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);
};

