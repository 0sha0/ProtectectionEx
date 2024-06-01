#include "Protection.hpp"
BOOLEAN IsBlue = false;
PVOID ProcessObHandle;
PVOID ThreadObHandle;
ULONG SignatureLevelOffset{}, SectionSignatureLevelOffset{};
NTSTATUS Protection::FindSignatureLevelOffsets(
	_Out_ PULONG SignatureLevelOffset,
	_Out_ PULONG SectionSignatureLevelOffset
)
{
	PAGED_CODE();

	*SignatureLevelOffset = 0;
	*SectionSignatureLevelOffset = 0;

	// Since the EPROCESS struct is opaque and we don't know its size, allocate for 4K possible offsets
	const PULONG CandidateSignatureLevelOffsets = static_cast<PULONG>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
			PAGE_SIZE * sizeof(ULONG),
			'PPLL'));
	if (CandidateSignatureLevelOffsets == nullptr)
		return STATUS_NO_MEMORY;
	const PULONG CandidateSectionSignatureLevelOffsets = static_cast<PULONG>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
			PAGE_SIZE * sizeof(ULONG),
			'PPLL'));
	if (CandidateSectionSignatureLevelOffsets == nullptr)
	{
		ExFreePoolWithTag(CandidateSignatureLevelOffsets, 'PPLL');
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(CandidateSignatureLevelOffsets, sizeof(ULONG) * PAGE_SIZE);
	RtlZeroMemory(CandidateSectionSignatureLevelOffsets, sizeof(ULONG) * PAGE_SIZE);

	// Query all running processes
	ULONG NumSignatureRequiredProcesses = 0, BestMatchCount = 0;
	ULONG SignatureOffset = 0, SectionSignatureOffset = 0;
	NTSTATUS Status;
	ULONG Size;
	PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = nullptr, Entry;
	if ((Status = ZwQuerySystemInformation(SystemProcessInformation,
		SystemProcessInfo,
		0,
		&Size)) != STATUS_INFO_LENGTH_MISMATCH)
		goto finished;
	SystemProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
			2 * Size,
			'PPLL'));
	if (SystemProcessInfo == nullptr)
	{
		Status = STATUS_NO_MEMORY;
		goto finished;
	}
	Status = ZwQuerySystemInformation(SystemProcessInformation,
		SystemProcessInfo,
		2 * Size,
		nullptr);
	if (!NT_SUCCESS(Status))
		goto finished;

	// Enumerate the process list
	Entry = SystemProcessInfo;
	while (true)
	{
		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(static_cast<PUNICODE_STRING>(nullptr),
			OBJ_KERNEL_HANDLE);
		CLIENT_ID ClientId = { Entry->UniqueProcessId, nullptr };
		HANDLE ProcessHandle;
		Status = ZwOpenProcess(&ProcessHandle,
			PROCESS_QUERY_LIMITED_INFORMATION,
			&ObjectAttributes,
			&ClientId);
		if (NT_SUCCESS(Status))
		{
			// Query the process's signature policy status
			PROCESS_MITIGATION_POLICY_INFORMATION PolicyInfo;
			PolicyInfo.Policy = ProcessSignaturePolicy;
			Status = ZwQueryInformationProcess(ProcessHandle,
				ProcessMitigationPolicy,
				&PolicyInfo,
				sizeof(PolicyInfo),
				nullptr);

			// If it has an MS signature policy requirement, get the EPROCESS
			if (NT_SUCCESS(Status) && PolicyInfo.u.SignaturePolicy.MicrosoftSignedOnly != 0)
			{
				PEPROCESS Process;
				Status = ObReferenceObjectByHandle(ProcessHandle,
					PROCESS_QUERY_LIMITED_INFORMATION,
					*PsProcessType,
					KernelMode,
					reinterpret_cast<PVOID*>(&Process),
					nullptr);
				if (NT_SUCCESS(Status))
				{
					// Find plausible offsets in the EPROCESS
					const ULONG_PTR End = ALIGN_UP_BY(Process, PAGE_SIZE) - reinterpret_cast<ULONG_PTR>(Process) - sizeof(UCHAR);
					for (ULONG_PTR i = PS_SEARCH_START; i < End; ++i)
					{
						// Take the low nibble of both bytes, which contains the SE_SIGNING_LEVEL_*
						const UCHAR CandidateSignatureLevel = *(reinterpret_cast<PUCHAR>(Process) + i) & 0xF;
						const ULONG CandidateSectionSignatureLevel = *(reinterpret_cast<PUCHAR>(Process) + i + sizeof(UCHAR)) & 0xF;

						if ((CandidateSignatureLevel == SE_SIGNING_LEVEL_MICROSOFT ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_WINDOWS ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_ANTIMALWARE ||
							CandidateSignatureLevel == SE_SIGNING_LEVEL_WINDOWS_TCB)
							&&
							(CandidateSectionSignatureLevel == SE_SIGNING_LEVEL_MICROSOFT ||
								CandidateSectionSignatureLevel == SE_SIGNING_LEVEL_WINDOWS))
						{
							CandidateSignatureLevelOffsets[i]++;
							i += sizeof(UCHAR);
							CandidateSectionSignatureLevelOffsets[i]++;
						}
					}
					NumSignatureRequiredProcesses++;
					ObfDereferenceObject(Process);
				}
			}
			ZwClose(ProcessHandle);
		}

		if (Entry->NextEntryOffset == 0)
			break;

		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
			Entry->NextEntryOffset);
	}

	// Go over the possible offsets to find the combination that is correct for all processes
	for (ULONG i = PS_SEARCH_START; i < PAGE_SIZE; ++i)
	{
		if (CandidateSignatureLevelOffsets[i] > BestMatchCount)
		{
			if (BestMatchCount == NumSignatureRequiredProcesses)
			{
				Log("Found multiple offsets for SignatureLevel that match all processes! This is probably a bug - please report.\n");
				Status = STATUS_NOT_FOUND;
				goto finished;
			}
			SignatureOffset = i;
			SectionSignatureOffset = i + sizeof(UCHAR);
			BestMatchCount = CandidateSignatureLevelOffsets[i];
		}
	}

	if (BestMatchCount == 0 && NumSignatureRequiredProcesses > 0)
	{
		Log("Did not find any possible offsets for the SignatureLevel field.\n");
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (BestMatchCount != NumSignatureRequiredProcesses)
	{
		Log("Best found SignatureLevel offset match +0x%02X is only valid for %u of %u processes.\n",
			SignatureOffset, BestMatchCount, NumSignatureRequiredProcesses);
		Status = STATUS_NOT_FOUND;
		goto finished;
	}

	if (NumSignatureRequiredProcesses > 1) // Require at least System + 1 other MS signing policy process to give a reliable result
		Log("Found SignatureLevel offset +0x%02X and SectionSignatureLevel offset +0x%02X.\n\n",
			SignatureOffset, SectionSignatureOffset);
	else
	{
		// This is not an error condition; it just means there are no processes with MS code signing requirements.
		// There may still be PPLs to kill. Set a non-error status to indicate this.
		Log("Did not find any non-system processes with signature requirements.\n");
		Status = STATUS_NO_MORE_ENTRIES;
		SignatureOffset = 0;
		SectionSignatureOffset = 0;
	}
	*SignatureLevelOffset = SignatureOffset;
	*SectionSignatureLevelOffset = SectionSignatureOffset;

finished:
	if (SystemProcessInfo != nullptr)
		ExFreePoolWithTag(SystemProcessInfo, 'PPLL');
	ExFreePoolWithTag(CandidateSectionSignatureLevelOffsets, 'PPLL');
	ExFreePoolWithTag(CandidateSignatureLevelOffsets, 'PPLL');
	return Status;
}
NTSTATUS Protection::TokenLevelUp(ULONG PID)
{
	NTSTATUS status = STATUS_SUCCESS;

	CLIENT_ID clientId;
	HANDLE handle, hToken;

	TOKEN_PRIVILEGES tkp = { 0 };
	OBJECT_ATTRIBUTES objAttr;
	ULONG BreakOnTermination = 1;

	clientId.UniqueThread = NULL;
	clientId.UniqueProcess = ULongToHandle(PID);
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
	if (!NT_SUCCESS(status))
	{

		Log("Failed to open process : % d\n", status);
		return status;
	}

	status = ZwOpenProcessTokenEx(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
	if (!NT_SUCCESS(status))
	{
		Log("Failed to open token : % d\n", status);
		ZwClose(hToken);
		return status;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);

	status = ZwAdjustPrivilegesToken(hToken, FALSE, &tkp, 0, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		Log("Failed to adjust token : % d\n", status);
		ZwClose(hToken);
		return status;
	}
	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
		Log("Failed to set information process : % d\n", status);
		ZwClose(hToken);
		return status;
	}
	tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
	status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
		Log("Failed to set information process: nr 2");
		ZwClose(hToken);
		return status;
	}
	ZwClose(hToken);
	return status;
}
NTSTATUS Protection::ApcThreadLevelUp(ULONG PID) {
	PEPROCESS ProcessEprocess = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)PID, &ProcessEprocess))) {
		Log("Failed to Find process : % d\n");
     	ObDereferenceObject(ProcessEprocess);
		return STATUS_NOT_FOUND;
	}
	else
	{
		for (int i = 4; i < 262144; i = i + 4)
		{
			PKTHREAD KTHREAD = NULL;
			PsLookupThreadByThreadId((HANDLE)i, &KTHREAD);
			if (KTHREAD != NULL)
			{
				*(ULONG64*)((ULONG64)KTHREAD + 116) &= 0xFFFFFFFFFBFFFui64;
				ObDereferenceObject(KTHREAD);
			}
		}
		ObDereferenceObject(ProcessEprocess);
		return STATUS_SUCCESS;
	}
}
NTSTATUS Protection::InitPPL_Offset() {
	OSVERSIONINFOEXW VersionInfo = { sizeof(OSVERSIONINFOEXW) };
	NTSTATUS Status = RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&VersionInfo));
	if (!NT_SUCCESS(Status))
		return Status;

	// Only Windows 8.1 and later are afflicted with PPL.
	if (VersionInfo.dwBuildNumber < 6002)
	{
		Log("Unsupported OS version.\n");
		return STATUS_NOT_SUPPORTED;
	}

	if (VersionInfo.dwBuildNumber == 6002)
		SignatureLevelOffset = 0x036c;
	else if (VersionInfo.dwBuildNumber == 7601)
		SignatureLevelOffset = 0x043c;
	else
	{
		if (VersionInfo.dwBuildNumber == 9200)
			IsBlue = true;
		// Find the offsets of the [Section]SignatureLevel fields
		Status = FindSignatureLevelOffsets(&SignatureLevelOffset, &SectionSignatureLevelOffset);
		if (!NT_SUCCESS(Status) && Status != STATUS_NO_MORE_ENTRIES)
		{
			Log("Failed to find the SignatureLevel and SectionSignatureLevel offsets for Windows %u.%u.%u.\n",
				VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber);
			return Status;
		}
	}

}
NTSTATUS Protection::InsertPPL_SystemThread(PEPROCESS Process) {
	HANDLE hThread{};
	PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, [](PVOID StartContext)
		{
			Sleep(1000);
			if (!SectionSignatureLevelOffset)
			{
				PULONG pFlags2 = (PULONG)(((ULONG_PTR)StartContext) + SignatureLevelOffset);
				*pFlags2 |= PROTECTED_PROCESS_MASK;
			}
			else
			{
				PPROCESS_SIGNATURE_PROTECTION pSignatureProtect = (PPROCESS_SIGNATURE_PROTECTION)(((ULONG_PTR)StartContext) + SignatureLevelOffset);
				pSignatureProtect->SignatureLevel = IsBlue ? 0x0F : 0x3F;
				pSignatureProtect->SectionSignatureLevel = IsBlue ? 0x0F : 0x3F;
				if (!IsBlue)
				{
					pSignatureProtect->Protection.Type = 2;
					pSignatureProtect->Protection.Audit = 0;
					pSignatureProtect->Protection.Signer = 6;
				}
			}
		}
	, Process);
}
OB_PREOP_CALLBACK_STATUS Protection::OnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->KernelHandle) {
		return OB_PREOP_SUCCESS;
	}

	auto Process = (PEPROCESS)OperationInformation->Object;
	auto pid = HandleToULong(PsGetProcessId(Process));

	// If the process was found on the list, remove permissions for dump / write process memory and kill the process.
	for (ULONG ProPid : _Pid_LIst) {
		if (ProPid == pid) {
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
		}
	}
	return OB_PREOP_SUCCESS;
}
OB_PREOP_CALLBACK_STATUS Protection::OnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->KernelHandle) {
		return OB_PREOP_SUCCESS;
	}


	PETHREAD thread = (PETHREAD)OperationInformation->Object;
	ULONG tid = HandleToULong(PsGetThreadId(thread));
	ULONG ownerPid = HandleToULong(PsGetThreadProcessId(thread));
	ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

	// To avoid a situation when a process dies and the thread needs to be closed but it isn't closed, if the killer is its owning process, let it be killed.
	if (callerPid == ownerPid || callerPid == 4 || callerPid == 0) {
		return OB_PREOP_SUCCESS;
	}
	for (ULONG ProPid : _Pid_LIst) {
		if(ownerPid==ProPid){
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
		}
	}
	return OB_PREOP_SUCCESS;
}
NTSTATUS Protection::Init_Process_Callbacks() {

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	memset(&opReg, 0, sizeof(opReg)); //初始化结构体变量
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = static_cast<POB_PRE_OPERATION_CALLBACK>(&OnPreOpenProcess);
	obReg.OperationRegistration = &opReg; //注意这一条语句
	ObRegisterCallbacks(&obReg, &ProcessObHandle); //注册回调函数
	return STATUS_SUCCESS;
}
NTSTATUS Protection::Init_Thread_Callbacks() {

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	memset(&opReg, 0, sizeof(opReg)); //初始化结构体变量
	opReg.ObjectType = PsThreadType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = reinterpret_cast<POB_PRE_OPERATION_CALLBACK>(&OnPreOpenThread);
	obReg.OperationRegistration = &opReg; //注意这一条语句
	ObRegisterCallbacks(&obReg, &ThreadObHandle); //注册回调函数
	return STATUS_SUCCESS;
}
NTSTATUS Protection::InsertProtectionToPid(ULONG PID) {
	PEPROCESS ProcessEprocess = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)PID, &ProcessEprocess))) {
		Log("Failed to Find process : % d\n");
		ObDereferenceObject(ProcessEprocess);
		return STATUS_NOT_FOUND;
	}
	else {
		_Pid_LIst.push_back(PID);
		TokenLevelUp(PID);
		InsertPPL_SystemThread(ProcessEprocess);
		ApcThreadLevelUp(PID);
	}
}
/*
PVOID GetPspCidTable()
{
	ULONG64 PspCidTable = 0, PspReferenceCidTableEntry = 0, i = 0;
	PspReferenceCidTableEntry = (ULONG64)PsLookupProcessByProcessId;
	if (PspReferenceCidTableEntry)
	{
		for (i = 0; i <= 0x100; i++)
		{
			if (*(UCHAR*)PspReferenceCidTableEntry == 0xE8 && *(UCHAR*)(PspReferenceCidTableEntry + 5) == 0x48 && *(UCHAR*)(PspReferenceCidTableEntry + 6) == 0x8B
				&& *(UCHAR*)(PspReferenceCidTableEntry + 7) == 0xD8 && *(UCHAR*)(PspReferenceCidTableEntry + 8) == 0x48)
			{
				PspReferenceCidTableEntry++;
				PspCidTable = PspReferenceCidTableEntry = Dereference(PspReferenceCidTableEntry, 0);
			}
			++PspReferenceCidTableEntry;
		}
		if (MmIsAddressValid((PVOID)PspReferenceCidTableEntry))
		{
			for (i = 0; i <= 0x30; i++)
			{
				if (*(UCHAR*)PspCidTable == 0x48 && *(UCHAR*)(PspCidTable + 1) == 0x8B && *(UCHAR*)(PspCidTable + 2) == 0x05)
				{
					PspCidTable++;
					PspCidTable = PspCidTable + *(INT*)(PspCidTable + 2) + 6;
					return *(PVOID*)PspCidTable;
				}
				++PspCidTable;
			}
		}
		return NULL;
	}
	return NULL;
}*/
//PspCid Offset
/*
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)PID, &EProcess)))
		{
			UnLinkProcesssList(EProcess);
			UnLinkHandleTable(EProcess);
			RemovePspCidTable(PID);
			*(ULONG64*)((ULONG64)EProcess + UniqueProcessId) = 0;
			*(ULONG64*)((ULONG64)EProcess + ProcessLock) = 0;
			*(ULONG64*)((ULONG64)EProcess + InheritedFromUniqueProcessId) = 0;
			*(CHAR*)((ULONG64)EProcess - 0x30 + 0x1B) = 0x4;
			ObDereferenceObject(EProcess);
		}*/
//Hidden Process

//PS 因为我只需要保护进程 而不是隐藏进程 所以这个保护可以被刷回 (在内核里面的进行逆操作)
//若隐藏进程 那就是断链的事情了 PspCidTable ThreadTable ActiveProcessTable这些（一些名词为简写)
