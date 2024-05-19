#pragma once
#include "Includes.hpp"
#include <stdio.h>
#include <stdarg.h>

BOOLEAN Sleep(ULONG MillionSecond)
{
	NTSTATUS st;
	LARGE_INTEGER DelayTime;
	DelayTime = RtlConvertLongToLargeInteger(-10000 * MillionSecond);
	st = KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
	return (NT_SUCCESS(st));
}
VOID
Log(
	_In_ PCCH Format,
	_In_ ...
)
{
	CHAR Message[512];
	va_list VaList;
	va_start(VaList, Format);
	CONST ULONG N = _vsnprintf_s(Message, sizeof(Message) - sizeof(CHAR), Format, VaList);
	Message[N] = '\0';
	vDbgPrintExWithPrefix("[ProtectionEx] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Message, VaList);
	va_end(VaList);
}