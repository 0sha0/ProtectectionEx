#include "Includes.hpp"
#include "DeviceControl.hpp"
DeviceIoControl* _Driver_Control;

void DriverUnload(PDRIVER_OBJECT drive_object)
{
	_Driver_Control->Delete_IO_Control();
	delete _Driver_Control;
	Log("Unload [ProtectionEx Driver] Over!\n");
}


extern "C" NTSTATUS DriverMain(PDRIVER_OBJECT drive_object, PUNICODE_STRING path)
{
	//ÈÆ¹ýMmVerifyCallbackFunction
#if _WIN64
	PLDR_DATA_TABLE_ENTRY64 ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY64)drive_object->DriverSection;
	ldr->Flags |= 0x20;
#else
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY32 ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY32)drive_object->DriverSection;
	ldr->Flags |= 0x20;
#endif

	drive_object->DriverUnload = DriverUnload;
	_Driver_Control = new DeviceIoControl(drive_object);
	_Driver_Control->Create_IO_Control();
	return STATUS_SUCCESS;
}