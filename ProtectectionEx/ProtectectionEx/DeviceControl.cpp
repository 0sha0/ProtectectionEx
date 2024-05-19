#pragma once
#include "DeviceControl.hpp"
#define DEVICE_NAME L"\\Device\\ProtectionEx"
#define LINK_NAME L"\\??\\ProtectionEx"

DeviceIoControl* DeviceIoControl::_This;

NTSTATUS DeviceIoControl::Create_IO_Control()
{
	NTSTATUS status = 0;
	//创建设备对象
	RtlInitUnicodeString(&Device_Name, DEVICE_NAME);
	status = IoCreateDevice(Driver_Object, 0, &Device_Name, FILE_DEVICE_UNKNOWN, 0, FALSE, &Device_Object);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create Device error!\n");
		return status;
	}

	Device_Object->Flags |= DO_BUFFERED_IO;
	//创建符号连接
	RtlInitUnicodeString(&Link_Name, LINK_NAME);
	status = IoCreateSymbolicLink(&Link_Name, &Device_Name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(Device_Object);
		DbgPrint("Create Link error!\n");
		return status;
	}
	Driver_Object->MajorFunction[IRP_MJ_CREATE] = DeviceIoControl::IO_Default;
	Driver_Object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl::IoDeviceControl_Centre;


	return STATUS_SUCCESS;
}

NTSTATUS DeviceIoControl::Delete_IO_Control()
{
	IoDeleteSymbolicLink(&Link_Name);
	IoDeleteDevice(Device_Object);
	DbgPrint("Link_Unload\n");
	return STATUS_SUCCESS;
}

NTSTATUS DeviceIoControl::IO_Default(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceIoControl::IoDeviceControl_Centre(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp)
{
	PIO_STACK_LOCATION irp = IoGetCurrentIrpStackLocation(pIrp);
	ULONG Io_Control_Code = irp->Parameters.DeviceIoControl.IoControlCode;
	ULONG Input_Lenght = irp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG Output_Lenght = irp->Parameters.DeviceIoControl.OutputBufferLength;
	char* Input_Buffer = (char*)pIrp->AssociatedIrp.SystemBuffer;


	/*
	if (Io_Control_Code == 1)
	{
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		pIrp->IoStatus.Information = 1024;
		IoCompleteRequest(pIrp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}
	*/
	//这里本来是想要做通信的 但是太懒了
	//请直接看到Protection.cpp类
	pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}