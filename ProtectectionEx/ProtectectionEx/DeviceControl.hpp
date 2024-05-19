#include "Includes.hpp"
#pragma once
struct IOCTLS
{
	bool ObCallback;
	bool FindPspCidOffset;
};
class DeviceIoControl
{
public:
	DeviceIoControl(PDRIVER_OBJECT drive_object)
	{
		Driver_Object = drive_object;
		_This = this;
	}
	~DeviceIoControl() = default;
public:
	NTSTATUS Create_IO_Control();
	NTSTATUS Delete_IO_Control();
private:
	static DeviceIoControl* _This;
	static NTSTATUS IO_Default(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp);
	static NTSTATUS IoDeviceControl_Centre(PDEVICE_OBJECT  DeviceObject, PIRP  pIrp);
private:
	DRIVER_OBJECT* Driver_Object = nullptr;
	DEVICE_OBJECT* Device_Object = nullptr;
	UNICODE_STRING Device_Name;
	UNICODE_STRING Link_Name;
private:

};

