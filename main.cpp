#include <ntifs.h>
#include <ntddk.h>
#include "Global.h"
#include "UnDocFuncAndStr.h"

//Global Var

EtwHook g_Etwhook;

//Func Def
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegPath);
void Unload(PDRIVER_OBJECT DriverObject);
NTSTATUS ShowErrInfo(const char* szStr);
extern NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);



extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegPath) {
	
	UNREFERENCED_PARAMETER(RegPath);
	
	DriverObject->DriverUnload = Unload;


	
	if (!g_Etwhook.init()) return STATUS_UNSUCCESSFUL;

	if (!g_Etwhook.start()) return STATUS_UNSUCCESSFUL;
	
	UNICODE_STRING usMyCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
	g_Etwhook.add_hook(&usMyCreateFile, (ULONG_PTR)MyNtCreateFile);



	return (g_Etwhook.init() && g_Etwhook.start()) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

void Unload(PDRIVER_OBJECT DriverObject) {

	UNREFERENCED_PARAMETER(DriverObject);
	
	//stop
	g_Etwhook.stop();

	KdPrint(("¡¾EtwHook¡¿:DriverUnload Successly\n"));
}

NTSTATUS ShowErrInfo(const char* szStr)
{

	KdPrint(("¡¾EtwHook¡¿:%s\n", szStr));
	return STATUS_UNSUCCESSFUL;
}

