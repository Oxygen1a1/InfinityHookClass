#include <ntifs.h>
#include <wdm.h>
#include <intrin.h>
#include "Global.h"


extern EtwHook g_Etwhook;


NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);



NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) {
		if(DesiredAccess>=0x10000)
		KdPrint(("¡¾EtwHook¡¿:Hook Successly.the DesiredAccess==0x%x\n", DesiredAccess));
		


	}
	UNICODE_STRING usNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
	FNtCreateFile _ori_NtCreateFile = (FNtCreateFile)MmGetSystemRoutineAddress(&usNtCreateFile);


	return _ori_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	
}

void __fastcall hook_etw_call_back(unsigned long ssdt_index, void** ssdt_address) {
	//this is really hook ntapi func
	//filter the callindex or addr 
	UNREFERENCED_PARAMETER(ssdt_index);
	
	ULONG_PTR uMyFuncAddr=g_Etwhook.is_hook_func((ULONG_PTR)*ssdt_address);

	
	if (uMyFuncAddr) *ssdt_address = (void*)uMyFuncAddr;

}
//os buildnum <18363
unsigned long long MyGetCpuClock() {


	if (ExGetPreviousMode() == KernelMode) return __rdtsc();

	const long SYSCALL_MAGIC_1 = 0x501802;
	const short SYSCALL_MAGIC_2 = 0xf33;
	

	PKTHREAD CurrentThread = (PKTHREAD)__readgsqword(0x188);

	unsigned int call_index = 0;
	DWORD32 dwBuildNumer = g_Etwhook.ret_build_num();

	//get callindex
	if(dwBuildNumer<=7601) call_index = *(unsigned int*)((unsigned long long)CurrentThread + 0x1f8);
	else call_index = *(unsigned int*)((unsigned long long)CurrentThread + 0x80);

	void** stack_max = (void**)__readgsqword(0x1a8);
	void** stack_frame = (void**)_AddressOfReturnAddress();

	//from bottom to top
	for (void** stack_current = stack_max; stack_current > stack_frame; stack_current--) {
		
		if (*(long*)stack_current != SYSCALL_MAGIC_1) continue;

		stack_current--;

		if (*(short*)stack_current != SYSCALL_MAGIC_2) continue;

		//is a syscall

		//find a retvaule in syscall entry range

		for (; stack_current < stack_max; stack_current++) {

			//rough estimate
			if ((ULONG_PTR)(*stack_current) >= g_Etwhook.ret_syscall_entry() && (ULONG_PTR)(*stack_current) <= g_Etwhook.ret_syscall_entry() + 2 * PAGE_SIZE) {

				//find 

				void** syscall_call_func = &stack_current[9];

				//modify syscall_call_func and hook
				hook_etw_call_back(call_index, syscall_call_func);

				break;
			}

		}

		break; //must break in here else the os will crash!!!
	}

	return __rdtsc();
}

unsigned long long MyHvlGetQpcBias() {
	ULONG_PTR pTscpage = g_Etwhook.ret_tsc_page();
	
	
	MyGetCpuClock();


	return *((unsigned long long*)(*((unsigned long long*)pTscpage)) + 3);//HvlGetQpcBias really done

}


