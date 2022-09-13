#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h> //Kernel program pe format headfile
#include "UnDocFuncAndStr.h"
#include "Global.h"



#include "hde/hde64.h"

#pragma warning(disable : 4310)
#pragma warning(disable : 4309)
#pragma warning(disable : 4838)

extern void __fastcall hook_etw_call_back(unsigned long ssdt_index, void** ssdt_address);
extern unsigned long long MyHvlGetQpcBias();
extern unsigned long long MyGetCpuClock();



BOOLEAN EtwHook::init()
{
	

	get_os_build_num();

	if (this->dwBuildNumer == 0) return show_err_info("Get osBuildNumer err!");

	KdPrint(("¡¾EtwHook¡¿:Os Build Number:%d\n", this->dwBuildNumer));

	this->uNtoskrnlBase = get_ntoskrnl_base();

	if (this->uNtoskrnlBase == 0) return show_err_info("Get uNtoskrnlBase err!");
	
	KdPrint(("¡¾EtwHook¡¿:uNtoskrnlBase:%p\n",this->uNtoskrnlBase));

	this->uCkclWmiLoggerContext = get_ckclcontext_addr();

	if (this->uCkclWmiLoggerContext == 0) return show_err_info("Get uCkclWmiLoggerContext err!");

	KdPrint(("¡¾EtwHook¡¿:CkclWmiLoggerContext:%p\n", this->uCkclWmiLoggerContext));

	if (!get_cpu_clock()) return show_err_info("Get CpuClock err!");

	KdPrint(("¡¾EtwHook¡¿:Cpuclock:%p\n", this->CpuClock));

	if (!get_syscall_entry()) return show_err_info("Get syscall_entry err!");

	KdPrint(("¡¾EtwHook¡¿:sysentry:%p\n", this->uSystemCall64));

	//if buildnumber>18363
	//the cpuclock is not a pointer but a num
	//we intend to hook pHvlGetQpcBias
	//refer https://www.freebuf.com/articles/system/278857.html
	//because etw logger finally call this func (if cpuclok num is 2)
	//and by the way, this func is not protected by PG
	
	if (dwBuildNumer > 18363) {

			/*.text:00000001403638A0 48 8B 05 D9 8D 99 00      mov     rax, cs:HvlpReferenceTscPage
			.text : 00000001403638A7 48 8B 40 18         mov     rax, [rax + 18h]
			.text:00000001403638AB C3       */      
		//00 ref ?? 

		//qword_140C4A2F8  is pHvlGetQpcBias
		//48 8B 05 5F 84 79 00                          mov     rax, cs:qword_140C4A2F8  
		//	.text : 00000001404B1E99 48 85 C0                                      test    rax, rax
		//	.text : 00000001404B1E9C 74 28                                         jz      short loc_1404B1EC6

		char TscPageshellcode[12] = { 0x48,0x8B,0x05,0x00,0x00,0x00,0x00,0x48,0x8B,0x40,0x18,0xC3 };
		char HvlGetQpcBiasshellcode[15] = { 0x48,0x8B,0x05,0x00,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x00,0x48,0x83,0x3d };

		ULONG_PTR _HvlGetQpcBias = get_undoc_func_by_shellcode(TscPageshellcode, sizeof(TscPageshellcode));
		pHvlGetQpcBias = get_undoc_func_by_shellcode(HvlGetQpcBiasshellcode, sizeof(HvlGetQpcBiasshellcode));

		if (!_HvlGetQpcBias || !pHvlGetQpcBias) return show_err_info("get undoc func err!");

		KdPrint(("pHvlGetQpcBias==%p,_HvlGetQpcBias==%p", pHvlGetQpcBias, _HvlGetQpcBias));

		pHvlGetQpcBias = pHvlGetQpcBias+ *(int*)(pHvlGetQpcBias + 3)+7;
		
		if(!_HvlGetQpcBias) return show_err_info("Get _HvlGetQpcBias err!");

		KdPrint(("¡¾EtwHook¡¿:pHvlGetQpcBias:%p\n", pHvlGetQpcBias));
		

		pHvlpReferenceTscPage = _HvlGetQpcBias + *(int*)(_HvlGetQpcBias + 3)+7;

		KdPrint(("¡¾EtwHook¡¿:pHvlpReferenceTscPage:%p\n", this->pHvlpReferenceTscPage));
	}


	return true;
}

BOOLEAN EtwHook::start()
{
	if (!NT_SUCCESS(modify_etw_settings(syscall_trace))) {

		if (!NT_SUCCESS(modify_etw_settings(start_trace))) {
			return show_err_info("start etw err!");

		}

		if (!NT_SUCCESS(modify_etw_settings(syscall_trace))) {
			return show_err_info("start etw err!");
		}
	}

	//KdPrint(("start etw successly\n"));

	//if os buildnum<=18369
	//GetCpuClock is a pointer so we just modify the pointer
	if (dwBuildNumer <= 18363) {
		*(PVOID*)(this->CpuClock) = MyGetCpuClock;

	}
	else {
		//else the CpuClock is a num
		//save the Old Cpuclock
		OriCpuClock = *(ULONG_PTR*)CpuClock;

		*(ULONG_PTR*)CpuClock = 2;
		//in above buildnum 18369 
		//cpuclock=0 call RtlGetSystemTimePrecise PG
		//cpuclock=1 call KeQueryPerformanceCounter PG
		//cpuclock=2 call offset_off_140C009E0 none PG
		//cpuclock=3 call __rdtsc PG
		//and off_140C009E0 = (__int64 (__fastcall *)(_QWORD))HalpTimerQueryHostPerformanceCounter;
		//HalpTimerQueryHostPerformanceCounter call qword_140C4A2F8()
		//qword_140C4A2F8=pHvlGetQpcBias
		//pHvlGetQpcBias return *(_QWORD *)(HvlpReferenceTscPage + 24);
		//we can hook pHvlGetQpcBias and call HvlpReferenceTscPage + 24
		
		//save 
		HvlGetQpcBias = *(ULONG_PTR*)pHvlGetQpcBias;
		*(ULONG_PTR*)pHvlGetQpcBias = (ULONG_PTR)MyHvlGetQpcBias;
	
	}

	KdPrint(("Install etw hook successly\n"));
	return true;
}

void EtwHook::stop()
{

	//disable syscall trace
	modify_etw_settings(stop_trace);

	modify_etw_settings(start_trace);

	//win10 1909 need to resume the envirmonet

	if (dwBuildNumer>18363) {
		*(ULONG_PTR*)this->pHvlGetQpcBias = this->HvlGetQpcBias;
		*(ULONG_PTR*)this->CpuClock = this->OriCpuClock;
	}
	

}

BOOLEAN EtwHook::add_hook(PUNICODE_STRING usHookFuncName, ULONG_PTR MyFunc) {

	for (int i = 0; i < 20; i++) {


		if (!this->HookFuncPointerArr[i]) {
			//add pointer
			ULONG_PTR OriFuncAddr = (ULONG_PTR)MmGetSystemRoutineAddress(usHookFuncName);

			if (!OriFuncAddr) return show_err_info("can not get system addr!");

			this->HookFuncPointerArr[i] = MyFunc;

			this->HookOriFuncPointerArr[i] = OriFuncAddr;

			return true;

		}


	}

	return show_err_info("hook arry has no space!");

}

ULONG_PTR EtwHook::ret_tsc_page()
{
	return this->pHvlpReferenceTscPage;
}

DWORD32 EtwHook::ret_build_num()
{
	return this->dwBuildNumer;
}

ULONG_PTR EtwHook::ret_syscall_entry()
{
	return uSystemCall64;
}

unsigned int EtwHook::get_os_build_num()
{
	DWORD32 dwBuildNum=0;
	RTL_OSVERSIONINFOEXW info = { 0 };
	info.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	
	if (NT_SUCCESS(RtlGetVersion((PRTL_OSVERSIONINFOW)&info))) dwBuildNum = info.dwBuildNumber;

	this->dwBuildNumer = dwBuildNum;
	return dwBuildNum;
}

ULONG_PTR EtwHook::is_hook_func(ULONG_PTR uFuncAddr)
{

	for (int i = 0; i < 20; i++) {

		if (this->HookOriFuncPointerArr[i] == uFuncAddr) {

			return HookFuncPointerArr[i];
		}

	}

	//can not find
	return 0;
}

BOOLEAN EtwHook::show_err_info(const char* szStr)
{
	KdPrint(("¡¾EtwHook¡¿:%s\n",szStr));
	return 0;
}

ULONG_PTR EtwHook::get_ntoskrnl_base()
{
	//ULONG_PTR _uNtoskrnlBase = 0;
	const unsigned long tag = 'etw';
	unsigned long length = 0;
	//UNICODE_STRING usNtoskrnl = RTL_CONSTANT_STRING(L"ntoskrnl.exe");

	//use kernel api rather than LDR_DATA_TABLE_ENTRY 
	// and PsLoadedModuleList traversal 
	//it is better suitable for different os version

	//due to kernel Double-Fetch
	//var length is PSYSTEM_MODULE_INFORMATION 
	//size(Variable length arrry)

	ZwQuerySystemInformation(11, &length, 0, &length);
	
	if (!length) return show_err_info("Get system info err!");

	PSYSTEM_MODULE_INFORMATION system_modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, length, tag);
	
	if(!system_modules) return show_err_info("alloc system_info err!");
	
	ZwQuerySystemInformation(11, system_modules, length, 0);

	for (DWORD32 i=0;i<system_modules->ulModuleCount ;i++) {
		PSYSTEM_MODULE mod = &system_modules->Modules[i];
		
		if (strcmp("\\SystemRoot\\system32\\ntoskrnl.exe", mod->ImageName)==0) {
			//find
			uNtoskrnlBase = (ULONG_PTR)mod->Base;
			break;
		}
	}

	ExFreePoolWithTag(system_modules, tag);
	return uNtoskrnlBase;
}

ULONG_PTR EtwHook::get_ckclcontext_addr()
{
	ULONG_PTR EtwpHostSiloState = 0;

	//.text:00000001405A13F9 44 8A 44 24 50                                mov     r8b, [rsp + 48h + arg_0]
	//	.text : 00000001405A13FE 41 8B CE                                      mov     ecx, r14d
	//	.text : 00000001405A1401 48 8B 15 00 9C 75 00                          mov     rdx, cs : EtwpHostSiloState

	CHAR EtwHostStateShellcode[] = { 0x44,0x8A,0x44,0x24,0x50,0x41,0x8B,0xCE,0x48,0x8B,0x15 };
	ULONG_PTR* puEtwpDebuggerDataSilo = 0;



	EtwpHostSiloState = get_EtwpHostSiloState(EtwHostStateShellcode, sizeof(EtwHostStateShellcode));

	if (EtwpHostSiloState == 0) return show_err_info("can not get EtwpHostSiloState addr!");

	puEtwpDebuggerDataSilo = (ULONG_PTR*)*(ULONG_PTR*)(*(ULONG_PTR*)EtwpHostSiloState + 0x1c8);

	if(!MmIsAddressValid((PVOID)puEtwpDebuggerDataSilo)) return show_err_info("can not get EtwpHostSiloState addr!");

	return puEtwpDebuggerDataSilo[2];
}

ULONG_PTR EtwHook::get_EtwpHostSiloState(char* shellcode, int size)
{
	int Max = 0x1000;
	BOOLEAN bFind=0;
	int i = 0;
	DWORD32 dwOffset = 0;
	//.text:00000001405A13F9 44 8A 44 24 50                                mov     r8b, [rsp + 48h + arg_0]
	//	.text : 00000001405A13FE 41 8B CE                                      mov     ecx, r14d
	//	.text : 00000001405A1401 48 8B 15 00 9C 75 00                          mov     rdx, cs : EtwpHostSiloState
	UNICODE_STRING usEtwSendTraceBuffer = RTL_CONSTANT_STRING(L"EtwSendTraceBuffer");
	PCHAR EtwSendTraceBuffer = (PCHAR)MmGetSystemRoutineAddress(&usEtwSendTraceBuffer);

	if (EtwSendTraceBuffer == 0) return show_err_info("can not get EtwSendTraceBuffer addr!");
	
	for (; i < Max; i++) {
		if (RtlCompareMemory((PVOID)(EtwSendTraceBuffer+i), shellcode, size)==size) {
			bFind = 1;
			dwOffset = *(PDWORD32)(EtwSendTraceBuffer + size + i);
			break;
		}

	}
	if (bFind) {
		return (ULONG_PTR)EtwSendTraceBuffer + i + size + 4 + (int)dwOffset;
	}
	else return 0;
}

BOOLEAN EtwHook::get_cpu_clock()
{
	//win7 and win11 cpuclock offset is 0x18 win8 -win10 is 0x28;
	if (!MmIsAddressValid((PVOID)uCkclWmiLoggerContext)) return show_err_info("pCkclContext invalid!");

	if (dwBuildNumer <= 7601 || dwBuildNumer == 22000) CpuClock = (ULONG_PTR)(uCkclWmiLoggerContext + 0x18);
	else CpuClock = (ULONG_PTR)(uCkclWmiLoggerContext + 0x28);
	
	return true;
}

BOOLEAN EtwHook::get_syscall_entry()
{
	//if os enable kpti,need to hde disassmbly
	//if os enbale kpti,section headers contains of "KVASCODE"
	//KiSystemCall64Shadow will jmp to(E9) KiSystemCall64

	const CHAR JMP = (char)0xE9;
	const DWORD32 IA_LSTAR_MSR=0xC0000082;
	int _secsize=0;

	ULONG_PTR uKVASCODE = get_image_addr("KVASCODE",&_secsize);


	uSystemCall64 = __readmsr(IA_LSTAR_MSR);
	if (!uKVASCODE) return true;

	if (uSystemCall64<uKVASCODE || uSystemCall64>uKVASCODE + _secsize) return true;

	
	//enable 
	//need to use disassembly engine
	hde64s hde_info{0};

	for (int i = 0;; i += hde_info.len) {
		
		//end
		if (!hde64_disasm(PVOID(i + uSystemCall64), &hde_info)) break;
		
		if (hde_info.opcode != JMP) continue;


		uSystemCall64 += i + hde_info.len + (int)hde_info.imm.imm32;

		//still in shadow func
		if (uSystemCall64 >= __readmsr(IA_LSTAR_MSR) && uSystemCall64 <= uKVASCODE + _secsize) {
			uSystemCall64 = __readmsr(IA_LSTAR_MSR);
			continue;
		}
		
		return 1;
	
	}

	//can not find!
	return 0;
}

ULONG_PTR EtwHook::get_image_addr(const char* szSectionName,int* size)
{
	

	PIMAGE_DOS_HEADER _doshead = (PIMAGE_DOS_HEADER)uNtoskrnlBase;

	//maybe not correct ntoskrbase
	if (_doshead->e_magic != IMAGE_DOS_SIGNATURE) return show_err_info("not valid pe format!");
	
	PIMAGE_NT_HEADERS _nthead = (PIMAGE_NT_HEADERS)(_doshead->e_lfanew + uNtoskrnlBase);

	if(_nthead->Signature != IMAGE_NT_SIGNATURE) return show_err_info("not valid pe format!");

	PIMAGE_SECTION_HEADER _sectionhead = IMAGE_FIRST_SECTION(_nthead);

	for (int i = 0; i < _nthead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER _cursectionhead = &_sectionhead[i];
		if (_cursectionhead->Name[0]==szSectionName[0] && _cursectionhead->Name[1]== szSectionName[1] && _cursectionhead->Name[2]== szSectionName[2] && _cursectionhead->Name[3]== szSectionName[3]) {
			*size = _cursectionhead->SizeOfRawData;
			return (ULONG_PTR)_cursectionhead->VirtualAddress+(ULONG_PTR)_cursectionhead;

		}
	}
	
	//can not find kvascode

	return 0;
}

ULONG_PTR EtwHook::get_undoc_func_by_shellcode(char* shellcode, int size)
{
	int _size;
	ULONG_PTR uTextSection = get_image_addr(".text", &_size);

	if (!uTextSection) return 0;
	int j = 0;
	for (int i = 0; i < _size;) {
		for (; j < size;) {
			if (shellcode[j] == 0) {
				i++, j++;
				continue;
			}
			if(MmIsAddressValid((PVOID)(uTextSection + i))){
			//Even though in text section there is still some unread mem
			if (shellcode[j] == *(PCHAR)(uTextSection + i)) {
				i++, j++;
				continue;
			}
			}
			
			i = i - j + 1;
			j = 0;

			if (i >= _size) break;
		}
		
		if(j==size) return uTextSection + i - size;


	}

	return 0;
}

NTSTATUS EtwHook::modify_etw_settings(trace_type type)
{
	const unsigned long tag = 'etwm';

	CKCL_TRACE_PROPERTIES* property = (CKCL_TRACE_PROPERTIES*)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, tag);
	if (!property) return STATUS_MEMORY_NOT_ALLOCATED;

	RtlZeroMemory(property,PAGE_SIZE);

	property->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");

	property->Wnode.BufferSize = PAGE_SIZE;
	property->Wnode.Flags = 0x00020000;
	GUID ckcl_session_guid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };
	property->Wnode.Guid = ckcl_session_guid; // It is fixed
	property->Wnode.ClientContext = 3;
	property->BufferSize = sizeof(unsigned long);
	property->MinimumBuffers = 2;
	property->MaximumBuffers = 2;
	property->LogFileMode = 0x00000400;

	
	unsigned long length = 0;
	if (type == trace_type::syscall_trace) property->EnableFlags = 0x00000080;//EVENT_TRACE_FLAG_SYSTEMCALL (0x00000080)
	
	NTSTATUS status = NtTraceControl(type, property, PAGE_SIZE, property, PAGE_SIZE, &length);
	
	ExFreePoolWithTag(property, tag);

	return status;
}

