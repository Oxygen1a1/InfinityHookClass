#pragma once

#pragma warning(disable : 4210)

typedef NTSTATUS(*FNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

typedef enum _trace_type
{
	start_trace = 1,
	stop_trace = 2,
	query_trace = 3,
	syscall_trace = 4,
	flush_trace = 5
}trace_type;




class EtwHook {
private:
	
	ULONG_PTR uCkclWmiLoggerContext;
	ULONG_PTR uNtoskrnlBase;
	DWORD32 dwBuildNumer;
	ULONG_PTR CpuClock;/*In win7-win8 It is a pointer. In win10-win11 It is a num */
	ULONG_PTR uSystemCall64;
	ULONG_PTR pHvlGetQpcBias;//dwBuildNumber>18363
	ULONG_PTR pHvlpReferenceTscPage;//table for pHvlGetQpcBias
	ULONG_PTR HvlGetQpcBias;//saved for hook
	ULONG_PTR OriCpuClock;//for >18363
	ULONG_PTR HookOriFuncPointerArr[20];// maxinum to hook 10 syscall func
	ULONG_PTR HookFuncPointerArr[20];
public:
	BOOLEAN init();
	BOOLEAN start();
	void stop();
	BOOLEAN add_hook(PUNICODE_STRING usHookFuncName,ULONG_PTR MyFunc);
	ULONG_PTR is_hook_func(ULONG_PTR);
	ULONG_PTR ret_tsc_page();
	DWORD32 ret_build_num();
	ULONG_PTR ret_syscall_entry();
	unsigned int get_os_build_num();
	BOOLEAN show_err_info(const char* szStr);
	ULONG_PTR get_ntoskrnl_base();
	ULONG_PTR get_ckclcontext_addr();
	ULONG_PTR get_EtwpHostSiloState(char * shellcode,int size);
	BOOLEAN get_cpu_clock();
	BOOLEAN get_syscall_entry();
	ULONG_PTR get_image_addr(const char* szSectionName,int *);
	ULONG_PTR get_undoc_func_by_shellcode(char* shellcode, int size);
	NTSTATUS modify_etw_settings(trace_type type);
};