#pragma once
#include <functional>
#include <Windows.h>

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);

namespace typedefs
{
	using NtQuerySystemInformationTypedef = NTSTATUS(*)(ULONG, PVOID, ULONG, PULONG);

	typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
	{
		ULONG   Length;
		ULONG   CodeIntegrityOptions;
	} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation = 0,
		SystemPerformanceInformation = 2,
		SystemTimeOfDayInformation = 3,
		SystemProcessInformation = 5,
		SystemProcessorPerformanceInformation = 8,
		SystemInterruptInformation = 23,
		SystemExceptionInformation = 33,
		SystemRegistryQuotaInformation = 37,
		SystemLookasideInformation = 45,
		SystemCodeIntegrityInformation = 103,
		SystemPolicyInformation = 134,
	} SYSTEM_INFORMATION_CLASS;
}

namespace umium::security
{
	extern auto block_api(const char* libName, const char* apiName)->DWORD;
	
	extern std::function<void(void)> ProtectionThread;
	extern std::function<void(void)> find_window;
	extern std::function<void(void)> anti_attach;
	extern std::function<void(void)> is_memory_traversed;
	extern std::function<void(void)> is_debugger_present;

	extern std::function<int(void)> check_remote_session;
	extern std::function<int(void)> close_handle_exception;
	extern std::function<int(void)> check_window_name;
	extern std::function<int(void)> check_sandboxie;
	extern std::function<int(void)> check_titan_hide;
	extern std::function<int(void)> check_kernel_drivers;
	
	extern int __stdcall check_dbg_print();
	//extern std::function<int(void)> check_dbg_print();
}
