#include <Windows.h>
#include <string>
#include <sstream>
#include <versionhelpers.h>
#include <intrin.h>
#include <wininet.h>
#include <strsafe.h>
#include <iostream>
#include <msclr/marshal_cppstd.h>

#pragma comment(lib,"Wininet.lib")

#include "../import.hpp"
#include "../h/umium.h"
#include "../h/xorstr.h"

#pragma warning(disable : 4838)
#pragma warning(disable : 4309)
#pragma warning(disable : 4312)
#pragma warning(disable : 4311)
#pragma warning(disable : 4302)
#pragma warning(disable : 4715)

typedef DWORD(WINAPI* PFZWSETINFORMATIONTHREAD) (
	HANDLE		ThreadHandle,
	DWORD		ThreadInformationClass,		// Original : _THREAD_INFORMATION_CLASS
	PVOID		ThreadInformation,
	ULONG		ThreadInformationLength
	);
typedef DWORD(WINAPI* PFZWQUERYINFORMATIONPROCESS) (
	HANDLE		ProcessHandle,
	DWORD		ProcessInformationClass,	// Origianl : _PROCESS_INFORMATION_CLASS
	PVOID		ProcessInformation,
	ULONG		ProcessInformationLength,
	PULONG		ReturnLength
	);

namespace umium::security
{	
	std::function<void(void)> ProtectionThread = []()
	{
		while (true) 
		{
			BYTE* overflow = reinterpret_cast<BYTE*>((xorstr_("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")));
			LI_FN(PostQuitMessage)(0);
			LI_FN(TerminateProcess).get()(LI_FN(GetCurrentProcess).get()(), 0);
			LI_FN(PostQuitMessage)(0);
			LI_FN(WriteProcessMemory).get()(LI_FN(GetCurrentProcess).get()(), main, overflow, 1024, nullptr);
			LI_FN(WriteProcessMemory).get()(LI_FN(GetCurrentProcess).get()(), FindWindowA, overflow, 1024, nullptr);
			LI_FN(WriteProcessMemory).get()(LI_FN(GetCurrentProcess).get()(), memcpy, overflow, 1024, nullptr);
			LI_FN(WriteProcessMemory).get()(LI_FN(GetCurrentProcess).get()(), OpenProcess, overflow, 1024, nullptr);
			LI_FN(WriteProcessMemory).get()(LI_FN(GetCurrentProcess).get()(), GetProcAddress, overflow, 1024, nullptr);
			LI_FN(WriteProcessMemory).get()(LI_FN(GetCurrentProcess).get()(), WriteProcessMemory, overflow, 1024, nullptr);
			LI_FN(WriteProcessMemory).get()(LI_FN(GetCurrentProcess).get()(), GetAsyncKeyState, overflow, 1024, nullptr);
		}
	};
	
	std::function<void(void)> find_window = []()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		if (LI_FN(FindWindowA)(nullptr, xorstr_("IDA v7.0.170914")) || LI_FN(FindWindowA)(nullptr, xorstr_("x64dbg")) || LI_FN(FindWindowA)(nullptr, xorstr_("Scylla x64 v0.9.8")) || LI_FN(FindWindowA)(nullptr, xorstr_("IAT Autosearch")))
		{
			ProtectionThread();
		}
	};

	std::function<void(void)> is_debugger_present = []()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		auto is_dbg_present = FALSE;
		if (LI_FN(IsDebuggerPresent).get()())
		{
			ProtectionThread();
		}
		if (LI_FN(CheckRemoteDebuggerPresent).get()(LI_FN(GetCurrentProcess).get()(), &is_dbg_present))
		{
			if (is_dbg_present)
			{
				ProtectionThread();
			}
		}
	};

	std::function<void(void)> anti_attach = []()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		HMODULE h_ntdll = LI_FN(GetModuleHandleA).get()(xorstr_("ntdll.dll"));
		if (!h_ntdll)
			return;

		FARPROC p_dbg_break_point = LI_FN(GetProcAddress).get()(h_ntdll, xorstr_("DbgBreakPoint"));
		if (!p_dbg_break_point)
			return;

		DWORD dw_old_protect;
		if (!LI_FN(VirtualProtect).get()(p_dbg_break_point, 1, PAGE_EXECUTE_READWRITE, &dw_old_protect))
			return;

		*reinterpret_cast<PBYTE>(p_dbg_break_point) = static_cast<BYTE>(0xC3); // 0xC3 == RET
	};
	
	std::function<void(void)> is_memory_traversed = []()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		const auto m = LI_FN(VirtualAlloc).get()(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		PSAPI_WORKING_SET_EX_INFORMATION set;
		set.VirtualAddress = m;

		while (true)
		{
			if (LI_FN(K32QueryWorkingSetEx).get()(LI_FN(GetCurrentProcess).get()(), &set, sizeof(set)) && (set.VirtualAttributes.Valid & 0x1))
			{
				ProtectionThread();
			}
		}
	};

	std::function<int(void)> check_remote_session = []()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		const auto session_metrics = LI_FN(GetSystemMetrics).get()(SM_REMOTESESSION);
		return session_metrics != 0;
	};

	std::function<int(void)> check_window_name = []()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		if (LI_FN(FindWindowA)(xorstr_("Qt5QWindowIcon"), nullptr) || LI_FN(FindWindowA)(xorstr_("x64dbg"), nullptr) || LI_FN(FindWindowA)(xorstr_("SunAwtFrame"), nullptr) || LI_FN(FindWindowA)(xorstr_("ID"), nullptr))
		{
			return 0x1005;
		}
		return 0;
	};

	std::function<int(void)> check_sandboxie = []()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		if (LI_FN(GetModuleHandleA).get()(xorstr_("SbieDll.dll")))
		{
			return 0x600;
		}
		return 0;
	};
	
	std::function<int(void)> check_kernel_drivers = []()
	{
		LPVOID drivers[1024];
		DWORD cb_needed;

		if (LI_FN(K32EnumDeviceDrivers).get()(drivers, sizeof(drivers), &cb_needed) && cb_needed < sizeof(drivers))
		{
			wchar_t szDriver[1024];
			const wchar_t* bl_driver_list[] = { L"kprocesshacker.sys", L"SbieSvc.sys", L"HttpDebuggerSdk.sys", L"dbk64.sys",
			L"dbk32.sys", L"SharpOD_Drv.sys" }; /* unicode anyways */

			const int c_drivers = cb_needed / sizeof(drivers[0]);

			for (auto i = 0; i < c_drivers; i++)
			{
				if (LI_FN(K32GetDeviceDriverBaseNameW).get()(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
				{
					for (const auto* driver_name : bl_driver_list)
					{
						if (wcscmp(szDriver, driver_name) == 0) 
						{
							std::wstring ws(driver_name);
							std::string str(ws.begin(), ws.end());
							std::string output = xorstr_("Detected blacklisted driver loaded (") + str + xorstr_("). Please unload it from memory.");

							LI_FN(MessageBoxA)(nullptr, output.c_str(), xorstr_("umium"), MB_ICONERROR | MB_OK);
							return 0x4171;
						}
					}
				}
			}
		}
		return 0;
	};

	std::function<int(void)> check_titan_hide = []()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		const auto module = LI_FN(GetModuleHandleA).get()(xorstr_("ntdll.dll"));

		const auto information = reinterpret_cast<typedefs::NtQuerySystemInformationTypedef>(LI_FN(GetProcAddress).get()(
			module, xorstr_("NtQuerySystemInformation")));

		typedefs::SYSTEM_CODEINTEGRITY_INFORMATION sci;

		sci.Length = sizeof sci;

		information(typedefs::SystemCodeIntegrityInformation, &sci, sizeof sci, nullptr);

		const auto ret = sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN || sci.CodeIntegrityOptions &
			CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;

		if (ret != 0)
			return 1;

		return 0;
	};

	int __stdcall check_dbg_print()
	{
		const auto xor_buffer = xorstr_("xor-buffer");
		__try
		{
			LI_FN(RaiseException).get()(DBG_PRINTEXCEPTION_C, 0, 0, nullptr);
		}
		__except (_exception_code() == DBG_PRINTEXCEPTION_C)
		{
			return 1;
		}

		return 0;
	}

	__forceinline std::void_t<> check_guard_hook()
	{
		MEMORY_BASIC_INFORMATION memory_info;
		PEB* peb = (PEB*)__readgsqword(0x60);

		LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;
		LIST_ENTRY curr = head;
		for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
		{
			LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (mod->FullDllName.Buffer)
			{
				auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(mod->DllBase) + static_cast<PIMAGE_DOS_HEADER>(mod->DllBase)->e_lfanew);
				auto* sections = IMAGE_FIRST_SECTION(headers);

				for (auto i = 0; i <= headers->FileHeader.NumberOfSections; i++)
				{
					auto* section = &sections[i];

					auto virtualAddress = static_cast<PBYTE>(mod->DllBase) + section->VirtualAddress;

					if (LI_FN(VirtualQuery).get()(virtualAddress, &memory_info, sizeof(MEMORY_BASIC_INFORMATION)))
					{
						if (memory_info.State == MEM_COMMIT && (memory_info.Protect & PAGE_GUARD))
							ProtectionThread();
					}
				}
			}
		}
	}
}
