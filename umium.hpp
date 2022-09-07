#ifndef UMIUM_HPP
#define UMIUM_HPP

#pragma region UMIUM_INCLUDES
#include <Windows.h>
#include <functional>
#include <intrin.h>
#include <strsafe.h>
#include <msclr/marshal_cppstd.h>
#pragma endregion UMIUM_INCLUDES

#pragma region UMIUM_WARNINGS
#pragma warning(disable : 4838)
#pragma warning(disable : 4309)
#pragma warning(disable : 4312)
#pragma warning(disable : 4311)
#pragma warning(disable : 4302)
#pragma warning(disable : 4715)
#pragma endregion UMIUM_WARNINGS

#ifndef UMIUM_NO_FORCEINLINE
#if defined(_MSC_VER)
#define UMIUM_FORCEINLINE __forceinline
#elif defined(__GNUC__) && __GNUC__ > 3
#define UMIUM_FORCEINLINE inline __attribute__((__always_inline__))
#else
#define UMIUM_FORCEINLINE inline
#endif
#else
#define UMIUM_FORCEINLINE inline
#endif

namespace umium
{	
	namespace typedefs
	{
		using NtQuerySystemInformationTypedef = NTSTATUS(*)(ULONG, PVOID, ULONG, PULONG);

		typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
		{
			ULONG Length;
			ULONG CodeIntegrityOptions;
		} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

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
	namespace utils
	{
		UMIUM_FORCEINLINE const PEB* get_peb() noexcept
		{
			#if defined(_M_X64) || defined(__amd64__)
        		return reinterpret_cast<const PEB*>(__readgsqword(0x60));
			#elif defined(_M_IX86) || defined(__i386__)
        		return reinterpret_cast<const PEB*>(__readfsdword(0x30));
			#elif defined(_M_ARM) || defined(__arm__)
        		return *reinterpret_cast<const PEB**>(_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
			#elif defined(_M_ARM64) || defined(__aarch64__)
       	 		return *reinterpret_cast<const PEB**>(__getReg(18) + 0x60);
			#elif defined(_M_IA64) || defined(__ia64__)
        		return *reinterpret_cast<const PEB**>(static_cast<char*>(_rdteb()) + 0x60);
			#else
				#error Unsupported platform.
			#endif
		}
	}
	namespace security
	{
		std::function<void(void)> ProtectionThread = []()
		{
			while (true) 
			{
				BYTE* overflow = reinterpret_cast<BYTE*>("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
				PostQuitMessage(0);
				TerminateProcess(GetCurrentProcess(), 0);
				PostQuitMessage(0);
				WriteProcessMemory(GetCurrentProcess(), main, overflow, 1024, nullptr);
				WriteProcessMemory(GetCurrentProcess(), FindWindowA, overflow, 1024, nullptr);
				WriteProcessMemory(GetCurrentProcess(), memcpy, overflow, 1024, nullptr);
				WriteProcessMemory(GetCurrentProcess(), OpenProcess, overflow, 1024, nullptr);
				WriteProcessMemory(GetCurrentProcess(), GetProcAddress, overflow, 1024, nullptr);
				WriteProcessMemory(GetCurrentProcess(), WriteProcessMemory, overflow, 1024, nullptr);
				WriteProcessMemory(GetCurrentProcess(), GetAsyncKeyState, overflow, 1024, nullptr);
			}
		};
	
		std::function<void(void)> find_window = []()
		{
			if (FindWindowA(nullptr, "IDA v7.0.170914") || FindWindowA(nullptr, "x64dbg") || FindWindowA(nullptr, "Scylla x64 v0.9.8") || FindWindowA(nullptr, "IAT Autosearch"))
			{
				ProtectionThread();
			}
		};

		std::function<void(void)> is_debugger_present = []()
		{
			auto is_dbg_present = FALSE;
			if (sDebuggerPresent())
			{
				ProtectionThread();
			}
			if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_dbg_present))
			{
				if (is_dbg_present)
				{
					ProtectionThread();
				}
		};

		std::function<void(void)> anti_attach = []()
		{
			HMODULE h_ntdll = GetModuleHandleA("ntdll.dll");
			if (!h_ntdll)
				return;

			FARPROC p_dbg_break_point = GetProcAddress(h_ntdll, "DbgBreakPoint");
			if (!p_dbg_break_point)
				return;

			DWORD dw_old_protect;
			if (!VirtualProtect(p_dbg_break_point, 1, PAGE_EXECUTE_READWRITE, &dw_old_protect))
			return;

			*reinterpret_cast<PBYTE>(p_dbg_break_point) = static_cast<BYTE>(0xC3); // 0xC3 == RET
		};
	
		std::function<void(void)> is_memory_traversed = []()
		{
			const auto m = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

			PSAPI_WORKING_SET_EX_INFORMATION set;
			set.VirtualAddress = m;

			if (K32QueryWorkingSetEx(GetCurrentProcess(), &set, sizeof(set)) && (set.VirtualAttributes.Valid & 0x1))
			{
				ProtectionThread();
			}
		};

		std::function<int(void)> check_remote_session = []()
		{
			const auto session_metrics = GetSystemMetrics(SM_REMOTESESSION);
			return session_metrics != 0;
		};

		std::function<int(void)> check_window_name = []()
		{
			if (FindWindowA("Qt5QWindowIcon", nullptr) || FindWindowA("x64dbg", nullptr) || FindWindowA("SunAwtFrame", nullptr) || FindWindowA("ID", nullptr))
			{
				return 1;
			}
			return 0;
		};

		std::function<int(void)> check_sandboxie = []()
		{
			if (GetModuleHandleA("SbieDll.dll"))
			{
				return 1;
			}
			return 0;
		};
	
		std::function<int(void)> check_kernel_drivers = []()
		{
			LPVOID drivers[1024];
			DWORD cb_needed;

			if (K32EnumDeviceDrivers(drivers, sizeof(drivers), &cb_needed) && cb_needed < sizeof(drivers))
			{
				wchar_t szDriver[1024];
				const wchar_t* bl_driver_list[] = { L"kprocesshacker.sys", L"SbieSvc.sys", L"HttpDebuggerSdk.sys", L"dbk64.sys",
				L"dbk32.sys", L"SharpOD_Drv.sys" }; /* unicode anyways */

				const int c_drivers = cb_needed / sizeof(drivers[0]);

				for (auto i = 0; i < c_drivers; i++)
				{
					if (K32GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
					{
						for (const auto* driver_name : bl_driver_list)
						{
							if (wcscmp(szDriver, driver_name) == 0) 
							{
								std::wstring ws(driver_name);
								std::string str(ws.begin(), ws.end());
								std::string output = "Detected blacklisted driver loaded (" + str + "). Please unload it from memory.";

								MessageBoxA(nullptr, output.c_str(), "umium", MB_ICONERROR | MB_OK);
								return 1;
							}
						}
					}
				}
			}
			return 0;
		};

		std::function<int(void)> check_titan_hide = []()
		{
			const auto module = GetModuleHandleA("ntdll.dll");
			const auto information = reinterpret_cast<typedefs::NtQuerySystemInformationTypedef>(GetProcAddress(module, "NtQuerySystemInformation"));

			typedefs::SYSTEM_CODEINTEGRITY_INFORMATION sci;
			sci.Length = sizeof sci;

			information(typedefs::SystemCodeIntegrityInformation, &sci, sizeof sci, nullptr);

			const auto ret = sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN || sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;

			if (ret != 0)
				return 1;

			return 0;
		};

		std::function<int(void)> check_dbg_print = []()
		{
			__try
			{
				RaiseException(DBG_PRINTEXCEPTION_C, 0, 0, nullptr);
			}
			__except (_exception_code() == DBG_PRINTEXCEPTION_C)
			{
				return 1;
			}

			return 0;
		};

		std::function<int(void)> check_guard_hook = []()
		{
			MEMORY_BASIC_INFORMATION memory_info;
			PEB* peb = utils::get_peb();

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

						if (VirtualQuery(virtualAddress, &memory_info, sizeof(MEMORY_BASIC_INFORMATION)))
						{
							if (memory_info.State == MEM_COMMIT && (memory_info.Protect & PAGE_GUARD))
								return 1;
						}
					}
				}
			}
			return 0;
		};
	}
}

#endif /* include guard */
