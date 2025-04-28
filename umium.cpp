/*
 * Copyright 2022 - 2025 | hotline1337
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "umium.hpp"

/*
/* Forcefully terminates the process using multiple methods to ensure it exits immediately.
/* Acts as an emergency kill switch in case of security violations or debugging attempts.
*/
auto umium::trigger() const -> std::void_t<>
{
	while (true)
	{
		PostQuitMessage(0);
		TerminateProcess(GetCurrentProcess(), 0u);
		ExitThread(0ul);
		ExitProcess(0u);
		FatalExit(0);
	}
}

umium::umium() :

/*
/* Initializes security mechanisms.
/* Ensures early protection is active before any potential tampering occurs.
*/
start([this]() -> bool
{
	/* change base image size to prevent memory dumps */
	this->change_image_size();

	/* dispatch threads before patching NtContinue & co. */
	this->dispatch_threads();

	/* patch DbgUiRemoteBreakin, DbgBreakPoint, NtContinue */
	this->patch_debug_functions();

	/* disable LoadLibrary */
	this->disable_loadlibrary();
	return true;
}),

/*
/* Dispatches multiple security monitoring threads to run periodic checks.
/* Continuously validates system integrity and looks for signs of tampering or debugging.
*/
dispatch_threads([this]() -> std::void_t<>
{
	std::thread([&]
	{
		while (true)
		{
			this->check_debuggers();
			this->check_hardware_registers();
			this->check_remote_session();
			this->check_windows();
			this->check_kernel_drivers();
			this->check_blacklisted_modules();
			this->check_test_sign_mode();
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}).detach();
}),

/*
/* Patches critical debug functions in `ntdll.dll` like `DbgUiRemoteBreakin`, `DbgBreakPoint`, and `NtContinue`.
/* Makes it harder for debuggers to attach or manipulate the process by forcing an exit if called.
*/
patch_debug_functions([this]() -> std::void_t<>
{
	const auto ntdll_handle = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll_handle)
		return;

	const FARPROC p_dbg_break_point = GetProcAddress(ntdll_handle, "DbgBreakPoint");
	const FARPROC p_dbg_ui_remote_breakin = GetProcAddress(ntdll_handle, "DbgUiRemoteBreakin");
	if (!p_dbg_break_point || !p_dbg_ui_remote_breakin)
		return;

	const FARPROC exports[] = {
		p_dbg_break_point,
		p_dbg_ui_remote_breakin
	};

	for (const auto& export_address : exports)
	{
		unsigned long old_protection;
		if (!VirtualProtect(reinterpret_cast<void*>(export_address), sizeof(uintptr_t) + 1, PAGE_EXECUTE_READWRITE, &old_protection))
			return;

		*reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(export_address)) = static_cast<uint8_t>(0xE9);
		*reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(export_address) + 1) = reinterpret_cast<uintptr_t>(ExitProcess);

		VirtualProtect(reinterpret_cast<void*>(export_address), sizeof(uintptr_t) + 1, old_protection, &old_protection);
	}
}),

/*
/* Modifies the image size field of the process's PEB loader entry.
/* This obfuscates memory layout information to prevent memory scanners and debuggers.
*/
change_image_size([this]() -> std::void_t<>
{
	const auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
	const auto load_order = static_cast<LIST_ENTRY*>(peb->Ldr->Reserved2[1]);
	const auto table_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(reinterpret_cast<char*>(load_order) - reinterpret_cast<unsigned long long>(&static_cast<LDR_DATA_TABLE_ENTRY*>(nullptr)->Reserved1[0]));
	const auto entry_size = reinterpret_cast<unsigned long*>(&table_entry->Reserved3[1]);
	*entry_size = static_cast<unsigned long>(reinterpret_cast<long long>(table_entry->DllBase) + 0x100000);
}),

/*
/* Disables the ability to load non-Microsoft signed binaries into the process.
/* Increases protection by enforcing stricter binary signature policies at runtime.
*/
disable_loadlibrary([this]() -> std::void_t<>
{
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {};
	policy.MicrosoftSignedOnly = 1;

	SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy));
}),

/*
/* Checks the CPU's debug registers (DR0–DR7) for signs of hardware breakpoints.
/* If any are set, triggers a protection response to prevent debugging or tampering.
*/
check_hardware_registers([this]() -> std::void_t<>
{
	CONTEXT ctx = {};
	void* thread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(thread, &ctx);
	if (ctx.Dr0 != 0x00 || ctx.Dr1 != 0x00 || ctx.Dr2 != 0x00 || ctx.Dr3 != 0x00 || ctx.Dr6 != 0x00 || ctx.Dr7 != 0x00)
	{
		this->trigger();
	}
}),

/*
/* Detects if the process is running inside a remote desktop session.
/* If a remote session is detected, triggers a protection response to avoid remote debugging.
*/
check_remote_session([this]() -> std::void_t<>
{
	const auto session_metrics = GetSystemMetrics(SM_REMOTESESSION);
	if (session_metrics != 0)
	{
		this->trigger();
	}
}),

/*
/* Scans open windows for known debugger or reverse engineering tool signatures.
/* Triggers a security callback if a blacklisted window is detected.
*/
check_windows([this]() -> std::void_t<>
{
	using window_params = std::pair<const wchar_t*, const wchar_t*>;
	static std::vector<window_params> black_listed_windows = {
		{L"ID",				L"Immunity"},
		{L"Qt5QWindowIcon",	L"x64dbg"},
		{L"Qt5QWindowIcon",	L"The Wireshark Network Analyzer"},
		{L"Chrome_WidgetWin_1", L"Fiddler Everywhere"},
		{nullptr, L"Progress Telerik Fiddler Web Debugger"},
		{L"Qt5153QTQWindowIcon", nullptr},
		{L"dbgviewClass", nullptr},
		{L"WinDbgFrameClass", nullptr},
		{L"Zeta Debugger", nullptr},
		{L"Rock Debugger", nullptr},
		{L"ObsidianGUI", nullptr},
		{nullptr, L"IDA v7.0.170914"},
		{nullptr, L"x64dbg"},
		{nullptr, L"IAT Autosearch"},
		{nullptr, L"IDA: Quick start"},
		{nullptr, L"BreakpointsViewClassWindow"},
		{nullptr, L"Detect It Easy v3.10 [Windows 10 Version 2009] (x86_64)"},
		{nullptr, L"CFF Explorer VIII"},
		{nullptr, L"Scylla x64 v0.9.8"},
		{nullptr, L"Binary Ninja Personal 3.3.3996 Personal"},
		{L"Qt661QWindowIcon", L"Binary Ninja Personal 4.0.4958-Stable"}
	};

	for (auto& [first, second] : black_listed_windows)
	{
		if (FindWindowW(first, second))
			this->trigger();
	}
}),

/*
/* Checks if the process is being debugged using several methods, including API calls and direct PEB access.
/* If a debugger is detected, the process will terminate immediately.
*/
check_debuggers([this]() -> std::void_t<>
{
	auto is_dbg_present = FALSE;
	if (IsDebuggerPresent())
	{
		this->trigger();
	}

	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_dbg_present))
	{
		if (is_dbg_present)
		{
			this->trigger();
		}
	}

	const PEB* process_env_block = reinterpret_cast<PEB*>(__readgsqword(0x60));
	if (process_env_block->BeingDebugged)
	{
		this->trigger();
	}
}),

/*
/* Scans loaded modules for known blacklisted libraries commonly used for hooking or debugging.
/* Triggers a security kill if any unauthorized module is found.
*/
check_blacklisted_modules([this]() -> std::void_t<>
{
	const std::vector<std::wstring> blacklisted_modules = {
		L"vehdebug-x86_64.dll",
		L"winhook-x86_64.dll",
		L"luaclient-x86_64.dll",
		L"allochook-x86_64.dll",
		L"HookLibraryx64.dll",
		L"avghookx.dll",
		L"avghooka.dll",
		L"snxhk.dll",
		L"sbiedll.dll",
		L"dbghelp.dll",
		L"api_log.dll",
		L"dir_watch.dll",
		L"pstorec.dll",
		L"vmcheck.dll",
		L"wpespy.dll",
		L"cmdvrt64.dll"
	};

	for (const auto& module : blacklisted_modules)
	{
		if (GetModuleHandleW(module.c_str()))
		{
			this->trigger();
		}
	}
}),

/*
/* Enumerates loaded kernel-mode drivers and checks against a blacklist of known malicious drivers.
/* Helps detect and respond to tampering at the kernel level.
*/
check_kernel_drivers([this]() -> std::void_t<>
{
	std::void_t<>* drivers[1024];
	unsigned long needed;

	if (K32EnumDeviceDrivers(drivers, sizeof(drivers), &needed) && needed < sizeof(drivers))
	{
		wchar_t driver_buffer[1024];
		const std::vector<std::wstring> driver_list = {
			L"kprocesshacker.sys",
			L"SystemInformer.sys",
			L"npf.sys",
			L"HttpDebuggerSdk.sys",
			L"dbk64.sys",
			L"dbk32.sys",
			L"SharpOD_Drv.sys",
			L"SbieSvc.exe"
		};

		const int driver_count = needed / sizeof(drivers[0]);
		for (auto i = 0; i < driver_count; i++)
		{
			if (K32GetDeviceDriverBaseNameW(drivers[i], driver_buffer, std::size(driver_buffer)))
			{
				for (const auto& driver_name : driver_list)
				{
					if (std::wstring_view(driver_buffer) == driver_name)
					{
						this->trigger();
						return;
					}
				}
			}
		}
	}
}),

/*
/* Queries system code integrity information to detect if Test Signing Mode or Debug Mode is enabled.
/* Ensures that only production-signed drivers are active, and triggers security if a violation is found.
*/
check_test_sign_mode([this]() -> std::void_t<>
{
	umium::code_integrity_information sci = {};
	sci.m_size = sizeof(sci);

	/* find syscall */
	const static auto ntdll_handle = GetModuleHandleW(L"ntdll.dll");
	const static auto nt_query_system_information = reinterpret_cast<long(__stdcall*)(unsigned long, void*, unsigned long, unsigned long*)>(GetProcAddress(ntdll_handle, "NtQuerySystemInformation"));

	/* query system information */
	nt_query_system_information(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr);

	if (sci.m_options & CODEINTEGRITY_OPTION_TESTSIGN ||
		sci.m_options & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED ||
		sci.m_options & CODEINTEGRITY_OPTION_TEST_BUILD)
	{
		this->trigger();
	}
}){}