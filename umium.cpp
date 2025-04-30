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

umium::umium() :

 /*
  * Initializes security mechanisms.
  * Ensures early protection is active before any potential tampering occurs.
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

	/* erase pe header */
	this->erase_pe_header();
	return true;
}),

/*
 * Forcefully terminates the process using multiple methods to ensure it exits immediately.
 * Acts as an emergency kill switch in case of security violations or debugging attempts.
 */
trigger([this]() -> std::void_t<>
{
	static const auto rtl_raise_status = reinterpret_cast<void(*)(long)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlRaiseStatus"));
	static const auto nt_terminate_process = reinterpret_cast<long(*)(void*, long)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess"));
	while (true)
	{
		*reinterpret_cast<uintptr_t*>(0xFFFFFFFFFFFFFFFFull) = 0xFFFFFFFFFFFFFFFFull;
		rtl_raise_status(static_cast<long>(0xFFFFFFFFFFFFFFFFull));
		nt_terminate_process(GetCurrentProcess(), static_cast<long>(0xFFFFFFFFFFFFFFFFull));
		abort();
		terminate();
		PostQuitMessage(0);
		TerminateProcess(GetCurrentProcess(), 0u);
		ExitThread(0ul);
		ExitProcess(0u);
		FatalExit(0);
		DebugBreak();
	}
}),

/*
 * Dispatches multiple security monitoring threads to run periodic checks.
 * Continuously validates system integrity and looks for signs of tampering or debugging.
 */
dispatch_threads([this]() -> std::void_t<>
{
	std::thread([this]
	{
		static const auto nt_set_information_thread = reinterpret_cast<long(*)(void*, unsigned int, void*, unsigned long)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"));
		nt_set_information_thread(GetCurrentThread(), 0x11u, nullptr, 0);

		while (true)
		{
			this->check_debuggers();
			this->check_hardware_registers();
			this->check_remote_session();
			this->check_windows();
			this->check_kernel_drivers();
			this->check_blacklisted_modules();
			this->check_hidden_thread();
			this->check_process_job();
			this->check_csr();
			this->check_local_size();
			this->check_test_sign_mode();
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}).detach();
}),

/*
 * Patches critical debug functions in `ntdll.dll` like `DbgUiRemoteBreakin`, `DbgBreakPoint`.
 * Makes it harder for debuggers to attach or manipulate the process by forcing an exit if called.
 */
patch_debug_functions([this]() -> std::void_t<>
{
	const FARPROC p_dbg_break_point = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "DbgBreakPoint");
	const FARPROC p_dbg_ui_remote_breakin = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "DbgUiRemoteBreakin");
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
 * Modifies the image size field of the process's PEB loader entry.
 * This obfuscates memory layout information to prevent memory scanners and debuggers.
 */
change_image_size([this]() -> std::void_t<>
{
	const auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
	const auto load_order = static_cast<LIST_ENTRY*>(peb->Ldr->Reserved2[1]);
	const auto table_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(reinterpret_cast<char*>(load_order) - reinterpret_cast<uintptr_t>(&static_cast<LDR_DATA_TABLE_ENTRY*>(nullptr)->Reserved1[0]));
	const auto entry_size = reinterpret_cast<unsigned long*>(&table_entry->Reserved3[1]);
	*entry_size = static_cast<unsigned long>(reinterpret_cast<int64_t>(table_entry->DllBase) + 0x100000);
}),

/*
 * Disables the ability to load non-Microsoft signed binaries into the process.
 * Increases protection by enforcing stricter binary signature policies at runtime.
 */
disable_loadlibrary([this]() -> std::void_t<>
{
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {};
	policy.MicrosoftSignedOnly = 1;

	SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy));
}),

/*
 * Erases the PE (Portable Executable) headers of the current process from memory.
 * Helps to hinder memory dumping and reverse engineering by removing key metadata from the loaded module.
 */
erase_pe_header([this]() -> std::void_t<>
{
	const auto base_address = GetModuleHandleW(nullptr);
	if (!base_address)
		return;

	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint8_t*>(base_address) + dos_header->e_lfanew);
	const auto nt_headers_size = nt_headers->OptionalHeader.SizeOfHeaders;
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return;

	unsigned long old_protection;
	if (VirtualProtect(base_address, nt_headers_size, PAGE_EXECUTE_READWRITE, &old_protection))
	{
		RtlSecureZeroMemory(base_address, nt_headers_size);
		VirtualProtect(base_address, nt_headers_size, old_protection, &old_protection);
	}
}),

/*
 * Checks the CPU's debug registers (DR0–DR7) for signs of hardware breakpoints.
 * If any are set, triggers a protection response to prevent debugging or tampering.
 */
check_hardware_registers([this]() -> std::void_t<>
{
	CONTEXT ctx = {};
	auto* thread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(thread, &ctx);
	if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr6 || ctx.Dr7)
	{
		this->trigger();
	}
}),

/*
 * Detects if the process is running inside a remote desktop session.
 * If a remote session is detected, triggers a protection response to avoid remote debugging.
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
 * Scans open windows for known debugger or reverse engineering tool signatures.
 * Triggers a security callback if a blacklisted window is detected.
 */
check_windows([this]() -> std::void_t<>
{
	using window_params = std::pair<const wchar_t*, const wchar_t*>;
	static std::vector<window_params> black_listed_windows = {
		{L"ID", L"Immunity"},
		{L"Qt5QWindowIcon", L"x64dbg"},
		{L"Qt5QWindowIcon", L"The Wireshark Network Analyzer"},
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
 * Checks if the process is being debugged using several methods, including API calls and direct PEB access.
 * If a debugger is detected, the process will terminate immediately.
 */
check_debuggers([this]() -> std::void_t<>
{
	if (IsDebuggerPresent())
	{
		this->trigger();
	}

	auto is_dbg_present = FALSE;
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
 * Scans loaded modules for known blacklisted libraries commonly used for hooking or debugging.
 * Triggers a security kill if any unauthorized module is found.
 */
check_blacklisted_modules([this]() -> std::void_t<>
{
	HMODULE modules[0x400] = {};
	unsigned long needed;
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

	if (K32EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) 
	{
		for (auto i = 0ull; i < needed / sizeof(HMODULE); i++) 
		{
			wchar_t module_name[MAX_PATH];
			if (K32GetModuleFileNameExW(GetCurrentProcess(), modules[i], module_name, MAX_PATH)) 
			{
				for (const auto& module : blacklisted_modules)
				{
					if (std::wstring_view(module_name).contains(module))
					{
						this->trigger();
					}
				}
			}
		}
	}
}),

/*
 * Enumerates loaded kernel-mode drivers and checks against a blacklist of known malicious drivers.
 * Helps detect and respond to tampering at the kernel level.
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
			L"SbieSvc.exe",
			L"TitanHide.sys"
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
					}
				}
			}
		}
	}
}),

/*
 * Detects attempts to hide the current thread from debuggers using NtSetInformationThread and NtQueryInformationThread.
 * Triggers a security response if thread hiding is possible or inconsistencies in thread info are detected.
 */
check_hidden_thread([this]() -> std::void_t<>
{
	struct aligned_bool
	{
		alignas(4) bool value;
	};

	static const auto nt_set_information_thread = reinterpret_cast<long(*)(void*, unsigned int, void*, unsigned long)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"));
	static const auto nt_query_information_thread = reinterpret_cast<long(*)(void*, unsigned int, void*, unsigned long, unsigned long*)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));

	aligned_bool is_thread_hidden;
	is_thread_hidden.value = false;

	long status = nt_set_information_thread(GetCurrentThread(), 0x11u, &is_thread_hidden, 12345);
	if (status == 0)
		this->trigger();

	status = nt_set_information_thread(reinterpret_cast<void*>(0xFFFF), 0x11u, nullptr, 0);
	if (status == 0)
		this->trigger();

	status = nt_set_information_thread(GetCurrentThread(), 0x11u, nullptr, 0);

	if (status == 0)
	{
		status = nt_query_information_thread(GetCurrentThread(), 0x11u, &is_thread_hidden.value, sizeof(bool), nullptr);
		if (status == 0xC0000004ul)
			this->trigger();

		if (status == 0)
		{
			aligned_bool bogus_is_thread_hidden;
			bogus_is_thread_hidden.value = false;

			status = nt_query_information_thread(GetCurrentThread(), 0x11u, &bogus_is_thread_hidden.value, sizeof(int), nullptr);
			if (status != 0xC0000004ul)
				this->trigger();

			constexpr size_t unaligned_check_count = 8;
			bool bogus_unaligned_values[unaligned_check_count];
			int alignment_error_count = 0;

			constexpr size_t max_alignment_check_success_count = 2;
			for (bool& bogus_unaligned_value : bogus_unaligned_values)
			{
				status = nt_query_information_thread(GetCurrentThread(), 0x11u, &bogus_unaligned_value, sizeof(int), nullptr);
				if (status == 0x80000002ul)
				{
					alignment_error_count++;
				}
			}
			
			if (unaligned_check_count - max_alignment_check_success_count > alignment_error_count)
				this->trigger();

			if (!is_thread_hidden.value)
				this->trigger();
		}
	}
	else
	{
		this->trigger();
	}
}),

/*
 * Verifies the current process's job object to detect suspicious process inclusion.
 * This check is useful for detecting sandbox environments or job-based process manipulation.
 */
check_process_job([this]() -> std::void_t<>
{
	auto job_found = FALSE;
	constexpr unsigned long job_process_struct_size = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(uintptr_t) * 0x400;

	std::vector<std::byte> job_process_buffer(job_process_struct_size, std::byte{});
	if (auto* job_process_id_list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(job_process_buffer.data()))
	{
		job_process_id_list->NumberOfProcessIdsInList = 0x400ul;

		if (QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, job_process_id_list, static_cast<unsigned long>(job_process_buffer.size()), nullptr))
		{
			auto whitelisted_processes = 0;
			for (auto i = 0ul; i < job_process_id_list->NumberOfAssignedProcesses; i++)
			{
				if (const uintptr_t process_id = job_process_id_list->ProcessIdList[i]; process_id == static_cast<uintptr_t>(GetCurrentProcessId()))
				{
					whitelisted_processes++;
				}
				else
				{
					if (auto job_process_handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)>(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, static_cast<unsigned long>(process_id)), CloseHandle))
					{
						std::vector<wchar_t> process_name(0x1000);
						if (K32GetProcessImageFileNameW(job_process_handle.get(), process_name.data(), static_cast<unsigned long>(process_name.size())) > 0)
						{
							if (std::wstring pn_str(process_name.data()); pn_str.contains(L"\\Windows\\System32\\conhost.exe"))
							{
								whitelisted_processes++;
							}
						}
					}
				}
			}
			job_found = static_cast<unsigned long>(whitelisted_processes) != job_process_id_list->NumberOfAssignedProcesses;
		}
	}

	if (job_found)
		this->trigger();
}),

check_csr([this]() -> std::void_t<>
{
	static const auto csr_get_process_id = reinterpret_cast<void*(*)()>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrGetProcessId"));
	if (!csr_get_process_id)
		return;

	const auto handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)>(OpenProcess(PROCESS_ALL_ACCESS, FALSE, reinterpret_cast<unsigned long>(csr_get_process_id())), CloseHandle);
	if (!handle.get())
	{
		this->trigger();
	}
}),

/*
 * Repeatedly calls LocalSize on a null pointer to detect unusual behavior or potential heap manipulation.
 * The function is meant to observe how the system responds to invalid memory queries.
 */
 check_local_size([this]() -> std::void_t<>
 {
	 uintptr_t buffer;
	 for (auto i = 0u; i < INFINITE; i++)
	 {
		 buffer = LocalSize(nullptr);
	 }
}),

/*
 * Queries system code integrity information to detect if Test Signing Mode or Debug Mode is enabled.
 * Ensures that only production-signed drivers are active, and triggers security if a violation is found.
 */
check_test_sign_mode([this]() -> std::void_t<>
{
	umium::code_integrity_information sci = {};
	sci.m_size = sizeof(sci);

	static const auto nt_query_system_information = reinterpret_cast<long(*)(unsigned long, void*, unsigned long, unsigned long*)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));

	nt_query_system_information(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr);
	if (sci.m_options & CODEINTEGRITY_OPTION_TESTSIGN ||
		sci.m_options & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED ||
		sci.m_options & CODEINTEGRITY_OPTION_TEST_BUILD)
	{
		this->trigger();
	}
}){}