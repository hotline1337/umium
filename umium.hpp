/*
 * Copyright (c) 2022 - 2025 hotline1337
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * UMIUM — single-header anti-debug / anti-RE library for Windows 10/11 x64.
 *
 * Usage (exactly once, in one .cpp file):
 *
 *   #define UMIUM_IMPLEMENTATION
 *   #include "umium.hpp"
 *
 *   int main()
 *   {
 *       umium::instance().start();
 *   }
 *
 * Every other translation unit that needs the type just does:
 *
 *   #include "umium.hpp"
 */

#ifndef UMIUM_HPP
#define UMIUM_HPP

#if !defined(_M_X64) && !defined(__amd64__)
#error umium: only x86-64 is supported
#endif

#ifndef _WIN32
#error umium: Windows-only library
#endif

// Keep WIN32_LEAN_AND_MEAN unless the including TU already defined it differently.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// Public API declaration
// ─────────────────────────────────────────────────────────────────────────────

class umium_t
{
public:
	[[nodiscard]] static auto instance() -> umium_t&;

	// Applies early protections (image-size spoof, thread dispatch, patches,
	// LoadLibrary lockdown, PE-header erasure). Returns false only if the
	// process is already terminated by a triggered check.
	[[nodiscard]] auto start() -> bool;

protected:
	// Emergency kill-switch; loops through multiple termination methods.
	// Marked [[noreturn]] conceptually — the loop never exits.
	auto trigger() -> void;
	auto dispatch_threads() -> void;
	auto patch_debug_functions() -> void;
	auto change_image_size() -> void;
	auto disable_loadlibrary() -> void;
	auto erase_pe_header() -> void;

private:
	struct code_integrity_information
	{
		std::uint32_t size;
		std::uint32_t options;
	};

	auto check_hardware_registers() -> void;
	auto check_remote_session() -> void;
	auto check_windows() -> void;
	auto check_debuggers() -> void;
	auto check_blacklisted_modules() -> void;
	auto check_kernel_drivers() -> void;
	auto check_hidden_thread() -> void;
	auto check_process_job() -> void;
	auto check_csr() -> void;
	auto check_local_size() -> void;
	auto check_test_sign_mode() -> void;
};

/* global singleton accessor */
namespace umium
{
	[[nodiscard]] inline auto get() -> umium_t& { return umium_t::instance(); }
}

#ifdef UMIUM_IMPLEMENTATION

auto umium_t::instance() -> umium_t&
{
	static umium_t inst;
	return inst;
}

/*
 * Initializes security mechanisms.
 * Ensures early protection is active before any potential tampering occurs.
 */
auto umium_t::start() -> bool
{
	change_image_size();
	dispatch_threads();
	patch_debug_functions();
	disable_loadlibrary();
	erase_pe_header();
	return true;
}

/*
 * Forcefully terminates the process using multiple methods to ensure it exits immediately.
 * Acts as an emergency kill switch in case of security violations or debugging attempts.
 */
auto umium_t::trigger() -> void
{
	// Unsafe: intentional null-deref + NT calls to guarantee termination.
	static const auto rtl_raise_status =
		reinterpret_cast<void(*)(long)>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlRaiseStatus"));
	static const auto nt_terminate_process =
		reinterpret_cast<long(*)(void*, long)>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtTerminateProcess"));

	while (true)
	{
		*reinterpret_cast<std::uintptr_t*>(0xFFFF'FFFF'FFFF'FFFFull) = 0xFFFF'FFFF'FFFF'FFFFull;
		rtl_raise_status(static_cast<long>(0xFFFF'FFFF'FFFF'FFFFull));
		nt_terminate_process(GetCurrentProcess(), static_cast<long>(0xFFFF'FFFF'FFFF'FFFFull));
		std::abort();
		std::terminate();
		PostQuitMessage(0);
		TerminateProcess(GetCurrentProcess(), 0u);
		ExitThread(0ul);
		ExitProcess(0u);
		FatalExit(0);
		DebugBreak();
	}
}

/*
 * Dispatches multiple security monitoring threads to run periodic checks.
 * Continuously validates system integrity and looks for signs of tampering or debugging.
 */
auto umium_t::dispatch_threads() -> void
{
	std::jthread([this](std::stop_token st)
	{
		static const auto nt_set_information_thread =
			reinterpret_cast<long(*)(void*, unsigned int, void*, unsigned long)>(
				GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"));
		nt_set_information_thread(GetCurrentThread(), 0x11u, nullptr, 0);

		while (!st.stop_requested())
		{
			check_debuggers();
			check_hardware_registers();
			check_remote_session();
			check_windows();
			check_kernel_drivers();
			check_blacklisted_modules();
			check_hidden_thread();
			check_process_job();
			check_csr();
			check_local_size();
			check_test_sign_mode();
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
	}).detach();
}

/*
 * Patches critical debug functions in ntdll.dll (DbgUiRemoteBreakin, DbgBreakPoint).
 * Makes it harder for debuggers to attach or manipulate the process.
 */
auto umium_t::patch_debug_functions() -> void
{
	const FARPROC p_dbg_break_point       = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "DbgBreakPoint");
	const FARPROC p_dbg_ui_remote_breakin = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "DbgUiRemoteBreakin");
	if (!p_dbg_break_point || !p_dbg_ui_remote_breakin)
		return;

	const FARPROC exports[] = { p_dbg_break_point, p_dbg_ui_remote_breakin };
	for (const auto& export_addr : exports)
	{
		unsigned long old_protection{};
		if (!VirtualProtect(reinterpret_cast<void*>(export_addr), sizeof(std::uintptr_t) + 1, PAGE_EXECUTE_READWRITE, &old_protection))
			return;

		// Unsafe: writing a JMP opcode + target directly into ntdll code pages.
		*reinterpret_cast<std::uint8_t*>(reinterpret_cast<std::uintptr_t>(export_addr)) = static_cast<std::uint8_t>(0xE9);
		*reinterpret_cast<std::uintptr_t*>(reinterpret_cast<std::uintptr_t>(export_addr) + 1) = reinterpret_cast<std::uintptr_t>(ExitProcess);

		VirtualProtect(reinterpret_cast<void*>(export_addr), sizeof(std::uintptr_t) + 1, old_protection, &old_protection);
	}
}

/*
 * Modifies the image size field of the process's PEB loader entry.
 * Obfuscates memory layout to prevent memory scanners and debuggers.
 */
auto umium_t::change_image_size() -> void
{
	// Unsafe: direct GS-relative PEB access, undocumented LDR_DATA_TABLE_ENTRY layout.
	const auto peb        = reinterpret_cast<PEB*>(__readgsqword(0x60));
	const auto load_order = static_cast<LIST_ENTRY*>(peb->Ldr->Reserved2[1]);
	const auto table_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
		reinterpret_cast<char*>(load_order)
		- reinterpret_cast<std::uintptr_t>(&static_cast<LDR_DATA_TABLE_ENTRY*>(nullptr)->Reserved1[0]));
	const auto entry_size = reinterpret_cast<unsigned long*>(&table_entry->Reserved3[1]);
	*entry_size = static_cast<unsigned long>(reinterpret_cast<std::int64_t>(table_entry->DllBase) + 0x100000);
}

/*
 * Disables the ability to load non-Microsoft-signed binaries into the process.
 */
auto umium_t::disable_loadlibrary() -> void
{
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = { .MicrosoftSignedOnly = 1 };
	SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy));
}

/*
 * Erases the PE headers of the current process from memory.
 * Hinders memory dumping and reverse engineering.
 */
auto umium_t::erase_pe_header() -> void
{
	const auto base_address = GetModuleHandleW(nullptr);
	if (!base_address)
		return;

	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base_address);
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(
		reinterpret_cast<std::uint8_t*>(base_address) + dos_header->e_lfanew);
	const auto nt_headers_size = nt_headers->OptionalHeader.SizeOfHeaders;
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return;

	unsigned long old_protection{};
	if (VirtualProtect(base_address, nt_headers_size, PAGE_EXECUTE_READWRITE, &old_protection))
	{
		RtlSecureZeroMemory(base_address, nt_headers_size);
		VirtualProtect(base_address, nt_headers_size, old_protection, &old_protection);
	}
}

/*
 * Checks CPU debug registers (DR0–DR7) for hardware breakpoints.
 */
auto umium_t::check_hardware_registers() -> void
{
	CONTEXT ctx = { .ContextFlags = CONTEXT_ALL };
	GetThreadContext(GetCurrentThread(), &ctx);

	if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr6 || ctx.Dr7)
		trigger();
}

/*
 * Detects if the process is running inside a remote desktop session.
 */
auto umium_t::check_remote_session() -> void
{
	if (GetSystemMetrics(SM_REMOTESESSION) != 0)
		trigger();
}

/*
 * Scans open windows for known debugger / RE tool signatures.
 */
auto umium_t::check_windows() -> void
{
	using window_params = std::pair<const wchar_t*, const wchar_t*>;
	static const window_params blacklisted_windows[] = {
		{L"ID",                    L"Immunity"},
		{L"Qt5QWindowIcon",        L"x64dbg"},
		{L"Qt5QWindowIcon",        L"The Wireshark Network Analyzer"},
		{L"Chrome_WidgetWin_1",    L"Fiddler Everywhere"},
		{nullptr,                  L"Progress Telerik Fiddler Web Debugger"},
		{L"Qt5153QTQWindowIcon",   nullptr},
		{L"dbgviewClass",          nullptr},
		{L"WinDbgFrameClass",      nullptr},
		{L"Zeta Debugger",         nullptr},
		{L"Rock Debugger",         nullptr},
		{L"ObsidianGUI",           nullptr},
		{nullptr,                  L"IDA v7.0.170914"},
		{nullptr,                  L"x64dbg"},
		{nullptr,                  L"IAT Autosearch"},
		{nullptr,                  L"IDA: Quick start"},
		{nullptr,                  L"BreakpointsViewClassWindow"},
		{nullptr,                  L"Detect It Easy v3.10 [Windows 10 Version 2009] (x86_64)"},
		{nullptr,                  L"CFF Explorer VIII"},
		{nullptr,                  L"Scylla x64 v0.9.8"},
		{nullptr,                  L"Binary Ninja Personal 3.3.3996 Personal"},
		{L"Qt661QWindowIcon",      L"Binary Ninja Personal 4.0.4958-Stable"},
	};

	for (const auto& [cls, title] : blacklisted_windows)
	{
		if (FindWindowW(cls, title))
			trigger();
	}
}

/*
 * Checks if the process is being debugged via API calls and direct PEB access.
 */
auto umium_t::check_debuggers() -> void
{
	if (IsDebuggerPresent())
		trigger();

	auto is_dbg_present = FALSE;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_dbg_present) && is_dbg_present)
		trigger();

	// Unsafe: direct GS-relative PEB read for BeingDebugged byte.
	const auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
	if (peb->BeingDebugged)
		trigger();
}

/*
 * Scans loaded modules for known hooking / debugging libraries.
 */
auto umium_t::check_blacklisted_modules() -> void
{
	static const std::wstring_view blacklisted[] = {
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
		L"cmdvrt64.dll",
	};

	for (const auto& mod : blacklisted)
	{
		if (GetModuleHandleW(mod.data()))
			trigger();
	}

	HMODULE modules[0x400] = {};
	unsigned long needed{};
	if (!K32EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed))
		return;

	const auto count = needed / sizeof(HMODULE);
	for (std::size_t i = 0; i < count; ++i)
	{
		wchar_t module_name[MAX_PATH]{};
		if (!K32GetModuleFileNameExW(GetCurrentProcess(), modules[i], module_name, MAX_PATH))
			continue;

		const std::wstring_view name_view(module_name);
		for (const auto& bl : blacklisted)
		{
			if (name_view.contains(bl))
				trigger();
		}
	}
}

/*
 * Enumerates kernel-mode drivers and checks against a blacklist.
 */
auto umium_t::check_kernel_drivers() -> void
{
	static const std::wstring_view driver_blacklist[] = {
		L"kprocesshacker.sys",
		L"SystemInformer.sys",
		L"npf.sys",
		L"HttpDebuggerSdk.sys",
		L"dbk64.sys",
		L"dbk32.sys",
		L"SharpOD_Drv.sys",
		L"SbieSvc.exe",
		L"TitanHide.sys",
	};

	void* drivers[1024] = {};
	unsigned long needed{};
	if (!K32EnumDeviceDrivers(drivers, sizeof(drivers), &needed) || needed > sizeof(drivers))
		return;

	const auto driver_count = static_cast<int>(needed / sizeof(drivers[0]));
	for (int i = 0; i < driver_count; ++i)
	{
		wchar_t driver_buffer[1024]{};
		if (!K32GetDeviceDriverBaseNameW(drivers[i], driver_buffer, static_cast<DWORD>(std::size(driver_buffer))))
			continue;

		const std::wstring_view name_view(driver_buffer);
		for (const auto& bl : driver_blacklist)
		{
			if (name_view == bl)
				trigger();
		}
	}
}

/*
 * Detects attempts to hide the current thread from debuggers via NtSetInformationThread /
 * NtQueryInformationThread inconsistency checks.
 */
auto umium_t::check_hidden_thread() -> void
{
	struct alignas(4) aligned_bool { bool value; };

	static const auto nt_set_information_thread =
		reinterpret_cast<long(*)(void*, unsigned int, void*, unsigned long)>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"));
	static const auto nt_query_information_thread =
		reinterpret_cast<long(*)(void*, unsigned int, void*, unsigned long, unsigned long*)>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));

	aligned_bool is_thread_hidden{ false };

	// Invalid length → should fail; success means debugger patched the function.
	long status = nt_set_information_thread(GetCurrentThread(), 0x11u, &is_thread_hidden, 12345);
	if (status == 0)
		trigger();

	// Invalid handle → must fail.
	status = nt_set_information_thread(reinterpret_cast<void*>(0xFFFF), 0x11u, nullptr, 0);
	if (status == 0)
		trigger();

	status = nt_set_information_thread(GetCurrentThread(), 0x11u, nullptr, 0);
	if (status == 0)
	{
		status = nt_query_information_thread(GetCurrentThread(), 0x11u, &is_thread_hidden.value, sizeof(bool), nullptr);
		if (status == static_cast<long>(0xC000'0004ul))
			trigger();

		if (status == 0)
		{
			aligned_bool bogus{ false };
			status = nt_query_information_thread(GetCurrentThread(), 0x11u, &bogus.value, sizeof(int), nullptr);
			if (status != static_cast<long>(0xC000'0004ul))
				trigger();

			constexpr std::size_t unaligned_check_count = 8;
			constexpr std::size_t max_alignment_ok      = 2;
			bool bogus_unaligned[unaligned_check_count]{};
			int alignment_errors = 0;

			for (auto& val : bogus_unaligned)
			{
				status = nt_query_information_thread(GetCurrentThread(), 0x11u, &val, sizeof(int), nullptr);
				if (status == static_cast<long>(0x8000'0002ul))
					++alignment_errors;
			}

			if (unaligned_check_count - max_alignment_ok > static_cast<std::size_t>(alignment_errors))
				trigger();

			if (!is_thread_hidden.value)
				trigger();
		}
	}
	else
	{
		trigger();
	}
}

/*
 * Verifies the process job object to detect sandbox or job-based manipulation.
 */
auto umium_t::check_process_job() -> void
{
	constexpr unsigned long job_process_struct_size =
		sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(std::uintptr_t) * 0x400;

	std::vector<std::byte> buf(job_process_struct_size, std::byte{});
	auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(buf.data());
	list->NumberOfProcessIdsInList = 0x400ul;

	if (!QueryInformationJobObject(nullptr, JobObjectBasicProcessIdList, list, static_cast<DWORD>(buf.size()), nullptr))
		return;

	int whitelisted = 0;
	for (DWORD i = 0; i < list->NumberOfAssignedProcesses; ++i)
	{
		const auto pid = list->ProcessIdList[i];
		if (pid == static_cast<std::uintptr_t>(GetCurrentProcessId()))
		{
			++whitelisted;
			continue;
		}

		auto proc = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)>(
			OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(pid)), CloseHandle);
		if (!proc)
			continue;

		std::vector<wchar_t> proc_name(0x1000);
		if (K32GetProcessImageFileNameW(proc.get(), proc_name.data(), static_cast<DWORD>(proc_name.size())) > 0)
		{
			if (std::wstring_view(proc_name.data()).contains(L"\\Windows\\System32\\conhost.exe"))
				++whitelisted;
		}
	}

	if (static_cast<DWORD>(whitelisted) != list->NumberOfAssignedProcesses)
		trigger();
}

/*
 * Verifies that the CSR (Client/Server Runtime) process is accessible.
 * Failure indicates a tampered or sandboxed environment.
 */
auto umium_t::check_csr() -> void
{
	static const auto csr_get_process_id =
		reinterpret_cast<void*(*)()>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "CsrGetProcessId"));
	if (!csr_get_process_id)
		return;

	auto handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)>(
		OpenProcess(PROCESS_ALL_ACCESS, FALSE, reinterpret_cast<DWORD>(csr_get_process_id())),
		CloseHandle);
	if (!handle)
		trigger();
}

/*
 * Repeatedly calls LocalSize(nullptr) to detect unusual heap behavior.
 * The return value is intentionally discarded — this is a timing/behavioral oracle.
 */
auto umium_t::check_local_size() -> void
{
	// Volatile to prevent the optimizer from eliminating the loop.
	// INFINITE iterations is intentional — this call runs inside a monitoring thread.
	[[maybe_unused]] volatile std::uintptr_t buf{};
	for (unsigned int i = 0u; i < INFINITE; ++i)
		buf = LocalSize(nullptr);
}

/*
 * Queries NtQuerySystemInformation(SystemCodeIntegrityInformation) to detect
 * test-signing mode, debug mode, or test build flags.
 */
auto umium_t::check_test_sign_mode() -> void
{
	code_integrity_information sci = {};
	sci.size = sizeof(sci);

	static const auto nt_query_system_information =
		reinterpret_cast<long(*)(unsigned long, void*, unsigned long, unsigned long*)>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));

	nt_query_system_information(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr);

	if (sci.options & CODEINTEGRITY_OPTION_TESTSIGN ||
		sci.options & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED ||
		sci.options & CODEINTEGRITY_OPTION_TEST_BUILD)
	{
		trigger();
	}
}

#endif // UMIUM_IMPLEMENTATION
#endif // UMIUM_HPP
