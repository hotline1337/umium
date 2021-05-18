#include <iostream>
#include <Windows.h>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <thread>
#include <functional>
#include <chrono>
#include <atomic>
#include <tchar.h>
#include <WinInet.h>
#include <conio.h>
#include <stdio.h>
#include <msclr/marshal_cppstd.h>

// Hashing
#include "../h/xorstr.h"

// Security
#include "../import.hpp"
#include "../h/umium.h"

#pragma warning(disable : 4996)
#pragma warning(disable : 4573)

using namespace System;
using namespace Threading;
using namespace Diagnostics;
using namespace Net;
using namespace Runtime::InteropServices;
using namespace Linq;
using namespace msclr::interop;

#define gmh(s) LI_FN(GetModuleHandleA).get()(xorstr_(s))
#define x_string(parameter) context.marshal_as<String^>(static_cast<std::string>(_XorStr(parameter)))
#define base64_hash(arr_x) base64_encode(reinterpret_cast<const unsigned char*>(arr_x.c_str()), arr_x.length())

const auto perform_checks = [&]() /* lambda */
{
	umium::security::find_window();
	umium::security::is_debugger_present();
	umium::security::anti_attach();
	if (umium::security::check_sandboxie() != 0 || umium::security::check_remote_session() != 0) // Cpu & remote check
	{
		umium::security::ProtectionThread();
	}
	if (umium::security::check_kernel_drivers() != 0 || umium::security::check_titan_hide() != 0)
	{
		// we can add a message here to inform the user to unload the driver or disable test signing
		// edit: added message with a driver name to check_kernel_drivers function (umium.cpp)
		LI_FN(TerminateProcess)(LI_FN(GetCurrentProcess).get()(), 0);
	}
	if (gmh("vehdebug-x86_64.dll") || gmh("winhook-x86_64.dll") || gmh("luaclient-x86_64.dll") || gmh("allochook-x86_64.dll")
			|| gmh("exp_64.dll") || gmh("HookLibraryx64.dll")) // Blacklisted handles check
	{
		umium::security::ProtectionThread();
	}
};

struct multi_thread
{
	template <typename FN>
	multi_thread(FN fn) : thread([this, fn] { while (alive) fn(); }) {}

	~multi_thread()
	{
		alive = false;
		thread.join();
	}

	multi_thread(const multi_thread&) = delete;
	multi_thread(multi_thread&&) = delete;
	multi_thread& operator=(multi_thread) = delete;

	std::atomic<bool> alive{ true };
	std::thread thread;
};

std::function<void(void)> reference = [&]()
{
	// proper middleman
	const auto call = [&]()
	{
		multi_thread obj([]
		{
			perform_checks();
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
		});
	};

	if (LI_FN(time).get()(nullptr) == LI_FN(time).get()(nullptr))
	{
		call();
	}

	return _XorStr("junk");
};

auto main(void) -> int
{
	// entrypoint
	// includes some junk like GetTickCount64 check so the code will appear more "obfuscated"
	// same for return statement
	const auto call = [&]()
	{
		reference();
	};

	if (LI_FN(GetTickCount64).get()() == LI_FN(GetTickCount64).get()())
	{
		call();
	}

	return (INT_MAX / 2) & (1 << 0);
}
