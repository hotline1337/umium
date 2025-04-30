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

#ifndef UMIUM_HPP
#define UMIUM_HPP

#if defined(_M_X64) || defined(__amd64__) || defined(_M_IX86) || defined(__i386__)
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#else
#error Unsupported platform
#endif

#include <algorithm>
#include <functional>
#include <thread>
#include <string>

class umium
{
private:
	struct code_integrity_information
	{
		std::uint32_t m_size;
		std::uint32_t m_options;
	};
public:
	umium();
	std::function<bool()> start;
protected:
	std::function<std::void_t<>()> trigger;
	std::function<std::void_t<>()> dispatch_threads;
	std::function<std::void_t<>()> patch_debug_functions;
	std::function<std::void_t<>()> change_image_size;
	std::function<std::void_t<>()> disable_loadlibrary;
	std::function<std::void_t<>()> erase_pe_header;
private:
	std::function<std::void_t<>()> check_hardware_registers;
	std::function<std::void_t<>()> check_remote_session;
	std::function<std::void_t<>()> check_windows;
	std::function<std::void_t<>()> check_debuggers;
	std::function<std::void_t<>()> check_blacklisted_modules;
	std::function<std::void_t<>()> check_kernel_drivers;
	std::function<std::void_t<>()> check_hidden_thread;
	std::function<std::void_t<>()> check_process_job;
	std::function<std::void_t<>()> check_csr;
	std::function<std::void_t<>()> check_local_size;
	std::function<std::void_t<>()> check_test_sign_mode;
};

inline const auto umium = std::make_unique<class umium>();

#endif