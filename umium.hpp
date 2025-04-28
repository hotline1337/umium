#pragma once

class umium
{
private:
	struct code_integrity_information
	{
		std::uint32_t m_size;
		std::uint32_t m_options;
	};

	enum special_mode
	{
		test_sign_mode,
		test_build_mode,
		debugging_mode
	};

public:
	umium();
	std::function<bool()> start;
	std::function<bool(const std::wstring&)> security_callback;
protected:
	std::function<std::void_t<>()> dispatch_threads;
	std::function<std::void_t<>()> patch_debug_functions;
private:
	auto trigger() const -> std::void_t<>;

	std::function<std::void_t<>()> disable_loadlibrary;
	std::function<std::void_t<>()> check_hardware_registers;
	std::function<std::void_t<>()> check_remote_session;
	std::function<std::void_t<>()> check_windows;
	std::function<std::void_t<>()> check_debuggers;
	std::function<std::void_t<>()> check_blacklisted_modules;
	std::function<std::void_t<>()> check_kernel_drivers;
	std::function<std::void_t<>()> check_test_sign_mode;
};

struct active_object
{
	template <typename FN>
	active_object(FN fn) : thread([this, fn] { while (alive) fn(); }) {}

	~active_object()
	{
		alive = false;
		thread.join();
	}

	active_object(const active_object&) = delete;
	active_object(active_object&&) = delete;
	active_object& operator=(active_object) = delete;

	std::atomic<bool> alive{ true };
	std::thread thread;
};