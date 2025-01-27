/*
 * Author: Alain Lanthier
 */
#include <iostream>
#include <limits>
#include <csignal>
#include <chrono>
#include "../include/crypto_server.hpp"
#include "../include/chat_srv.hpp"
#include "../include/cfg_srv.hpp"
#include "../include/string_util.hpp"
#include "../include/argparse.hpp"
#include "../include/crypto_parsing.hpp"
#include "../include/main_global.hpp"

std::stringstream	main_global::log_ss;
std::mutex			main_global::log_mutex;
bool				main_global::log_is_dirty = true;
NETW_MSG::encdec_stat main_global::msg_stats;
std::string         main_global::logfile;

// TODO add shutdown signal....
//std::atomic<int> cryptochat::srv::chat_srv::got_chat_srv_signal = 0;

class main_global_srv
{
public:
	static cryptochat::srv::chat_srv* global_srv;
};
cryptochat::srv::chat_srv* main_global_srv::global_srv = nullptr;

static void signalHandler(int code)
{
	{
		if (main_global_srv::global_srv != nullptr)
		{
            try
            {
                delete main_global_srv::global_srv;
                main_global_srv::global_srv = nullptr;
            }
            catch (...)
            {
            }
		}
  		exit(0);
	}
}

int main(int argc, char** argv)
{
	std::string FULLVERSION = version_to_string();

	// Argument parser
	try
	{
		signal(SIGINT, signalHandler);

		argparse::ArgumentParser program("chatsrv", FULLVERSION);
		{
			program.add_description("Run chat server");

			program.add_argument("-cfg", "--cfg")
				.default_value(std::string(""))
				.help("specify a config file.");
		}

		// Parse the arguments
		try
		{
			program.parse_args(argc, argv);
		}
		catch (const std::runtime_error& err)
		{
			std::cerr << err.what() << std::endl;
			std::cerr << program;
			return -1;
		}

		{
			auto& cmd = program;
			auto cfg = cmd.get<std::string>("--cfg");

			main_global_srv::global_srv = new cryptochat::srv::chat_srv(cfg);
			return main_global_srv::global_srv->run();
		}

	}
	catch (std::invalid_argument const& ex)
	{
		std::cerr << "CHATSRV FAILED - invalid_argument thrown " << ex.what() << '\n';
	}
	catch (std::logic_error const& ex)
	{
		std::cerr << "CHATSRV FAILED - logic_error thrown " << ex.what() << '\n';
	}
	catch (std::range_error const& ex)
	{
		std::cerr << "CHATSRV FAILED - range_error thrown " << ex.what() << '\n';
	}
	catch (std::runtime_error const& ex)
	{
		std::cerr << "CHATSRV FAILED - runtime_error thrown " << ex.what() << '\n';
	}
	catch (std::exception const& ex)
	{
		std::cerr << "CHATSRV FAILED - std exception thrown " << ex.what() << '\n';
	}
	catch (...)
	{
		std::cerr << "CHATSRV FAILED - exception thrown" << std::endl;
	}
	return 0;
}
