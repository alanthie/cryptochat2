#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <mutex>
#include <ctime>
#include "../include/chat_cli.hpp"
#include "../include/netw_msg.hpp"

class main_global
{
public:
	static cryptochat::cli::chat_cli*   global_cli;
	static NETW_MSG::encdec_stat        msg_stats;
	static std::string                  logfile;

	static NETW_MSG::encdec_stat& stats() {return msg_stats;}

	static void log(const std::string& s, bool log_to_file = false)
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			std::stringstream& ss = log_stream();
			ss << s;
			log_is_dirty = true;

			if (logfile.empty())
			{
                //const char* home_dir = getenv("HOME");
                pid_t pid = getpid();
                time_t now = time(0);
                tm* ltm = localtime(&now);
                char date_string[100];
                strftime(date_string, 100, "%Y%m%d_%H%M%S", ltm);

                if (file_util::fileexists("logdir") == false)
                    std::filesystem::create_directories("logdir") ;

                logfile = std::string("logdir/cryptochat_") + std::string(date_string) + "_" + std::to_string((int)pid) + ".log";
            }

            //if (log_to_file)
            {
                std::ofstream outfile;
                char buffer[256];
                time_t now = time(0);
                tm* ltm = localtime(&now);
                strftime(buffer, 256, "%Y%m%d_%H%M%S", ltm);
                std::string stime(buffer);

                if (file_util::fileexists(logfile) == false)
				{
					outfile.open(logfile.c_str(), std::ios_base::out);
                }
                else
				{
					outfile.open(logfile.c_str(), std::ios_base::app);
                }

                if (outfile.is_open())
                {
                    std::string s2 = s;
                    char c = '\r';
                    size_t pos = s2.find(c);
                    while (pos != std::string::npos)
                    {
                        s2.erase(pos, 1);
                        pos = s2.find(c);
                    }

                    std::vector<std::string> lines = NETW_MSG::split(s2, "\n");
                    for (size_t i = 0; i < lines.size(); i++)
                        if (lines[i].size() > 0)
                            outfile << stime << " : " << lines[i] << std::endl;

                    outfile.close();
                }
            }
		}
	};

	static bool is_log_dirty()
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			bool b = log_is_dirty;
			return b;
		}
	}

	static void set_log_dirty(bool b)
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			log_is_dirty = b;
		}
	}

	static std::string get_log_string()
	{
		{
			std::lock_guard lck(main_global::log_mutex);
			auto& ss = main_global::log_stream();
			std::string s = ss.str();
			return s;
		}
	}

	static void shutdown()
	{
        main_global::log("shutdown", true);
        cryptochat::cli::chat_cli::got_chat_cli_signal = 1;

        std::string key;
        key = main_global::global_cli->_chat_cli->get_key();

        NETW_MSG::MSG m;
        m.make_msg(NETW_MSG::MSG_CMD_RESP_SHUTDOWN, "shutdown", key);

        uint8_t crypto_flag = (main_global::global_cli->_chat_cli->cryto_on == true) ? 1 : 0;
        if (main_global::global_cli->_chat_cli->chat_with_other_user_index == 0) crypto_flag = 0;

        int ret = main_global::global_cli->_chat_cli->send_message_buffer(  main_global::global_cli->_chat_cli->get_socket(), m, key,
                                                        crypto_flag,
                                                        main_global::global_cli->_chat_cli->my_user_index,
                                                        main_global::global_cli->_chat_cli->chat_with_other_user_index);

	}

private:
	static std::stringstream    log_ss;
	static std::mutex           log_mutex;
	static bool                 log_is_dirty;

	static std::stringstream& log_stream()
	{
		return main_global::log_ss;
	};
};
