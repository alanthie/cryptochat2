#pragma once
#ifndef CHATCLI_H_INCLUDED
#define CHATCLI_H_INCLUDED

/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <limits>
#include <csignal>
#include <chrono>
#include "../include/crypto_client.hpp"
#include "../include/cfg_cli.hpp"
#include "../include/string_util.hpp"
#include "../include/argparse.hpp"
#include "../include/crypto_parsing.hpp"

namespace cryptochat
{
	namespace cli
	{
		class chat_cli
		{
		public:
			chat_cli(const std::string& cfgfile) : _cfg_file(cfgfile)
			{
			}

			~chat_cli()
			{
				if (_chat_cli != nullptr)
				{
                    std::cout << "deleting chat_cli" << std::endl;
					delete _chat_cli;
					_chat_cli = nullptr;
                }
			}


			bool read_cfg(bool create_if_not_exist, std::string& serr)
			{
                return _cfg.read_cfg(_cfg_file, create_if_not_exist, serr);
			}

			bool save_cfg(std::string& serr)
			{
                return _cfg.save_cfg(_cfg_file, serr);
			}

			void get_line(std::istream&, std::string& entry, uint32_t ctx = 0)
			{
                if (_auto_ui == false)
                {
                    std::getline(std::cin, entry);
                    return;
                }

                entry = {};
                return;
			}

			int run(std::string& serr, bool auto_ui = false)
			{
                _auto_ui = auto_ui;
				got_chat_cli_signal = 0;

				std::cout << "auto: " << auto_ui << std::endl;

				bool ok = read_cfg(false, serr);
				if (ok)
				{
					std::cout << "Server : " << _cfg._server << std::endl;
					std::cout << "Port : " << _cfg._port << std::endl;
					std::cout << "Username : " << _cfg._username << std::endl;
					std::cout << "Repository : " << _cfg._repo_root_path << std::endl;

					std::cout << "default_txt_filename : " << _cfg.default_txt_filename << std::endl;
					std::cout << "default_bin_filename : " << _cfg.default_bin_filename << std::endl;
					std::cout << "default_new_user_cmd : " << _cfg.default_new_user_cmd << std::endl;
					std::cout << "mediaviewer_folder   : " << _cfg.mediaviewer_folder  << std::endl;
                    std::cout << "mediaviewer_res_dir  : " << _cfg.mediaviewer_res_dir  << std::endl;

                    std::cout <<std::endl;

                    std::string entry;
					std::cout << "Press enter to continue" << std::endl;
					get_line(std::cin, entry);
				}
				else
				{
					std::string entry;

					_cfg._server = "127.0.0.1";
					std::cout << "Server (Default 127.0.0.1): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg._server = entry;

					_cfg._port = 14003;
					std::cout << "Port (Default 14003): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg._port = (int)NETW_MSG::str_to_ll(entry);

					_cfg._username = "user";
					std::cout << "Username (Default user): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg._username = entry;

                    std::cout << "default_txt_filename (Default " << _cfg.default_txt_filename << "): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg.default_txt_filename = entry;

                    std::cout << "default_bin_filename (Default " << _cfg.default_bin_filename << "): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg.default_txt_filename = entry;

					std::cout << "default_new_user_cmd (Default " << _cfg.default_new_user_cmd << "): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg.default_new_user_cmd = entry;

					std::cout << "mediaviewer_folder (Default " << _cfg.mediaviewer_folder << "): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg.mediaviewer_folder = entry;

					std::cout << "mediaviewer_res_dir (Default " << _cfg.mediaviewer_res_dir << "): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg.mediaviewer_res_dir = entry;

					// TODO...
#ifdef _WIN32
					_cfg._repo_root_path = "C:\\cpp\\test\\cryptochat_" + _cfg._username;
#else
                    const char* home_dir = getenv("HOME");
                    pid_t pid = getpid();
                    if (home_dir)
                    {
                        //_cfg._repo_root_path = std::string(home_dir) + "/dev/test/cryptochat_" + _cfg._username;
                        _cfg._repo_root_path = std::string(home_dir) + "/dev/test/cryptochat_" + std::to_string((int)pid);
                    }
                    else
                    {
                        _cfg._repo_root_path = "/home/allaptop/dev/test/cryptochat_" +  std::to_string((int)pid);
                    }
#endif
					std::cout << "Repository (Default " + _cfg._repo_root_path + "): ";
					get_line(std::cin, entry); if (!entry.empty()) _cfg._repo_root_path = entry;
					// validate...

					std::cout << std::endl;
					std::cout << "------------------------- " << std::endl;
					std::cout << "SUMMARY " << std::endl;
					std::cout << "------------------------- " << std::endl;
					std::cout << "Server : "    << _cfg._server << std::endl;
					std::cout << "Port : "      << _cfg._port << std::endl;
					std::cout << "Username : "  << _cfg._username << std::endl;
					std::cout << "Repository : " << _cfg._repo_root_path << std::endl;

					std::cout << "default_txt_filename : " << _cfg.default_txt_filename << std::endl;
					std::cout << "default_bin_filename : " << _cfg.default_bin_filename << std::endl;
					std::cout << "default_new_user_cmd : " << _cfg.default_new_user_cmd << std::endl;
					std::cout << "mediaviewer_folder   : " << _cfg.mediaviewer_folder << std::endl;
					std::cout << "mediaviewer_res_dir  : " << _cfg.mediaviewer_res_dir << std::endl;

					std::cout <<std::endl;
					std::cout << "Press enter to continue" << std::endl;
					get_line(std::cin, entry);

					bool r = save_cfg(serr);
				}

				try
				{
					_chat_cli = new crypto_socket::crypto_client(_cfg, _cfg_file);

					_chat_cli->connectServer(auto_ui);
					_chat_cli->client_UI(auto_ui); // LOOP

					// The client has quit
					got_chat_cli_signal = 1;

				}
				catch (const std::exception& e)
				{
					std::cerr << "Exception thrown: " << e.what() << std::endl;
				}
				catch(...)
				{
					std::cerr << "Exception thrown" << std::endl;
				}

				// EXITING
				std::this_thread::sleep_for(std::chrono::seconds(1));
				return 0;
			}

			std::string					    _cfg_file;
			cryptochat::cfg::cfg_cli	    _cfg;
			crypto_socket::crypto_client*   _chat_cli = nullptr;

			bool _auto_ui = false;

			static std::atomic<int> got_chat_cli_signal;
		};

	}
}

#endif
