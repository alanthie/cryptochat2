#pragma once
#ifndef CFGCLI_H_INCLUDED
#define CFGCLI_H_INCLUDED

#include <string>
#include <map>
#include "../include/c_plus_plus_serializer.h"
#include "../include/file_util.hpp"
#include "../include/terminal.h"
#include <type_traits>

template <typename E>
constexpr auto to_underlying(E e) noexcept
{
    return static_cast<std::underlying_type_t<E>>(e);
}

namespace cryptochat
{
    namespace cfg
    {
        struct mediaviewer_config
        {
            std::string mediaviewer_title   = "Chat Session";
            std::string data_folder         = "";
            std::string res_dir             = "";
            int mediaviewer_w               = 800;
            int mediaviewer_h               = 800;
            float mediaviewer_zoom          = 1.33;
            std::string mediaviewer_exclude_folder=".Thumbs;.dummy";
            std::string mediaviewer_img     ="jpg;png;gif;jpeg;bmp;mp4;avi;mkv;webm";
            int mediaviewer_mak_wav_file    =0;
            int mediaviewer_load_sound_file =1;
            int mediaviewer_make_N_sound_file=1;
        };

        struct cfg_cli
        {
            std::string _server;
            int			_port;
            std::string _username;
			std::string _repo_root_path;
            std::map<std::string, std::string> map_challenges;

            std::string default_txt_filename = "msg.txt";
            std::string default_bin_filename = "bin.dat";
            std::string default_new_user_cmd = "";

            std::string mediaviewer_folder  = "/home/allaptop/dev/cryptochatal/build/mediaviewer/mediaviewer";
            std::string mediaviewer_res_dir = "/home/allaptop/dev/cryptochatal/mediaviewer/prj/res";
			mediaviewer_config mv_cfg;

            cfg_cli() {}

            void make_default()
            {
                _server = "127.0.0.1";
                _port = 14003;
                _username = NETW_MSG::DEFAULT_USERNAME;
				_repo_root_path = "./cryptochat"; // should have a non relative path TODO...- not using default

                default_txt_filename = "msg.txt";
                default_bin_filename = "bin.dat";
                default_new_user_cmd = "";

                // TODO
                mediaviewer_folder  = "/home/allaptop/dev/cryptochatal/build/mediaviewer/mediaviewer";
                mediaviewer_res_dir = "/home/allaptop/dev/cryptochatal/mediaviewer/prj/res";
            }

            cfg_cli(const std::string& srv, int port, int number_connection,
                    const std::string& user, const std::string& repo_root_path)
            {
                _server = srv;
                _port = port;
                _username = user;
				_repo_root_path = repo_root_path;
            }

            bool read_cfg(const std::string& filename, bool create_if_not_exist, std::string& serr)
			{
				bool ret = false;
				bool has_cfg_file = false;

				if (filename.size() == 0)
				{
					serr += "WARNING read_cfg - cfg filename empty";
				}
				else if (file_util::fileexists(filename) == false)
				{
					serr += "WARNING read_cfg - cfg file not found: " + filename;
					if (create_if_not_exist)
					{
						make_default();
						std::ofstream outfile(filename, std::ios_base::out);
						outfile << bits(*this);
						outfile.close();
						has_cfg_file = true;
					}
				}
				else
				{
					has_cfg_file = true;
				}

				if (has_cfg_file)
				{
					// READ _cfg
					try
					{
						std::ifstream in(filename, std::ios_base::in);
						in >> bits(*this);
						in.close();
						ret = true;
					}
					catch (const std::exception& e)
					{
						serr += "WARNING read_cfg - unable to read file " + filename + "\n";
						serr += "Exception thrown: " + std::string(e.what()) + "\n";
					}
					catch (...)
					{
						serr += "WARNING read_cfg - unable to read file " + filename + "\n";
						serr += "Exception thrown\n";
					}
				}
				return ret;
			}

            bool save_cfg(const std::string& filename, std::string& serr)
			{
				if (filename.size() == 0)
				{
					serr += "WARNING save_cfg - cfg file name empty: ";
					return false;
				}

				try
				{
					std::ofstream outfile(filename, std::ios_base::out);
					outfile << bits(*this);
					outfile.close();
					return true;
				}
				catch (const std::exception& e)
				{
					serr += "WARNING save_cfg - unable to save file " + filename + "\n";
					serr += "Exception thrown: " + std::string(e.what()) + "\n";
				}
				catch (...)
				{
					serr += "WARNING save_cfg - unable to save file " + filename + "\n";
					serr += "Exception thrown\n";
				}
				return false;
			}

            friend std::ostream& operator<<(std::ostream& out, Bits<cfg_cli& > my)
            {
                out << bits(my.t._server) << bits(my.t._port) << bits(my.t._username)
					<< bits(my.t._repo_root_path)
					<< bits(my.t.map_challenges)
					<< bits(my.t.default_txt_filename)
					<< bits(my.t.default_bin_filename)
					<< bits(my.t.default_new_user_cmd)
					<< bits(my.t.mediaviewer_folder)
                    << bits(my.t.mediaviewer_res_dir)
					;
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<cfg_cli&> my)
            {
                in  >> bits(my.t._server) >> bits(my.t._port) >> bits(my.t._username)
					>> bits(my.t._repo_root_path)
					>> bits(my.t.map_challenges)
					>> bits(my.t.default_txt_filename)
					>> bits(my.t.default_bin_filename)
					>> bits(my.t.default_new_user_cmd)
					>> bits(my.t.mediaviewer_folder)
                    >> bits(my.t.mediaviewer_res_dir)
					;
                return (in);
            }
        };
    }
}

#endif


