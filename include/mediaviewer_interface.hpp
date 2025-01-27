/*
 * Author: Alain Lanthier
 */

#pragma once
#ifndef MediaViewerInterface_H_INCLUDED
#define MediaViewerInterface_H_INCLUDED

#include <string>
#include <map>
#include "../include/file_util.hpp"
#include "../include/c_plus_plus_serializer.h"
#include "../subprocess/subprocess.h"
#include <dirent.h>
#include <sys/stat.h>
#include "cfg_cli.hpp"

#ifdef _WIN32
//NOMINMAX
#pragma warning ( disable : 4146 )
#endif


namespace cryptochat
{
    namespace viewer
    {
        class MediaViewer
        {
        public:
            MediaViewer() = default;

			static bool processExists(const std::string& processName, std::string& serr)
			{
				DIR* dir = opendir("/proc");
				if (!dir)
				{
                    serr += "unable to open /proc: ";
					return false;
				}

				struct dirent* entry;
				while ((entry = readdir(dir)))
				{
					if (entry->d_type == DT_DIR && strcmp(entry->d_name, processName.c_str()) == 0)
					{
						closedir(dir);
						return true;
					}
				}
				closedir(dir);
				return false; // process not found
			}


            pid_t _pid;
			//subprocess_s _subprocess;

			std::string _process_name 	= "mediaviewer";
			std::string _process_folder_name= "/home/allaptop/dev/cryptochatal/build/mediaviewer/mediaviewer";
			std::string _process_args 	    = "/home/allaptop/dev/cryptochatal/mediaviewer/prj/LearnTool.ini";

            bool is_running(std::string& serr)
			{
				return processExists(_process_name, serr);
			}

            pid_t get_pid()
            {
				return _pid;
			}

			std::string  make_ini(const cryptochat::cfg::mediaviewer_config& mv_cfg, const std::string& folder, std::string& serr)
            {
                std::stringstream ss;
                ss << "[main]" << std::endl;
                ss << "path_folder="    << mv_cfg.data_folder << std::endl; // data folder
                ss << "res_folder="     << mv_cfg.res_dir << std::endl;
                ss << "title="          << mv_cfg.mediaviewer_title  << std::endl;
                ss << "w="              << mv_cfg.mediaviewer_w << std::endl;
                ss << "h="              << mv_cfg.mediaviewer_h << std::endl;
                ss << "zoom="           << mv_cfg.mediaviewer_zoom << std::endl;
                ss << "exclude_folder=" << mv_cfg.mediaviewer_exclude_folder << std::endl;
                ss << "img="            << mv_cfg.mediaviewer_img << std::endl;
                ss << "mak_wav_file="      << mv_cfg.mediaviewer_mak_wav_file << std::endl;
                ss << "load_sound_file="   << mv_cfg.mediaviewer_load_sound_file << std::endl;
                ss << "make_N_sound_file=" << mv_cfg.mediaviewer_make_N_sound_file << std::endl;

                std::string filenameinfo = folder + std::string("/") + std::string("mediaviewer.ini"); //file_separator()
                std::ofstream outstream;
				outstream.open(filenameinfo, std::ios_base::out);
				if (outstream.is_open()) 
				{
					outstream << ss.str();
					outstream.close();
					
					serr += std::string("file created [")  + filenameinfo + "]\n";
					return filenameinfo;
				} 
				else 
				{
					serr += std::string("Unable to create file [")  + filenameinfo + "]\n";
				}
                return "";
			}

            int create( std::string& serr,
                        const std::string& mediaviewer_folder,
                        const std::string& mediaviewer_args )
            {
                _process_folder_name    = mediaviewer_folder;
                _process_args           = mediaviewer_args;

                serr += "opening media viewer...\n";
                serr += mediaviewer_folder + "\n";
                serr += mediaviewer_args + "\n";
                
				bool process_exist = false;
				{
					 process_exist = processExists(_process_name, serr);
					 if (process_exist)
					 {
						serr += "process already runnung\n";
						return 0;
                     }
				}

                pid_t processID;
//                char *argV[] = {(char *) "/home/allaptop/dev/cryptochatal/mediaviewer/prj/LearnTool.ini",(char *) 0};
//                int status = posix_spawn(   &_pid,
//                                            "/home/allaptop/dev/cryptochatal/build/mediaviewer/mediaviewer",
//                                            NULL,NULL,argV,environ);
                char arg[1000] = {0};
                char pgm[1000] = {0};
                memcpy(arg, _process_args.data(), _process_args.size());
                memcpy(pgm, _process_folder_name.data(), _process_folder_name.size());
                char *argV[] = {arg, (char *) 0};
                int status = posix_spawn(   &_pid,pgm,NULL,NULL,argV,environ);
                return status;

/*
				/// @brief Create a process.
				/// @param command_line An array of strings for the command line to execute for
				/// this process. The last element must be NULL to signify the end of the array.
				/// The memory backing this parameter only needs to persist until this function
				/// returns.
				/// @param options A bit field of subprocess_option_e's to pass.
				/// @param out_process The newly created process.
				/// @return On success zero is returned.
				//subprocess_weak int subprocess_create(const char *const command_line[],
                                      //int options,
                                      //struct subprocess_s *const out_process);

                const char *command_line[] =
                {
					(get_process_folder() + get_process_name()).c_str(),
					get_process_args().c_str(),
					NULL
				};
				//const char *command_line[] = {"/bin/echo", "\"Hello, world!\"", NULL};

				int result = subprocess_create(command_line, 0, &_subprocess);
				if (0 != result)
				{
                    // an error occurred!
                    serr += "unable to create process: " + std::string(command_line[0]) + "\n";
                    serr += "                     arg: " + std::string(command_line[1]) + "\n";
                    serr += "                     err: " + std::to_string(result);
				}
				else
				{
					_count_create++;
				}
				return result;
*/
            }
		};
    }
}

#endif
