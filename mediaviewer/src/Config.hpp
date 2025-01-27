//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved
//                  License: MIT License
//=================================================================================================
#pragma once

#include "filesystem/path.h"
#include "filesystem/resolver.h"
#include "ini_parser/ini_parser.hpp"
#include <algorithm>
#include <iterator>
#include <cassert>
#include <string>
#include <chrono>
#include <thread>
#include <iostream>
#include <memory>

#include <filesystem>
#include <fstream>

class Config
{
public:
    [[maybe_unused]] static  bool fileexists(const std::filesystem::path& p, std::filesystem::file_status s = std::filesystem::file_status{})
	{
		if(std::filesystem::status_known(s) ? std::filesystem::exists(s) : std::filesystem::exists(p))
			return true;
		else
			return false;
	}

    [[maybe_unused]] static bool  fileExists(const std::string& filename) 
    {
        std::fstream file(filename, std::ios::in);
        bool r = file.is_open(); // returns true if file exists and can be opened
        file.close();
        return r;
    }

    std::string     title = "Learning Tool";
    int             default_w = 900;
    int             default_h = 600;
    std::string     path_dir = ".\\";
    std::string     res_dir  = ".\\";
    float           zoom = 1.25;
    int             mak_wav_file = 0;
    int             load_sound_file = 0;
    int             make_N_sound_file = 1;
    int             verbose = 0;

    std::vector<std::string> exclude_folder = { ".Thumbs" };
    std::vector<std::string> img = { "jpg",  "png", "gif", "jpeg", "bmp", "mp4" , "avi", "mkv", "webm"};

    Config() = default;

	bool setup(const std::string& config_file)
	{
		if (config_file.size() == 0)
		{
			std::cerr << "Config filename empty" << std::endl;
			return false;
		}

		if (config_file.size() > 0)
		{
		    //filesystem::path p(config_file);
		    //if ( p.exists() && p.is_file() )
		    //if (Config::fileexists(config_file) == true)
		    if (Config::fileExists(config_file) == true)
		    {
		        std::shared_ptr<ini_parser> cfg_ini = std::shared_ptr<ini_parser>(new ini_parser(config_file));
		        if (cfg_ini)
		        {
		            std::string path_dir_temp;
		            try
		            {
		                path_dir_temp = cfg_ini->get_string("path_folder", "main");
		                filesystem::path path_folder(path_dir_temp);
		                if ((path_folder.empty() == false) && (path_folder.exists() == true) && (path_folder.is_directory() == true))
		                {
		                    this->path_dir = path_folder.make_absolute().str();

		                    path_dir_temp = cfg_ini->get_string("res_folder", "main");
                            filesystem::path res_folder(path_dir_temp);
                            if ((res_folder.empty() == false) && (res_folder.exists() == true) && (res_folder.is_directory() == true))
                            {
                                this->res_dir = res_folder.make_absolute().str();
                            }
                            else
                            {
                                std::cerr << "Unreachable ressource directory (check res_dir entry): " << path_dir_temp << std::endl;
                            }
                        }
                        else
                        {
                            std::cerr << "Unreachable content directory (check path_folder entry): " << path_dir_temp << std::endl;
                        }
		            }
		            catch (...)
		            {
                        std::cerr << "Unexpected error" << std::endl;
		            }

		            try
		            {
		                this->title = cfg_ini->get_string("title", "main");
		            }
		            catch (...)
		            {
                        std::cerr << "Unexpected parse title error" << std::endl;
		            }

		            try
		            {
                        this->default_w = cfg_ini->get_int("w", "main");
		            }
		            catch (...)
		            {
                        std::cerr << "Unexpected parse w error" << std::endl;
		            }

		            try
		            {
                        this->default_h = cfg_ini->get_int("h", "main");
		            }
		            catch (...)
		            {
                        std::cerr << "Unexpected parse h error" << std::endl;
		            }

		            try
		            {
                        this->zoom = std::max<float>(1.05f, cfg_ini->get_float("zoom", "main") );
		            }
		            catch (...)
		            {
                        std::cerr << "Unexpected parse zoom error" << std::endl;
		            }

		            try
		            {
		                std::string s_excl = cfg_ini->get_string("exclude_folder", "main");
                        this->exclude_folder = Config::split(s_excl, ';');
		            }
		            catch (...)
		            {
		            }

		            try
		            {
		                std::string s_img = cfg_ini->get_string("img", "main");
                        this->img = Config::split(s_img, ';');
		            }
		            catch (...)
		            {
		            }

		            try
		            {
		                this->mak_wav_file = cfg_ini->get_int("mak_wav_file", "main");
		            }
		            catch (...)
		            {
		            }

		            try
		            {
		                this->load_sound_file = cfg_ini->get_int("load_sound_file", "main");
		            }
		            catch (...)
		            {
		            }

		            try
		            {
		                this->make_N_sound_file = cfg_ini->get_int("make_N_sound_file", "main");
		            }
		            catch (...)
		            {
		            }

		            try
		            {
                        this->verbose = cfg_ini->get_int("verbose", "main");
		            }
		            catch (...)
		            {
		            }

		        }
		        else
		        {
                    std::cerr << "Unable to parse Config file: " << config_file << std::endl;
                    return false;
		        }
		    }
		    else
		    {
                std::cerr << "Can not open config file [" << config_file << "]" << std::endl;
                return false;
		    }
        }
        else
        {
            std::cerr << "Config filename empty "<< std::endl;
            return false;
        }

		filesystem::path path_folder(this->path_dir);
		if (path_folder.empty() == true)
		{
			std::cerr << "Invalid content path - path empty:" << this->path_dir << std::endl;
			return false;
		}
		if (path_folder.exists() == false)
		{
			std::cerr << "Invalid content path - folder does not exist:" << this->path_dir << std::endl;
			return false;
		}
		if (path_folder.is_directory() == false)
		{
			std::cerr << "Invalid content path - not a folder:" << this->path_dir << std::endl;
			return false;
		}

		return true; // ok

	}

    static std::vector<std::string> split(const std::string &text, char sep)
    {
        std::vector<std::string> tokens;
        std::size_t start = 0, end = 0;
        while ((end = text.find(sep, start)) != std::string::npos)
        {
            tokens.push_back(text.substr(start, end - start));
            start = end + 1;
        }
        tokens.push_back(text.substr(start));
        return tokens;
    }

    static std::string merge(std::vector<std::string> v)
    {
        std::string s;
        for (size_t i = 0; i<v.size(); i++)
        {
            s += v[i];
            if (i < v.size() - 1)
                s += ", ";
        }
        return s;
    }
};
