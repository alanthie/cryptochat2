//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved
//                  License: MIT License
//=================================================================================================
#include <SFML/Graphics/Export.hpp>
#include <SFML/Graphics/RenderWindow.hpp>
#include <SFML/Graphics/RenderTarget.hpp>
#include <SFML/Graphics/Image.hpp>
#include <SFML/Graphics/Texture.hpp>
#include <SFML/Window/Window.hpp>
#include <SFML/Window/Event.hpp>
#include <SFML/Window/Keyboard.hpp>
#include <SFML/Graphics.hpp>

#include "filesystem/path.h"
#include "filesystem/resolver.h"
#include "ini_parser/ini_parser.hpp"
#include "UIMain.h"
#include "Config.hpp"

#include <string>
#include <chrono>
#include <thread>
#include <iostream>
#include <memory>

#ifndef _WIN32
#include "core/config.h"
#include <cstdlib>
#include <cstdio>
#endif

#include "SFML_SDK/ResourceManager/ResourceHolder.h"

#ifdef _WIN32
std::string ExePath()
{
    char buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}
#endif

#ifndef _WIN32
#define POSITIVE_ANSWER  0
#define NEGATIVE_ANSWER -1
int syscommand(std::string aCommand, std::string & result)
{
    FILE * f;
    if ( !(f = popen( aCommand.c_str(), "r" )) )
    {
            std::cout << "Can not open file" << std::endl;
            return NEGATIVE_ANSWER;
    }
    const int BUFSIZE = 4096;
    char buf[ BUFSIZE ];
    if (fgets(buf,BUFSIZE,f)!=NULL)
    {
       result = buf;
    }
    pclose( f );
    return POSITIVE_ANSWER;
}

std::string getBundleName()
{
    pid_t procpid = getpid();
    std::stringstream toCom;
    toCom << "cat /proc/" << procpid << "/comm";
    std::string fRes="";
    int lRet = syscommand(toCom.str(),fRes);
    if (lRet == NEGATIVE_ANSWER)
    {
       // ...
    }
    size_t last_pos = fRes.find_last_not_of(" \n\r\t") + 1;
    if (last_pos != std::string::npos) {
        fRes.erase(last_pos);
    }
    return fRes;
}

std::string getBundlePath()
{
    pid_t procpid = getpid();
    std::string appName = getBundleName();
    std::stringstream command;
    command <<  "readlink /proc/" << procpid << "/exe | sed \"s/\\(\\/" << appName << "\\)$//\"";
    std::string fRes;
    int lRet = syscommand(command.str(),fRes);
    if (lRet == NEGATIVE_ANSWER)
    {
       // ...
    }
    return fRes;
}
#endif

std::string trim(const std::string &s)
{
    std::string::const_iterator it = s.begin();
    while (it != s.end() && isspace(*it))
        it++;

    std::string::const_reverse_iterator rit = s.rbegin();
    while (rit.base() != it && isspace(*rit))
        rit++;

    return std::string(it, rit.base());
}

//-----------------------------------------
// Argument: Config file path
//
// Ex: LearnTool.exe .\\LearnTool.ini
// ~/dev/cryptochatal/build/mediaviewer$ ./mediaviewer ../../mediaviewer/prj/LearnTool.ini
//-----------------------------------------
int main(int argc, char *argv[])
{
    Config cfg; // has defaults values

    if (argc >= 2)
    {
        std::string config_file = std::string(argv[1]);

        if (cfg.setup(config_file) == true)
        {
			ResourceHolder::init(cfg.res_dir);
        }
        else
        {
			std::cerr << "Invalid config file:" << config_file << std::endl;
			return -1;
        }
    }
    else if (argc == 1) // fork
    {
        std::string config_file = std::string(argv[0]);

        if (cfg.setup(config_file) == true)
        {
			ResourceHolder::init(cfg.res_dir);
        }
        else
        {
			std::cerr << "Invalid config file:" << config_file << std::endl;
			return -1;
        }
    }
    else
    {
#ifdef _WIN32
        std::string exe_path = ExePath();
#else
		std::string exe_path = getBundlePath();
		exe_path = trim(exe_path);
#endif
		std::cout << "Missing argument argc: " << argc  << std::endl;
		std::cout << "Missing argument argv[0]: "<< argv[0]  << std::endl;
        std::cout << "Looking for config file: "<< exe_path << "\\LearnTool.ini" << std::endl;

        if (cfg.setup(exe_path + "\\LearnTool.ini") == true)
        {
			ResourceHolder::init(cfg.res_dir);
        }
        else
        {
            std::cerr << "Cannot find config ini file." << std::endl;
            return -1;
        }
    }

    //std::cout << "cfg.path_dir:" << cfg.path_dir << std::endl;

    UImain ui(cfg);
    ui.run();
    return 0;
}
