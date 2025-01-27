//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved  
//                  License: MIT License
//=================================================================================================
#pragma once

#include <opencv2/imgcodecs.hpp>
#include <opencv2/videoio.hpp>
#include <opencv2/highgui.hpp>
#include "filesystem/path.h"
#include "filesystem/resolver.h"
#include <SFML/Audio.hpp>
#include <stdlib.h>
#include <iostream>
#include <stdio.h>
#include <atomic>
#include <future>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

class VideoSoundCapturing;

//-----------------------------------
// VideoSoundCapturingDeleter
//-----------------------------------
class VideoSoundCapturingDeleter
{
public:
    VideoSoundCapturingDeleter(VideoSoundCapturing* v);
    ~VideoSoundCapturingDeleter();

    VideoSoundCapturing* vs_cap;
};

//-----------------------------------
// VideoSoundCapturing
//-----------------------------------
class VideoSoundCapturing
{
public:
    VideoSoundCapturing(const std::string& file, bool _auto_play = false);
    ~VideoSoundCapturing();

    static VideoSoundCapturing*  find( const std::string& f, const std::vector<VideoSoundCapturing*>& vvc);
    static void                  clear(const std::string& f, std::vector<VideoSoundCapturing*>& vvc, std::vector<VideoSoundCapturingDeleter*>& v_vcd);
    
    std::string         _file;
    cv::VideoCapture    vc;
    cv::Mat             frame;
    long                entry_frame = 0;
    std::chrono::time_point<std::chrono::system_clock> start;
    bool                done = false;
    bool                pause_unpause_pending = false;
    bool                speed_changed_pending = false;

    bool                videobar_changed_pending = false;
    float               videobar_perc = 0.0;

    sf::Music           music;
    bool                has_sound       = false;
    bool                sound_loaded    = false;
    std::string         sound_file;

    bool                open();
    void                load_sound();
    void                play_sound();
    void                recheck_sound();
    bool                readNextFrame();
    cv::Mat&            getFrame();
};


//-----------------------------------
// ExtractSound
//-----------------------------------
class ExtractSound
{
public:
    ExtractSound(const std::string& mp4_file) : _file(mp4_file)
    {
        filesystem::path p(mp4_file);
        if ((p.empty() == false) && (p.exists()) && (p.is_file()))
        {
            _thread = new std::thread(&ExtractSound::run, this);
        }
    }

    ~ExtractSound()
    {
        is_done.store(true);
        if (_thread)
        {
            _thread->join();

            delete _thread;
            _thread = nullptr;
        }
    }

#ifndef _WIN32
#define POSITIVE_ANSWER  0
#define NEGATIVE_ANSWER -1
int syscommand(std::string aCommand, std::string & result)
{
    FILE * f;
    if ( !(f = popen( aCommand.c_str(), "r" )) ) 
    {
            std::cerr << "Can not open file" << std::endl;
            return NEGATIVE_ANSWER;
    }
    const int BUFSIZE = 4096;
    char buf[ BUFSIZE ];
    if (fgets(buf,BUFSIZE,f)!=NULL) 
    {      
       result = buf;
    }
    int r = pclose( f );
    return r;
}
#endif


    void run()
    {
		try
        {
			while (is_started.load() == false)
			{
				std::this_thread::sleep_for(1000ms);
			}

			bool ok = true;
			filesystem::path file_path(_file);
			if (file_path.exists() == false)
			{
				ok = false;
				std::cerr<< "Invalid filename: " << _file << std::endl;
			}
			else if (!file_path.is_file())
			{
				ok = false;
				std::cerr<< "Invalid filename: " << _file << std::endl;
			}
        
#ifdef _WIN32
		// ffmpeg -i 0001.mp4 0001.mp4.wav
        if (ok == true)
        {
            filesystem::path cmd_path("..\\tools");
            std::string cmd = cmd_path.make_absolute().str()+"\\ffmpeg.exe -y -nostdin -i \"" + _file + "\" \"" + _file + ".wav\"";
			//std::cout << cmd << std::endl;
            int r = system(cmd.c_str());
        }
#else
        if (ok == true)
		{
            std::string cmd = "ffmpeg -y -nostdin -i \"" + _file + "\" \"" + _file + ".wav\"";
            //std::cout << cmd << std::endl;
            std::string result;
            int r = syscommand(cmd.c_str(), result);
            if (r != POSITIVE_ANSWER)
            {
                ok = false;
                std::cerr << "ffmpeg failed:[" << result << "]" << std::endl;
            }
            else
            {
                //std::cout << "ffmpeg result:[" << result << "]" << std::endl;
            }
        }

#endif
        if (ok == true)
		{
		    filesystem::path wav_path(_file + ".wav");
		    while (wav_path.exists() == false)
		    {
		        // check size...

		        if (is_done.load() == true)
		            break;
		        std::this_thread::sleep_for(10ms);
		   }
        }
		is_done.store(true);
	}
	catch(...)
	{
		std::cerr <<"Unexpect error in ExtractSound::run() " << std::endl;
		is_done.store(true);
	}
    }

    std::atomic<bool> is_started = false;
    std::string     _file;
    std::thread*    _thread = nullptr;
    std::atomic<bool> is_done = false;
};
