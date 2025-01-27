//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved  
//                  License: MIT License
//=================================================================================================
#pragma once

#include "VideoCapture.hpp"
#include "UIState.h"
#include <iostream>
#include <stdio.h>
#include <atomic>
#include <future>
#include <cassert>


VideoSoundCapturingDeleter::VideoSoundCapturingDeleter(VideoSoundCapturing* v) : vs_cap(v)
{
    if (vs_cap != nullptr)
    {
        vs_cap->music.pause();
    }
}

VideoSoundCapturingDeleter::~VideoSoundCapturingDeleter()
{
    if (vs_cap)
    {
        vs_cap->music.stop();
        delete vs_cap;
        vs_cap = nullptr;
    }
}

VideoSoundCapturing::VideoSoundCapturing(const std::string& file, bool _auto_play) : _file(file), vc(file), sound_file()
{
    filesystem::path p(file + ".wav");
    if ((p.empty() == false) && (p.exists()) && (p.is_file()))
    {
        has_sound = true;
        sound_file = p.make_absolute().str();

        load_sound(); // now music
    }
}


VideoSoundCapturing* VideoSoundCapturing::find(const std::string& f, const std::vector<VideoSoundCapturing*>& vvc)
{
    VideoSoundCapturing* r = nullptr;
    for (size_t i = 0; i < vvc.size(); i++)
    {
        if (vvc[i] != nullptr)
        {
            if (vvc[i]->_file == f)
            {
                r = vvc[i];
                break;
            }
        }
    }
    return r;
}

void VideoSoundCapturing::clear(const std::string& f, std::vector<VideoSoundCapturing*>& vvc, std::vector<VideoSoundCapturingDeleter*>& v_vcd)
{
    for (size_t i = 0; i < vvc.size(); i++)
    {
        if (vvc[i] != nullptr)
        {
            if (vvc[i]->_file == f)
            {
                v_vcd.push_back(new VideoSoundCapturingDeleter(vvc[i]));
                vvc[i] = nullptr;
                break;
            }
        }
    }
}

void VideoSoundCapturing::recheck_sound()
{
    filesystem::path p(_file + ".wav");
    if (has_sound == false)
    {
        if ((p.empty() == false) && (p.exists()) && (p.is_file()))
        {
            has_sound = true;
            sound_file = p.make_absolute().str();
        }
    }

    load_sound();
}

VideoSoundCapturing::~VideoSoundCapturing()
{
    if (has_sound)
    {
        music.stop();
    }

    //vc.release();
}


bool VideoSoundCapturing::open()
{
    if (_file.empty())
        return false;

    if (!vc.isOpened())
    {
        std::cerr << "Failed to open the video device, video file or image sequence!\n" << std::endl;
        return false;
    }
    return true;
}

void VideoSoundCapturing::load_sound()
{
    if (has_sound)
    {
        if (sound_loaded == false)
        {
            if (music.openFromFile(sound_file) == true)
            {
                sound_loaded = true;
            }
        }
    }
}

void VideoSoundCapturing::play_sound()
{
    if (has_sound && sound_loaded)
    {
        if (music.getStatus() != sf::SoundSource::Status::Playing)
        {
            music.play();
        }
    }
}

bool VideoSoundCapturing::readNextFrame()
{
    vc >> frame;
    if (frame.empty())
    {
        return false;
    }
    return true;
}

cv::Mat& VideoSoundCapturing::getFrame()
{
    return frame;
}