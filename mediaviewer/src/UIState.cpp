//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved
//                  License: MIT License
//=================================================================================================
#include "UIState.h"
#include "SFML_SDK/Game.h"
#include "SFML_SDK/GUI/Button.h"
#include "SFML_SDK/GUI/Textbox.h"
#include "SFML_SDK/States/StateBase.h"
#include "SFML_SDK/GUI/StackMenu.h"
#include <SFML/Graphics/Texture.hpp>
#include <SFML/Graphics.hpp>
#include <SFML/Audio.hpp>

#include "opencv2/imgproc.hpp"
#include "opencv2/core/utility.hpp"
#include "opencv2/imgproc/imgproc_c.h"
#include "opencv2/highgui.hpp"

#include "tinyfiledialogs/tinyfiledialogs.h"
#include "Quiz.h"

#include <memory>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <cassert>

void UIState::img_changed()
{
    if (ui.cfg.verbose > 1)
		std::cout <<"UIState::img_changed()" << std::endl;

    minimap.reset();
    canvas_scale = { 1.0f, 1.0f };
    cnt_loop = 0;

    if (_vc != nullptr)
    {
        _vc->music.pause();

        // keep in v_vc cache
        _vc = nullptr;
    }

    //  cleanup v_vcd
    if (v_vcd.size() > 0)
    {
        bool all_done = true;
        for( size_t i=0; i< v_vcd.size(); i++)
        {
            if (v_vcd[i] != nullptr)
            {
                if (v_vcd[i]->vs_cap != nullptr)
                {
                    delete v_vcd[i];
                    v_vcd[i] = nullptr;
                }
            }
        }

        if (all_done)
        {
            v_vcd.clear();
        }
    }

    // v_vc
    if (v_vc.size() > 20)
    {
        for (size_t i = 0; i< v_vc.size() - 10; i++)
        {
            if (v_vc[i] != nullptr)
            {
                VideoSoundCapturing::clear(v_vc[i]->_file, v_vc, v_vcd);
            }
        }
    }

    quiz.reset();
}

void UIState::widget_changed(std::string& b_name)
{
    // minimap changed...
}

void UIState::widget_clicked(std::string& b_name)
{
    if (ui.cfg.verbose > 1)
		std::cout <<"UIState::widget_clicked() " << b_name << std::endl;

    if (b_name == "pbar")
    {
        if (_mode == display_mode::show_movie)
        {
            if (_vc != nullptr)
            {
                _vc->videobar_changed_pending = true;
                _vc->videobar_perc = progress_bar.perc;
            }
        }
        else if (_mode == display_mode::show_img)
        {
            if (img_files.size() > 1)
            {
                float findex = (float)index_img;
                float n = (float)img_files.size();
                int idx = (int)(progress_bar.perc * n);
                if ( (idx!= index_img) && (idx >=0) && (idx <= img_files.size() - 1) )
                {
                    index_img = idx;
                    img_changed();
                }
            }
        }
    }

    else if (b_name == "pfilebar")
    {
        if (img_files.size() > 1)
        {
            float findex = (float)index_img;
            float n = (float)img_files.size();
            int idx = (int)(progress_filebar.perc * n);
            if ((idx != index_img) && (idx >= 0) && (idx <= img_files.size() - 1))
            {
                index_img = idx;
                img_changed();
            }
        }
    }

    else if (b_name == "quiz")
    {
        if (quiz.number_quiz() > 1)
        {
            size_t k = quiz.current_quiz();
            k++;
            if (k >= quiz.number_quiz())
                k = 0;
            quiz.set_quiz(k);
        }
    }

    else if (b_name == "b_folder")
    {
        std::string default_folder;
        try
        {
            default_folder = _fnav.root.make_absolute().str();
        }
        catch(...)
        {
            std::cerr <<"Unexpect error in UIState::widget_clicked- _fnav.root.make_absolute().str()" << std::endl;
        }

        if (_fnav.current_path.empty() == false)
            default_folder = _fnav.current_path.make_absolute().str();

        std::string folder = FolderNavigation::select_folder(default_folder.c_str());
        if (folder.empty() == false)
        {
            filesystem::path path_folder(folder);
            if ((path_folder.empty() == false) && (path_folder.exists() == true) && (path_folder.is_directory() == true))
            {
                filesystem::path parent_path = path_folder.parent_path();
                if ((parent_path.empty() == false) && (parent_path.exists() == true) && (parent_path.is_directory() == true))
                {
                    // ok
                    std::string pfolder;
                    try
                    {
                        pfolder = parent_path.make_absolute().str();

                        //--------------
                        // RESET _fnav
                        //--------------
                        _fnav.reset(pfolder, path_folder);
                        load_path(path_folder);
                        while (img_files.size() == 0)
                        {
                            // TODO - check infinte loop no img...
                            _fnav.next_path();
                        }
                        img_changed();
                    }
                    catch(...)
                    {
                        std::cerr <<"Unexpect error in UIState::widget_clicked- parent_path.make_absolute().str()" << std::endl;
                    }
                }
                else
                {
                    tinyfd_messageBox("The parent folder of the selected folder should exist", folder.c_str(), "ok", "error", 1);
                }
            }
            else
            {
                tinyfd_messageBox("The selected folder is invalid", folder.c_str(), "ok", "error", 1);
            }
        }
    }

    else if (b_name == "b_pause")
    {
        is_pause = !is_pause;
        if (is_pause)
        {
            button_menu[0][0]->setText("continue");
            if (_vc != nullptr)
            {
                if (_vc->has_sound)
                {
                    _vc->music.pause();
                }
            }
        }
        else
        {
            button_menu[0][0]->setText("pause");
            if (_vc != nullptr)
            {
                _vc->pause_unpause_pending = true;
                if (_vc->has_sound)
                {
                    _vc->music.play();
                }
            }
        }
    }

    else if (b_name == "b_shot")
    {
        if ((_mode == display_mode::show_movie) && (_vc != nullptr))
        {
            cv::Mat frameRGBA;
            cv::Mat frameRGB = _vc->getFrame();
            if (!frameRGB.empty())
            {
                cv::cvtColor(frameRGB, frameRGBA, cv::COLOR_BGR2RGBA);
                {
                    std::vector<int> compression_params;
                    compression_params.push_back(cv::IMWRITE_JPEG_QUALITY);
                    compression_params.push_back(100);

                    {
                        long np = (long)_vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES);
                        std::string filePath = _fnav.current_path.make_absolute().str()  + "\\" + img_files[index_img].filename()
                                                + "_" + to_string(static_cast<long long>(np)) + ".jpg";
                        cv::imwrite(filePath, frameRGB, compression_params);
                    }
                }
            }
        }
    }

    else if (b_name == "b_img_next")
    {
        if (index_img == img_files.size() - 1)
        {
            _fnav.next_path();
            while (img_files.size() == 0)
            {
                // TODO - check infinte loop no img...
                _fnav.next_path();
            }
            img_changed();
        }
        else
        {
            index_img++;
            if (index_img > img_files.size() - 1)
            {
                index_img = 0;
            }
            img_changed();
        }
    }
    else if (b_name == "b_img_prev")
    {
        if (index_img == 0)
        {
            _fnav.prev_path();
            while (img_files.size() == 0)
            {
                // TODO - check infinte loop no img...
                _fnav.prev_path();
            }
            img_changed();
        }
        else
        {
            index_img--;
            if (index_img < 0)
            {
                index_img = (long)img_files.size() - 1;
            }
            img_changed();
        }
    }

    else if (b_name == "b_topic_prev")
    {
        _fnav.prev_path();
        while (img_files.size() == 0)
        {
            // TODO - check infinte loop no img...
            _fnav.prev_path();
        }
        img_changed();
    }
    else if (b_name == "b_topic_next")
    {
        _fnav.next_path();
        while (img_files.size() == 0)
        {
            // TODO - check infinte loop no img...
            _fnav.next_path();
        }
        img_changed();
    }

    else if (b_name == "b_zoom_plus")
    {
        canvas_scale = canvas_scale * ui.cfg.zoom;
        minimap.set_view(canvas_w, canvas_h, canvas_bounds);
    }
    else if (b_name == "b_zoom_less")
    {
        canvas_scale = canvas_scale / ui.cfg.zoom;
        minimap.set_view(canvas_w, canvas_h, canvas_bounds);
    }

    else if (b_name == "b_scale_plus")
    {
        text_scale = text_scale * 1.10f,
        button_msg.m_text.setScale(text_scale, text_scale);
        button_name.m_text.setScale(text_scale, text_scale);
        button_parts.m_text.setScale(text_scale, text_scale);

        for (int i = 0; i < 9; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                if (button_menu[i][j] != nullptr)
                {
                    button_menu[i][j]->m_text.setScale(text_scale, text_scale);
                }
            }
        }
    }
    else if (b_name == "b_scale_less")
    {
        text_scale = text_scale* 1.0f / 1.10f;
        button_msg.m_text.setScale(text_scale, text_scale);
        button_name.m_text.setScale(text_scale, text_scale);
        button_parts.m_text.setScale(text_scale, text_scale);

        for (int i = 0; i < 9; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                if (button_menu[i][j] != nullptr)
                {
                    button_menu[i][j]->m_text.setScale(text_scale, text_scale);
                }
            }
        }
    }

	else if (b_name == "b_speed_slow")
	{
        if (_mode == display_mode::show_img)
        {
            vitesse_img_sec += 1.0f;
        }
        else
        {
            vitesse_video_factor /= 1.25f;
        }
        if (_vc != nullptr)
            _vc->speed_changed_pending = true;
	}

	else if (b_name == "b_speed_fast")
	{
        const float MIN_SPEED = 0.025f;
        if (_mode == display_mode::show_img)
        {
            vitesse_img_sec *= 0.50f;
            if (vitesse_img_sec <= MIN_SPEED)
                vitesse_img_sec = MIN_SPEED;
        }
        else
        {
            vitesse_video_factor *= 1.25f;
        }
        if (_vc != nullptr)
            _vc->speed_changed_pending = true;
	}

    else if (b_name == "b_vol_plus")
    {
        sound_volume *= 1.10f;
        if (sound_volume > 100.0) sound_volume = 100.0f;
        if (_vc != nullptr)
        {
            _vc->music.setVolume(sound_volume);
        }
    }
    else if (b_name == "b_vol_less")
    {
        sound_volume /= 1.10f;
        if (sound_volume < 0.0) sound_volume = 0.0f;
        if (_vc != nullptr)
        {
            _vc->music.setVolume(sound_volume);
        }
    }
}


UIState::UIState(UImain& g) :
	StateBase(g),
	ui(g),
    _fnav(*this, ui.cfg.path_dir, ui.cfg.exclude_folder, ui.cfg.img, ui.cfg.verbose),
	button_name(    "b_name",   gui::ButtonSize::Small),
	button_parts(   "b_parts",  gui::ButtonSize::Wide),
	button_msg(     "b_msg",    gui::ButtonSize::Wide),
	minimap(        "mmap",     50, 50),
    progress_bar(   "pbar",     0, 0, 2, 2),
    progress_filebar("pfilebar", 0, 0, 2, 2),
    quiz(           "quiz",     1000, 500, 50)
{
    if (ui.cfg.verbose > 1)
		std::cout <<"UIState::UIState " << std::endl;

    // TEST
    //QuizMaker::make_all_plant_quiz("Y:\\000 quiz_plant", 1000, "Y:\\000 plant\\p", "../res/plant.txt");
    //QuizMaker::make_all_plant_quiz("Y:\\000 quiz_root", 1000, "Y:\\000 plant\\p root", "../res/root.txt");
    //QuizMaker::make_all_plant_quiz("Y:\\000 quiz_plant_medical", 1000, "Y:\\000 plant\\p medical", "../res/plant_medical.txt");

    ResourceHolder::init(ui.cfg.res_dir);

	button_name.m_text.setFont( ResourceHolder::get().fonts.get("arial"));
	button_parts.m_text.setFont(ResourceHolder::get().fonts.get("arial"));
	button_msg.m_text.setFont(  ResourceHolder::get().fonts.get("arial"));

	button_msg.m_text.setOrigin(0.0f, 0.0f);
	button_menu[0][0] = new gui::Button("b_pause",      gui::ButtonSize::Small); // m_rect.setSize({128, 64});
	button_menu[1][0] = new gui::Button("b_img_prev",   gui::ButtonSize::Small);
	button_menu[1][1] = new gui::Button("b_img_next",   gui::ButtonSize::Small);
	button_menu[2][0] = new gui::Button("b_zoom_plus",  gui::ButtonSize::Small);
	button_menu[2][1] = new gui::Button("b_zoom_less",  gui::ButtonSize::Small);
	button_menu[3][0] = new gui::Button("b_topic_prev", gui::ButtonSize::Small);
	button_menu[3][1] = new gui::Button("b_topic_next", gui::ButtonSize::Small);
    button_menu[4][0] = new gui::Button("b_shot",       gui::ButtonSize::Small);
    button_menu[4][1] = nullptr;
	button_menu[5][0] = new gui::Button("b_speed_slow", gui::ButtonSize::Small);
	button_menu[5][1] = new gui::Button("b_speed_fast", gui::ButtonSize::Small);
    button_menu[6][0] = new gui::Button("b_vol_less",   gui::ButtonSize::Small);
    button_menu[6][1] = new gui::Button("b_vol_plus",   gui::ButtonSize::Small);
    button_menu[7][0] = new gui::Button("b_folder",     gui::ButtonSize::Small);
    button_menu[7][1] = nullptr;
    button_menu[8][0] = new gui::Button("b_scale_plus", gui::ButtonSize::Small);
    button_menu[8][1] = new gui::Button("b_scale_less", gui::ButtonSize::Small);

    float b_w = button_menu[0][0]->m_text.getLocalBounds().width;
    for (int i = 0; i < 9; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            if (button_menu[i][j] != nullptr)
            {
                button_menu[i][j]->m_rect.setFillColor(sf::Color::Black);
                button_menu[i][j]->m_rect.setOutlineColor(sf::Color::Black);

                button_menu[i][j]->setFunction(&StateBase::widget_clicked);
                button_menu[i][j]->m_rect.setSize({ b_w , b_h });
            }
        }
    }

	button_menu[0][0]->setText("pause");
	button_menu[1][0]->setText("<");
	button_menu[1][1]->setText(">");
	button_menu[2][0]->setText("+");
	button_menu[2][1]->setText("-");
	button_menu[3][0]->setText("<<");
	button_menu[3][1]->setText(">>");
    button_menu[4][0]->setText("shot");
    //button_menu[4][1
	button_menu[5][0]->setText("sp-");
	button_menu[5][1]->setText("sp+");
    button_menu[6][0]->setText("vol-");
    button_menu[6][1]->setText("vol+");
    button_menu[7][0]->setText("folder");
    //button_menu[7][1]
    button_menu[8][0]->setText("txt+");
    button_menu[8][1]->setText("txt-");

    button_menu[0][0]->m_rect.setSize({ 2 * b_w , b_h });
    button_menu[4][0]->m_rect.setSize({ 2 * b_w , b_h });
    button_menu[7][0]->m_rect.setSize({ 2 * b_w , b_h });

    minimap.m_rect.setSize({ 2 * b_w , 2 * b_w, });
    //progress_bar.reset(8, canvas_h - 32, w - 16, 2);
    //progress_filebar.reset(8, canvas_h - 16, w - 16, 2);
    progress_bar.reset(8, canvas_h - 32, w - (2*b_w+8+13), 2);
    progress_filebar.reset(8, canvas_h - 16, w - (2*b_w+8+13), 2);

    button_name.setFunction(    &StateBase::widget_clicked);
    button_parts.setFunction(   &StateBase::widget_clicked);
    button_msg.setFunction(     &StateBase::widget_clicked);

    minimap.setFunction(&StateBase::widget_changed);
    progress_bar.setFunction(&StateBase::widget_clicked);
    progress_filebar.setFunction(&StateBase::widget_clicked);

    quiz.setFunction(&StateBase::widget_clicked);

    if (_fnav.current_path.empty() == false)
    {
        load_path(_fnav.current_path);
    }

    //std::cout <<"Using OpenCV version " << CV_VERSION << "\n" << std::endl;
    //std::cout << cv::getBuildInformation();

    button_msg.m_text.setScale(text_scale, text_scale);
    button_name.m_text.setScale(text_scale, text_scale);
    button_parts.m_text.setScale(text_scale, text_scale);

    for (int i = 0; i < 9; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            if (button_menu[i][j] != nullptr)
            {
                button_menu[i][j]->m_text.setScale(text_scale, text_scale);
            }
        }
    }
}


void UIState::handleEvent(sf::Event e)
{
    if (ui.cfg.verbose > 1)
		std::cout <<"UIState::handleEvent() " << std::endl;

    switch (e.type)
    {
    case sf::Event::Closed:
        break;

    case sf::Event::Resized:
        //m_pGame->getWindow().setView(sf::View(sf::FloatRect(0, 0, (float)e.size.width, (float)e.size.height)));
        recalc_size(true);

        break;

    default:
        break;
    }

    for (int i = 0; i <9; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            if (button_menu[i][j] != nullptr)
            {
                button_menu[i][j]->handleEvent(e, m_pGame->getWindow(), *this);
            }
        }
    }

    button_name.handleEvent(e,  m_pGame->getWindow(), *this);
    button_parts.handleEvent(e, m_pGame->getWindow(), *this);
    button_msg.handleEvent(e,   m_pGame->getWindow(), *this);
    minimap.handleEvent(e,      m_pGame->getWindow(), *this);
    progress_bar.handleEvent(e, m_pGame->getWindow(), *this);
    progress_filebar.handleEvent(e, m_pGame->getWindow(), *this);

    if (img_index_has_quiz == true)
    {
        quiz.handleEvent(e, m_pGame->getWindow(), *this);
    }
}

void UIState::handleInput()
{
}

//-------------------------------------------------------
// Auto move to next file (is_pause == false)
// and image delay expired or video done
//------------------------------------------------------
void UIState::update(sf::Time deltaTime)
{
    if (_mode == display_mode::show_img)
    {
        if (img_files.size() > 0)
        {
            if (is_pause == false)
            {
                cnt_loop++;
                if (cnt_loop > 60 * vitesse_img_sec) // 1 sec * vitesse_img_sec
                {
                    //----------------------------------------
                    // Auto move to next file
                    //----------------------------------------
                    index_img++;
                    if (index_img > img_files.size() - 1)
                    {
                        _fnav.next_path();
                    }
                    img_changed();
                }
            }
        }
    }

    if (_mode == display_mode::show_movie)
    {
        if (is_pause == false)
        {
            if (cnt_loop > 0)   // 0 means first time
            {
                if (_vc == nullptr) // movie is done?
                {
                    //----------------------------------------
                    // Auto move to next file
                    //----------------------------------------
                    index_img++;
                    if (index_img > img_files.size() - 1)
                    {
                        _fnav.next_path();
                        while (img_files.size() == 0)
                        {
                            // TODO check infinite loop
                            _fnav.next_path();
                        }
                    }
                    img_changed();
                }
            }
            cnt_loop++;
        }
    }

    //---------------------------------
    // sound making quota
    //---------------------------------
    if (ui.cfg.mak_wav_file == 1)
    {
        if (v_extract_sound.size() > 0)
        {
            int n_running = 0;
            for (const auto item : v_extract_sound)
            {
                if (item != nullptr)
                {
                    if ((item->is_done.load() == false) && (item->is_started.load() == true))
                    {
                        n_running++;
                    }
                }
            }

            if ((n_running < ui.cfg.make_N_sound_file) && (v_extract_sound.size() > 0))
            {
                for (const auto item : v_extract_sound)
                {
                    if (item != nullptr)
                    {
                        if ((item->is_done.load() == false) && (item->is_started.load() == false))
                        {
                            item->is_started.store(true);
                            break;
                        }
                    }
                }
            }

            // cleanup
            bool all_done = true;
            for (const auto item : v_extract_sound)
            {
                if (item != nullptr)
                {
                    if (item->is_done.load() == false)
                    {
                        all_done = false;
                        break;
                    }
                }
            }

            if (all_done)
            {
                v_extract_sound.clear();
            }

            // TODO...
            if (v_extract_sound.size() > 10)
            {
                for (int i = 0; i< v_extract_sound.size(); i++)
                {
                    //if (i < 5)
                    {
                        if (v_extract_sound[i] != nullptr)
                        {
                            if (v_extract_sound[i]->is_done == true)
                            {
                                delete v_extract_sound[i];
                                v_extract_sound[i] = nullptr;
                            }
                        }
                    }
                }
                //...
            }
        }
    }


    //---------------------------------
    // sound loading
    //---------------------------------
    if (ui.cfg.load_sound_file == 1)
    {
        for (size_t i = 0; i < v_vc.size(); i++)
        {
            if (v_vc[i] != nullptr)
            {
                if (v_vc[i]->has_sound)
                {
                    if (v_vc[i]->sound_loaded == false)
                    {
                        v_vc[i]->load_sound();
                    }
                }
            }
        }
    }

}

void UIState::fixedUpdate(sf::Time deltaTime)
{

}

void UIState::load_img_quiz()
{
    if (ui.cfg.verbose > 1)
		std::cout <<"UIState::load_img_quiz() " << std::endl;


    img_index_has_quiz = false;

    if (img_files.size() > index_img)
    {
    	if (ui.cfg.verbose > 1)
			std::cout <<"UIState::load_img_quiz() check .quiz.xml" << std::endl;

        std::string quizfile = img_files[index_img].make_absolute().str() + ".quiz.xml";
        filesystem::path quiz_path(quizfile);
        if ((quiz_path.empty() == false) && (quiz_path.exists() == true) && (quiz_path.is_file() == true))
        {
            if (quiz.is_loaded(quizfile) == true)
            {
                img_index_has_quiz = true;
            }
            else
            {
                //quiz.reset();
                if (quiz.load_quiz(quizfile) == true)
                {
                    img_index_has_quiz = true;
                }
            }
        }
    }

    if (img_files.size() > index_img)
    {
    	if (ui.cfg.verbose > 1)
			std::cout <<"UIState::load_img_quiz() check .quiz2.xml" << std::endl;

        std::string quizfile = img_files[index_img].make_absolute().str() + ".quiz2.xml";
        filesystem::path quiz_path(quizfile);
        if ((quiz_path.empty() == false) && (quiz_path.exists() == true) && (quiz_path.is_file() == true))
        {
            if (quiz.is_loaded(quizfile) == true)
            {
                img_index_has_quiz = true;
            }
            else
            {
                //quiz.reset();
                if (quiz.load_quiz(quizfile) == true)
                {
                    img_index_has_quiz = true;
                }
            }
        }
    }
}

void UIState::render(sf::RenderTarget& renderer)
{
    if (ui.cfg.verbose> 1)
		std::cout <<"UIState::render() " << std::endl;

    button_msg.setText("");

    recalc_size();
    if (img_files.size() > 0)
    {
        std::string s = img_files[index_img].extension();
        if ((s == "mp4") || (s == "avi") || (s == "mkv") || (s == "webm"))
        {
            _mode = display_mode::show_movie;
        }
        else
        {
            _mode = display_mode::show_img;
        }
    }

    // main_view
    m_pGame->getWindow().setView(main_view);
    minimap.render(renderer);

    if (_mode == display_mode::show_img)
    {
        if (img_files.size() > 0)
        {
            assert(index_img >= 0);
            assert(index_img <= img_files.size() - 1);

            if (img_texture[index_img].get() == nullptr)
            {
                img_texture[index_img] = std::shared_ptr<sf::Texture>(new sf::Texture);
				try
				{
					img_texture[index_img]->loadFromFile(img_files[index_img].make_absolute().str());
				}
				catch(...)
				{
					std::cerr <<"Unexpect error in UIState::render - img_files[index_img].make_absolute().str()" << std::endl;
				}

                //img_texture[index_img]->loadFromFile(img_files[index_img].make_absolute().str());

// do we need 1 img??
                if (index_img == 0)
                {
                    QuizMaker::make_multi_image(_fnav.current_path, img_files);
                }
            }

            if (img_texture[index_img].get() != nullptr)
            {
                if (index_img < img_files.size())
                {
                    load_img_quiz();

                    button_msg.setText( "[" + std::to_string(1 + (long)index_img) + "/" + std::to_string((long)img_files.size()) + "] "
                                        + "File: "
                                        + img_files[index_img].filename() +
                                         " [" + std::to_string(vitesse_img_sec) + " sec/img, video_speed=" + std::to_string(vitesse_video_factor) + "]" +
                                         "[wav making=" + std::to_string(count_sound_making()) + "]");
                }

                sprite_canva.reset();
                img_texture[index_img]->setSmooth(true); // TEST
                sprite_canva = std::shared_ptr<sf::Sprite>(new sf::Sprite(*img_texture[index_img].get()));
                sf::Vector2f f = scale_sprite(sprite_canva); f.x = f.x * canvas_scale.x;  f.y = f.y * canvas_scale.y;
                sprite_canva->scale(f);
                //sprite_canva->scale(scale_sprite(sprite_canva));
                //sprite_canva->scale(canvas_scale);
                sprite_canva->move(-1.0f * minimap.ratio_offset.x * canvas_w, -1.0f * minimap.ratio_offset.y * canvas_h);
                canvas_bounds = sprite_canva->getGlobalBounds();
                renderer.draw(*(sprite_canva.get()));
            }
        }

        // view_minimap
        if (img_texture.size() > 0)
        {
            if (img_texture[index_img].get() != nullptr)
            {
                sprite_canva.reset();
                sprite_canva = std::shared_ptr<sf::Sprite>(new sf::Sprite(*img_texture[index_img].get()));

                sf::FloatRect acanvas_bounds = sprite_canva->getLocalBounds();
                view_minimap.setCenter((acanvas_bounds.width) / 2.0f, (acanvas_bounds.height) / 2.0f);
                view_minimap.setSize(acanvas_bounds.width, acanvas_bounds.height);

                m_pGame->getWindow().setView(view_minimap);
                renderer.draw(*(sprite_canva.get()));
                m_pGame->getWindow().setView(main_view);
            }
        }
    }

    // main_view
    bool done = false;
    bool new_entry = false;
    if (_mode == display_mode::show_movie)
    {
        //if (is_pause == false)
        {
            if (_vc == nullptr)
            {
                if (img_files.size() > 0)
                {
                    if (img_files[index_img].empty() == false)
                    {
                        std::string msg;
                        if (index_img < img_files.size())
                        {
                            msg = "[" + std::to_string(1 + (long)index_img) + "/" + std::to_string(0 + (long)img_files.size()) + "] " +
                                "File: " +
                                img_files[index_img].filename() +
                                " [" + std::to_string(vitesse_img_sec) + " sec/img, video_speed=" + std::to_string(vitesse_video_factor) + "]"
                                + "[wav_making=" + std::to_string(count_sound_making()) + "]";

                            button_msg.setText(msg);
                        }

						bool ok = true;
						VideoSoundCapturing* r = nullptr;
						std::string fimg;
						try
						{
							fimg = img_files[index_img].make_absolute().str();
							r = VideoSoundCapturing::find(fimg, v_vc);
						}
						catch(...)
						{
							ok = false;
							std::cerr <<"Unexpect error in UIState::render - iVideoSoundCapturing::find(img_files[index_img].make_absolute().str(), v_vc);" << std::endl;
						}

						if (ok)
						{
							//VideoSoundCapturing* r = VideoSoundCapturing::find(img_files[index_img].make_absolute().str(), v_vc);
							if (r != nullptr)
							{
								//-------------------------------------
								// VideoSoundCapturing already in cache
								//-------------------------------------
								_vc = r;
								if (is_pause == false)
									_vc->play_sound();
								_vc->music.setVolume(sound_volume);
							}
							else
							{
								//----------------------------------
								// new VideoSoundCapturing
								// ----------------------------------
								_vc = new VideoSoundCapturing(fimg);
								_vc->music.setVolume(sound_volume);
								v_vc.push_back(_vc);
							}

							new_entry = true;
							long np = (long)_vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES);
							_vc->entry_frame = np;

							if (_vc->open() == false)
							{
								_vc->music.pause();
								VideoSoundCapturing::clear(_vc->_file, v_vc, v_vcd);
								_vc = nullptr;
							}
							else
							{
								if (_vc->has_sound)
								{
									if (_vc->sound_loaded == false)
									{
										_vc->load_sound();
									}
								}
								else
								{
									// Create sound file
									if (ui.cfg.mak_wav_file == 1)
									{
										v_extract_sound.push_back(new ExtractSound(fimg));
									}
								}
							}
						}
                    }
                }
            }

            if (_vc != nullptr)
            {
                if (ui.cfg.load_sound_file == 1)
                {
                    if (ui.cfg.mak_wav_file == 1)
                    {
                        if (_vc->sound_loaded == false)
                        {
                            _vc->recheck_sound();
                        }
                    }

                    if (_vc->has_sound == true)
                    {
                        if (_vc->music.getStatus() != sf::SoundSource::Status::Playing)
                        {
                            if (_vc->sound_loaded == false)
                            {
                                _vc->load_sound();
                            }

                            if (_vc->sound_loaded == true)
                            {
                                if (is_pause == false)
                                    _vc->play_sound();

                                std::string msg;
                                msg =   "[" + std::to_string(1 + (long)index_img) + "/" + std::to_string(0 + (long)img_files.size()) + "] " +
                                        "File: " +
                                        img_files[index_img].filename() +
                                        " [" + std::to_string(vitesse_img_sec) + " sec/img, video_speed=" + std::to_string(vitesse_video_factor) + "]" +
                                        "[wav_making=" + std::to_string(count_sound_making()) + "]";

                                button_msg.setText(msg);
                            }
                        }
                    }
                }

                if (is_pause == false)
                {
                    long np = (long)_vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES);
                    long nc = (long)_vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_FRAME_COUNT);
                    double fps = _vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_FPS);

                    if ( (new_entry == true) && (_vc->done == true) )
                    {
                        // reset frame
                        np = 0;
                        _vc->entry_frame = 0;
                        _vc->vc.set(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES, 0);
                        _vc->done = false;
                        if (is_pause == false)
                            _vc->play_sound();
                        _vc->music.setPlayingOffset(sf::seconds((float)0)); // if fps frame/sec
                    }
                    else if (_vc->pause_unpause_pending == true)
                    {
                       _vc->entry_frame = np;
                       _vc->vc.set(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES, np);
                       _vc->pause_unpause_pending = false;
                       if (is_pause == false)
                         _vc->play_sound();
                       float frame_time = (float)(np / fps);
                       _vc->music.setPlayingOffset(sf::seconds(frame_time));
                    }
                    else if (_vc->speed_changed_pending == true)
                    {
                        _vc->entry_frame = np;
                        _vc->vc.set(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES, np);
                        _vc->speed_changed_pending = false;
                        float frame_time = (float)(np / fps);
                        if (is_pause == false)
                            _vc->play_sound();
                        _vc->music.setPlayingOffset(sf::seconds(frame_time));
                    }
                    else if (_vc->videobar_changed_pending == true)
                    {
                        float nc = (float)_vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_FRAME_COUNT);
                        _vc->entry_frame = (long)(nc * _vc->videobar_perc);
                        if (_vc->entry_frame > nc - 1) _vc->entry_frame = (long) (nc - 1);

                        np = _vc->entry_frame;
                        _vc->vc.set(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES, np);

                        _vc->videobar_changed_pending = false;
                        float frame_time = (float)(_vc->entry_frame / fps);
                        if (is_pause == false)
                            _vc->play_sound();
                        _vc->music.setPlayingOffset(sf::seconds(frame_time));
                    }

                    if (new_entry == true)
                    {
                        _vc->entry_frame = np;
                        _vc->vc.set(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES, np);
                        _vc->speed_changed_pending = false;
                        float frame_time = (float)(np / fps);
                        if (is_pause == false)
                            _vc->play_sound();
                        _vc->music.setPlayingOffset(sf::seconds(frame_time));
                    }

                    fps = fps * vitesse_video_factor;

                    bool skip = false;
                    int pass_n = 0;
                    if (np == _vc->entry_frame)
                    {
                        _vc->start = std::chrono::system_clock::now();
                        _vc->music.setVolume(sound_volume);
                    }
                    else if (std::abs(vitesse_video_factor - 1.0f) > 0.01)
                    {
                        auto end = std::chrono::system_clock::now();
                        std::chrono::duration<double> diff_sec = end - _vc->start;

                        // ???

                        long target = _vc->entry_frame + (long) ( fps * diff_sec.count() );
                        if (target > np + 1)
                        {
                            // read more
                            pass_n = target -( np + 1);
                        }
                        else if (target < np - 1)
                        {
                            // read less
                            skip = true;
                        }
                    }
                    else if ( (std::abs(vitesse_video_factor - 1.0f) <= 0.01) && (_vc->has_sound == true) )
                    {
                        // TODO: Reset sound or frame if sound was just created...

                        sf::Time t = _vc->music.getPlayingOffset();
                        float tsec = t.asSeconds();
                        float frame_time = (float)(np / fps);
                        if ((tsec > 0.00) && (tsec < frame_time - (1.0f/fps)))
                        {
                            // WAIT SOUND!
                            skip = true;
                            pass_n = 0;
                        }
                    }

                    np = (long)_vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES);
                    nc = (long)_vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_FRAME_COUNT);
                    if (pass_n > 0)
                    {
                        np += pass_n;
                        if (np >= nc) np = nc;
                        _vc->vc.set(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES, np);
                        if (np >= nc)
                        {
                            done = true;
                            _vc->done = true;
                        }
                        else
                        {
                            _vc->readNextFrame();
                        }
                    }

                    if (skip == false)
                    {
                        if (_vc->readNextFrame() == false)
                        {
                            done = true;
                            _vc->done = true;
                        }
                    }
                }
                else
                {
                    long np = (long)_vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES);
                    if ((np == _vc->entry_frame) && (np == 0))
                    {
                        // show 1th frame
                        if (_vc->readNextFrame() == false)
                        {
                            done = true;
                            _vc->done = true;
                        }
                    }
                }

                if (done == false)
                {
                    cv::Mat frameRGBA;
                    sf::Image image;
                    sf::Texture texture;

                    cv::Mat frameRGB = _vc->getFrame();
                    if (!frameRGB.empty())
                    {
                        cv::cvtColor(frameRGB, frameRGBA, cv::COLOR_BGR2RGBA);
                        image.create(frameRGBA.cols, frameRGBA.rows, frameRGBA.ptr());
                        if (texture.loadFromImage(image))
                        {
                            sprite_canva.reset();
                            sprite_canva = std::shared_ptr<sf::Sprite>(new sf::Sprite(texture));
                            sprite_canva->scale(scale_sprite(sprite_canva));
                            sprite_canva->scale(canvas_scale);
                            sprite_canva->move(-1.0f * minimap.ratio_offset.x * canvas_w, -1.0f * minimap.ratio_offset.y * canvas_h);
                            canvas_bounds = sprite_canva->getGlobalBounds();
                            renderer.draw(*(sprite_canva.get()));

                            // view_minimap
                            {
                                sprite_canva.reset();
                                sprite_canva = std::shared_ptr<sf::Sprite>(new sf::Sprite(texture));

                                sf::FloatRect acanvas_bounds = sprite_canva->getLocalBounds();
                                view_minimap.setCenter((acanvas_bounds.width) / 2.0f, (acanvas_bounds.height) / 2.0f);
                                view_minimap.setSize(acanvas_bounds.width, acanvas_bounds.height);

                                m_pGame->getWindow().setView(view_minimap);
                                renderer.draw(*(sprite_canva.get()));
                                m_pGame->getWindow().setView(main_view);
                            }
                        }

                        double np = _vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_POS_FRAMES); // retrieves the current frame number
                        double nc = _vc->vc.get(cv::VideoCaptureProperties::CAP_PROP_FRAME_COUNT);
                        button_msg.setText("[" + std::to_string(1 + (long)index_img) + "/" + std::to_string(0 + (long)img_files.size()) + "] "
                            + "File: "
                            + img_files[index_img].filename() + " - " + std::to_string((long)np) + "/" + std::to_string((long)nc)
                            + " [" + std::to_string(vitesse_img_sec) + " sec/img, video_speed=" + std::to_string(vitesse_video_factor) + "]"
                            + "[wav_making=" + std::to_string(count_sound_making()) + "]");

                        if (nc > 0)
                        {
                            progress_bar.setPerc(((float)(0 + np)) / (float)nc);
                        }
                        else
                        {
                            progress_bar.setPerc(0.0f);
                        }
                    }
                }
                else
                {
                    // done
                    _vc->music.pause();

                    // keep for a awhile
                    _vc = nullptr;
                }
            }
        }
    }

    //else if (_mode == display_mode::show_img)
    {
        if (img_files.size() > 0)
        {
            progress_filebar.setPerc(((float)(1 + index_img)) / (float)img_files.size());
        }
        else
        {
            progress_filebar.setPerc(0.0f);
        }
    }

    for (int i = 0; i < 9; i++)
    {
        for (int j = 0; j < 2; j++)
        {
            if (button_menu[i][j] != nullptr)
            {
                if (button_menu[i][j]->hasMouse(ui.getWindow()))
                {
                    button_menu[i][j]->m_rect.setFillColor(sf::Color::Green);
                    button_menu[i][j]->m_rect.setOutlineColor(sf::Color::Black);
                }
                else
                {
                    button_menu[i][j]->m_rect.setFillColor(sf::Color::Black);
                    button_menu[i][j]->m_rect.setOutlineColor(sf::Color::Green);
                }

                button_menu[i][j]->render(renderer);
            }
        }
    }

    button_name.render(renderer);
    button_parts.render(renderer);
    button_msg.render(renderer);

    renderer.draw(minimap.m_drag_rect);

    if (_mode == display_mode::show_movie)
    {
        progress_bar.render(renderer);
        renderer.draw(progress_bar.m_drag_rect);
    }

    if (_mode == display_mode::show_img)
    {
        if (img_index_has_quiz == true)
        {
            quiz.render(renderer);
        }
    }

    progress_filebar.render(renderer);
    renderer.draw(progress_filebar.m_drag_rect);
}

void UIState::recalc_size(bool is_resizing)
{
    if (ui.cfg.verbose > 1)
		std::cout <<"UIState::recalc_size() " << std::endl;

    w = (float)ui.getWindow().getSize().x;
    h = (float)ui.getWindow().getSize().y;

    canvas_w = (float)(canvas_x_perc * w);
    canvas_h = (float)(h - 2 * b_h - 1.0f);

    float b_w = (float)(w - canvas_w - 1) / 2;

    button_menu[0][0]->setPosition({ canvas_w, 1 });
    button_menu[0][0]->m_rect.setSize({ 2 * b_w  , b_h });
    button_menu[1][0]->m_rect.setSize({ b_w , b_h });
    button_menu[1][1]->m_rect.setSize({ b_w  , b_h });
    button_menu[2][0]->m_rect.setSize({ b_w , b_h });
    button_menu[2][1]->m_rect.setSize({ b_w , b_h });
    button_menu[3][0]->m_rect.setSize({ b_w , b_h });
    button_menu[3][1]->m_rect.setSize({ b_w , b_h });
	button_menu[4][0]->m_rect.setSize({ 2 * b_w , b_h });
	//button_menu[4][1]
    button_menu[5][0]->m_rect.setSize({ b_w , b_h });
    button_menu[5][1]->m_rect.setSize({ b_w , b_h });
    button_menu[6][0]->m_rect.setSize({ b_w , b_h });
    button_menu[6][1]->m_rect.setSize({ b_w , b_h });
    button_menu[7][0]->m_rect.setSize({ 2 * b_w , b_h });
    // button_menu[7][1]
    button_menu[8][0]->m_rect.setSize({ b_w , b_h });
    button_menu[8][1]->m_rect.setSize({ b_w , b_h });

    button_menu[1][0]->setPosition({ canvas_w, b_h });
    button_menu[1][1]->setPosition({ canvas_w + b_w, b_h });
    button_menu[2][0]->setPosition({ canvas_w, 2*b_h });
    button_menu[2][1]->setPosition({ canvas_w + b_w, 2*b_h });
    button_menu[3][0]->setPosition({ canvas_w, 3 * b_h });
    button_menu[3][1]->setPosition({ canvas_w + b_w, 3 * b_h });
    button_menu[4][0]->setPosition({ canvas_w, 8 * b_h });
    // button_menu[4][1]
	button_menu[5][0]->setPosition({ canvas_w, 9 * b_h });
	button_menu[5][1]->setPosition({ canvas_w + b_w, 9 * b_h });
    button_menu[6][0]->setPosition({ canvas_w, 10 * b_h });
    button_menu[6][1]->setPosition({ canvas_w + b_w, 10 * b_h });
    button_menu[7][0]->setPosition({ canvas_w, 11 * b_h });
    // button_menu[7][1]
    button_menu[8][0]->setPosition({ canvas_w, 12 * b_h });
    button_menu[8][1]->setPosition({ canvas_w + b_w, 12 * b_h });

    float mmap_w = 2 * b_w;
    minimap.m_rect.setSize({ mmap_w , 4 * b_h, });
    if (is_resizing)
    {
        minimap.m_drag_rect.setSize({ minimap.m_rect.getSize().x - 1, minimap.m_rect.getSize().y - 1 });
        minimap.set_view(canvas_w, canvas_h, canvas_bounds);
    }

    if (minimap.moving == false)
    {
        minimap.setPosition({ canvas_w, 4 * b_h });
        if (is_resizing)
        {
            minimap.m_drag_rect.setPosition(minimap.m_rect.getPosition().x + 1, minimap.m_rect.getPosition().y + 1);
            minimap.set_view(canvas_w, canvas_h, canvas_bounds);
        }
    }

    button_name.setPosition({ (float)1, canvas_h });
    button_name.m_rect.setSize({ (float)((button_parts.m_text.getString().getSize() == 0)? w-1: w/3 ) , b_h });

    button_parts.setPosition({ button_name.getSize().x , canvas_h });
    button_parts.m_rect.setSize({ w - (button_name.getSize().x + 1) , b_h });

    button_msg.m_rect.setSize({ w - 2.0f, b_h });
    button_msg.setPosition({ 1 , canvas_h + b_h });

    main_view.setCenter(w / 2.0f, h / 2.0f);
    main_view.setSize(w, h);
    main_view.setViewport(sf::FloatRect(0.0f, 0.0f, 1.0f, 1.0f));

    view_minimap.setCenter(canvas_w / 2.0f, canvas_h / 2.0f);
    view_minimap.setSize(canvas_w, canvas_h);
    view_minimap.setViewport(sf::FloatRect(minimap.m_rect.getPosition().x / w , minimap.m_rect.getPosition().y / h, minimap.m_rect.getSize().x / w, minimap.m_rect.getSize().y / h));

    //progress_bar.reset(8, canvas_h - 32, w - 16, 2);
    //progress_filebar.reset(8, canvas_h - 16, w - 16, 2);
    progress_bar.reset(8, canvas_h - 32, w - (2*b_w+8+13), 2);
    progress_filebar.reset(8, canvas_h - 16, w - (2*b_w+8+13), 2);

    if (_mode == display_mode::show_img)
    {
        if (img_index_has_quiz == true)
        {
            quiz.setPosition(sf::Vector2f(canvas_w - quiz.getSize().x, 0));
        }
    }
}

sf::Vector2f UIState::scale_sprite(std::shared_ptr<sf::Sprite> sprite)
{
    if (ui.cfg.verbose > 1)
		std::cout <<"UIState::scale_sprite() " << std::endl;

    float sx = (canvas_w) / (float)sprite->getTextureRect().width;
    float sy = (canvas_h) / (float)sprite->getTextureRect().height;
    return sf::Vector2f{ std::min(sx, sy), std::min(sx, sy) };
    //return sf::Vector2f{ 1.0f,  1.0f, };
}

void UIState::load_path(filesystem::path& p)
{
    if (ui.cfg.verbose > 1)
		std::cout <<"UIState::load_path() " << std::endl;

	try
	{
		ini_filename.clear();
		img_files.clear();
		img_texture.clear();

		index_img = 0;
		cnt_loop = 0;
		ini.reset();

		button_name.setText("");
		button_parts.setText("");

		std::string fullname;
		try
		{
			fullname = p.make_absolute().str();
		}
		catch(...)
		{
			std::cerr <<"Unexpect error in UIState::load_path() - std::string fullname = p.make_absolute().str(); " << std::endl;
		}
		try
		{
			_fnav.root.make_absolute().str();
		}
		catch(...)
		{
			std::cerr <<"Unexpect error in UIState::load_path() - _fnav.root.make_absolute().str() " << std::endl;
		}

		std::string name;
		try
		{
			name = std::string("Folder: ") + fullname;

 		  //path      /home/allaptop/dev/test/cryptochat_5614/000_chat_session/current_20241231_143702
 		  //fullname  /home/allaptop/dev/test/cryptochat_5614/000_chat_session/current_20241231_143702
 		  //fnav.root /home/allaptop/dev/test/cryptochat_5614/000_chat_session

			//std::string::size_type n;
			//n = fullname.find(_fnav.root.make_absolute().str());
			//if (std::string::npos != n)
			//{
				//if (n + 1 + _fnav.root.make_absolute().str().size() < fullname.size())
				//{
					//name = std::string("Folder: ") + fullname.substr(n + 1 + _fnav.root.make_absolute().str().size());
				//}
			//}
		}
		catch(...)
		{
			std::cerr <<"Unexpect error in UIState::load_path() - name = fullname.substr(fullname.find(_fnav.root.make_absolute().str()) + _fnav.root.make_absolute().str().size());" << std::endl;
			std::cerr <<" 		  path      " << p.str()  << std::endl;
			std::cerr <<" 		  fullname  " << fullname << std::endl;
			std::cerr <<" 		  fnav.root " << _fnav.root.str() << std::endl;
		}

		std::string desc;
		ui.getWindow().setTitle(ui.cfg.title);// + " [" + p.make_absolute().str() + "]");

		std::vector<std::string> files;
		try
		{
			files = filesystem::path::get_directory_file(p, false);
		}
		catch(...)
		{
			std::cerr <<"Unexpect error in UIState::load_path() - std::vector<std::string> files = filesystem::path::get_directory_file(p, false);" << std::endl;
		}

		for (size_t i = 0; i < files.size(); i++)
		{
			filesystem::path pv = files.at(i);
			if (pv.is_file())
			{
				std::string s = pv.extension();
				std::transform(s.begin(), s.end(), s.begin(), ::tolower);
				if (std::find(ui.cfg.img.begin(), ui.cfg.img.end(), s) != ui.cfg.img.end())
				{
					img_files.push_back(pv);

					if (ui.cfg.verbose > 1)
						std::cout <<"UIState::load_path() register:" << files.at(i) << std::endl;
				}

				if (pv.extension() == "ini")
				{
					if (pv.filename() == "desc.ini")
					{
						if (ui.cfg.verbose > 1)
							std::cout <<"UIState::load_path() check desc.ini" << std::endl;

						ini = std::shared_ptr<ini_parser>(new ini_parser(pv.make_absolute().str()));

						try
						{
							name = ini->get_string("name", "main");
						}
						catch (...)
						{
						}

						std::string key;
						try
						{
							key = ini->get_string("key", "parts");
						}
						catch (...)
						{
						}

						std::string value;
						try
						{
							value = ini->get_string("value", "parts");
						}
						catch (...)
						{
						}

						if (key.size() > 0)
						{
							std::vector<std::string> parts = Config::split(value, ';');
							desc = key + ": " + Config::merge(parts);
						}
					}
				}
			}
		}

		if (img_files.size() > 0)
			std::sort(img_files.begin(), img_files.end(), filesort);

		for (size_t i = 0; i < img_files.size(); i++)
		{
			std::shared_ptr<sf::Texture> texture(nullptr);
			img_texture.push_back(texture);
		}

		// No img/video in this folder
		if (img_files.size() == 0)
		{
			if (ui.cfg.verbose > 1)
				std::cout <<"UIState::load_path() no imag or videos in folder" << std::endl;
		}

		if (files.size() > 0)
		{
			button_name.setText(name);
			button_parts.setText(desc);
		}
		button_msg.setText("");
	}
	catch (const std::exception& e)
	{
		std::cerr <<"Unexpect error in UIState::load_path() err " << e.what() << std::endl;
	}
	catch(...)
	{
		std::cerr <<"Unexpect error in UIState::load_path() catch(...) path:" << p.str() << std::endl;
	}

}

int UIState::count_sound_making()
{
    if (ui.cfg.verbose > 1)
    {
		std::cout <<"UIState::count_sound_making() " << std::endl;
    }

	try
	{
	    int n = 0;
	    for (size_t i = 0; i < v_extract_sound.size(); i++)
	    {
		if (v_extract_sound[i] != nullptr)
		{
		    if ((v_extract_sound[i]->is_done.load() == false) && (v_extract_sound[i]->is_started.load() == true))
		    {
		        n++;
		    }
		}
	    }
	    return n;
	}
	catch(...)
	{
		std::cerr <<"Unexpect error in count_sound_making()" << std::endl;
	}

}
