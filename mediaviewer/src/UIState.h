//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved
//                  License: MIT License
//=================================================================================================
#pragma once

#include "UIMain.h"
#include "SFML_SDK//GUI/Button.h"
#include "SFML_SDK//GUI/Textbox.h"
#include "SFML_SDK/States/StateBase.h"
#include "SFML_SDK/GUI/StackMenu.h"
#include "SFML_SDK/GUI/Button.h"
#include "SFML_SDK/GUI/Minimap.h"
#include "SFML_SDK/GUI/ProgressBar.h"
#include "SFML_SDK/GUI/GuiQuiz.h"

#include <SFML/Graphics/Texture.hpp>
#include <SFML/Graphics.hpp>
#include "FolderNavigation.h"
#include "VideoCapture.hpp"

enum class display_mode {show_img, show_movie};

class UIState : public StateBase
{
public:
    UImain&                     ui;
    sf::View                    main_view;
    display_mode                _mode = display_mode::show_img;
    FolderNavigation            _fnav;

    VideoSoundCapturing*                     _vc = nullptr;  // current
    std::vector<VideoSoundCapturing*>        v_vc;           // caches
    std::vector<VideoSoundCapturingDeleter*> v_vcd;
    std::vector<ExtractSound*>               v_extract_sound;

    float                       sound_volume = 100.0;
    gui::Button*                button_menu[9][2] = { {nullptr}, { nullptr },{ nullptr } ,{ nullptr } ,{ nullptr } ,{ nullptr },{ nullptr },{ nullptr },{ nullptr } };
    gui::Button                 button_name;
    gui::Button                 button_parts;
    gui::Button                 button_msg;
    std::shared_ptr<sf::Sprite> sprite_canva;
    gui::Minimap                minimap;
    sf::View                    view_minimap;
    gui::ProgressBar            progress_bar;
    gui::ProgressBar            progress_filebar;

    bool                        img_index_has_quiz = false;
    gui::GuiQuiz                quiz;

    bool                        is_pause = false;

    std::string                 ini_filename;
    std::shared_ptr<ini_parser> ini;

    long                                        index_img = 0;
    long                                        cnt_loop = 0;
	float							            vitesse_img_sec         = 3.0f;         // SEC
    float							            vitesse_video_factor    = 1.0f;
    std::vector<filesystem::path>               img_files;
    std::vector<std::shared_ptr<sf::Texture>>   img_texture;

    float canvas_x_perc = 0.85f;
    float w;
    float h;
    float canvas_w;
    float canvas_h;
    float b_h = 30;//50;
    sf::FloatRect canvas_bounds;

    float text_scale = 1.0f; // use smaller font setCharacterSize (15);

public:
    UIState(UImain& g);

    void img_changed();

    void handleEvent(sf::Event e) override;
    void handleInput() override;
    void update(sf::Time deltaTime) override;
    void fixedUpdate(sf::Time deltaTime) override;
    void render(sf::RenderTarget& renderer) override;

    void load_img_quiz();

    void            recalc_size(bool is_resizing = false);
    sf::Vector2f    scale_sprite(std::shared_ptr<sf::Sprite> sprite);
    sf::Vector2f    canvas_scale = { 1.0f, 1.0f };

    void load_path(filesystem::path& p);

    void widget_clicked(std::string& b_name) override;
    void widget_changed(std::string& b_name) override;

    int count_sound_making();
};

inline bool filesort(const filesystem::path& a, const filesystem::path& b)
{
    std::string sa = a.make_absolute().str();
    std::string sb = b.make_absolute().str();
    std::string sae = a.extension();
    std::string sbe = b.extension();
    if ((sae == "jpg") && (sbe == "jpg"))
    {
        if (sa.size() == sb.size())
        {
            return a.make_absolute().str() < b.make_absolute().str();
        }
        else
        {
            return sa.size() < sb.size();
        }
    }
    else
    {
        return a.make_absolute().str() < b.make_absolute().str();
    }
}
