//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved
//                  License: MIT License
//=================================================================================================
#include "UIMain.h"
#include "UIState.h"
#include "SFML_SDK/Game.h"
#include <string>

//#include "SFML_SDK/ResourceManager/ResourceHolder.h"
//build/mediaviewer$ ./mediaviewer ../../mediaviewer/prj/LearnTool.ini

UImain::UImain(Config& _cfg) :
    Game(_cfg.default_w, _cfg.default_h, _cfg.title, _cfg.res_dir),
    cfg(_cfg)
{
//std::cerr << "res_dir: " << _cfg.res_dir << std::endl;

    //ResourceHolder::init(_cfg.res_dir);
    pushState<UIState>(*this);
}

