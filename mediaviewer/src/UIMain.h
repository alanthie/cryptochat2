//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved  
//                  License: MIT License
//=================================================================================================
#pragma once

#include "SFML_SDK/Game.h"
#include "Config.hpp"
#include <string>

class UImain : public Game
{
public:
    UImain(Config& _cfg);

    Config cfg;
};
