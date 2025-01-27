#pragma once


#include "StateBase.h"
#include "../GUI/StackMenu.h"
#include "../GUI/Textbox.h"
#include <SFML/Graphics/Texture.hpp>
#include <SFML/Graphics.hpp>
#include <memory>

//    Game state for the main part of the game
//
class StatePlaying : public StateBase
{
    public:
        StatePlaying(Game& game);

        void handleEvent    (sf::Event e)                   override;
        void handleInput    ()                              override;
        void update         (sf::Time deltaTime)            override;
        void fixedUpdate    (sf::Time deltaTime)            override;
        void render         (sf::RenderTarget& renderer)    override;

    private:
        gui::StackMenu m_TestMenu;

        std::string txt_content;
        gui::TextBox txt;

        std::shared_ptr<sf::Texture> texture;
        std::shared_ptr<sf::Sprite> sprite;
};
