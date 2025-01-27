#include "StatePlaying.h"

#include "../GUI/Button.h"
#include "../GUI/Textbox.h"
#include "../Game.h"

#include <iostream>

StatePlaying::StatePlaying(Game& game)
    :   StateBase   (game),
        m_TestMenu  (game.getWindow(), 50),
        txt("2", txt_content)
{
    //auto b = std::make_unique<gui::Button>();
    //b->setText("Button 1");
    //b->setFunction([]() {
    //    std::cout << "Button 1 clicked!" << '\n';
    //});

    //auto b2 = std::make_unique<gui::Button>();
    //b2->setText("Button 2");
    //b2->setFunction([]() {
    //    std::cout << "Button 2 clicked!" << '\n';
    //});

    //m_TestMenu.addWidget(std::move(b));
    //m_TestMenu.addWidget(std::move(b2));

    txt.setLabel("label");
    txt.setPosition({ 500, 300 });

    texture = std::shared_ptr<sf::Texture>(new sf::Texture());
    texture->loadFromFile("..\\res\\img\\220px-ShikraTrap.jpg");

    sprite = std::shared_ptr<sf::Sprite>(new sf::Sprite(*texture));
    sprite->scale(sf::Vector2f{ 600.0f / sprite->getTextureRect().width, 600.0f / sprite->getTextureRect().height });
}

void StatePlaying::handleEvent(sf::Event e)
{
    m_TestMenu.handleEvent(e, m_pGame->getWindow(), *this);
    txt.handleEvent(e, m_pGame->getWindow(), *this);
}

void StatePlaying::handleInput()
{
}

void StatePlaying::update(sf::Time deltaTime)
{

}

void StatePlaying::fixedUpdate(sf::Time deltaTime)
{

}

void StatePlaying::render(sf::RenderTarget& renderer)
{
    renderer.draw(*(sprite.get()));
    m_TestMenu.render(renderer);
    txt.render(renderer);
}
