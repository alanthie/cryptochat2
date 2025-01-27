#include "Button.h"
#include <iostream>
#include <cmath>

namespace gui {

sf::Vector2f round(const sf::Vector2f vector)
{
    return sf::Vector2f{ std::round(vector.x), std::round(vector.y) };
}

Button::Button(const std::string& name, ButtonSize s) : gui::Widget(name)
{
    m_rect.setOutlineThickness(1);
    m_rect.setOutlineColor(sf::Color::Green);
    m_rect.setFillColor(sf::Color::Black);
    switch (s)
    {
        case ButtonSize::Wide:
            m_rect.setSize({256, 64});
            break;

        case ButtonSize::Small:
            m_rect.setSize({128, 64});
            break;
    }
}

void Button::setText (const std::string& str)
{
    m_text.setString(str);
    updateText();
}

void Button::setTexture (const sf::Texture& tex)
{
    m_rect.setTexture(&tex);
}

bool Button::hasMouse(const sf::RenderWindow& window)
{
    auto pos = sf::Mouse::getPosition(window);
    return m_rect.getGlobalBounds().contains((float)pos.x, (float)pos.y);
}

void Button::handleEvent(sf::Event e, const sf::RenderWindow& window, StateBase& current_state)
{
    auto pos = sf::Mouse::getPosition(window);

    switch(e.type)
    {
        case sf::Event::MouseButtonPressed:
            switch(e.mouseButton.button)
            {
                case sf::Mouse::Left:
                    if (m_rect.getGlobalBounds().contains((float)pos.x, (float)pos.y))
                    {
                        std::invoke(m_state_func, &current_state, name); // current_state->m_state_func(name)
                    }

                default:
                    break;
            }

        default:
            break;
    }
}

void Button::render(sf::RenderTarget& renderer)
{
    renderer.draw(m_rect);
    renderer.draw(m_text);
}

void Button::setPosition(const sf::Vector2f& pos)
{
    m_position = pos;

    m_rect.setPosition(m_position);
    m_text.setPosition(m_position);

    updateText();
}

void Button::updateText()
{
    auto textRect = m_text.getLocalBounds();
    auto btnRect  = m_rect.getLocalBounds();
    m_text.setOrigin(0.0f, 0.0f);
    m_text.setPosition(m_rect.getPosition());

    //m_text.setOrigin(m_text.getGlobalBounds().getSize() / 2.f + m_text.getLocalBounds().getPosition());
    //m_text.setPosition(m_rect.getPosition() + (m_rect.getSize() / 2.f));

    // TODO
    // SCALING has produce distortion in centering...
    m_text.move((btnRect.left + btnRect.width - (textRect.left + textRect.width))/2,
                (btnRect.top + btnRect.height - (textRect.top + textRect.height))/2 );
}

sf::Vector2f Button::getSize() const
{
    return m_rect.getSize();
}

}
