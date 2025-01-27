#include "ProgressBar.h"
#include <iostream>

namespace gui {

    ProgressBar::ProgressBar(const std::string& name, float _x, float _y, float _w, float _h) : gui::Widget(name), x(_x), y(_y), w(_w), h(_h)
    {
        m_rect.setOutlineThickness(1);
	sf::Color co = sf::Color(128,128, 128);
        m_rect.setOutlineColor(co);
        m_rect.setFillColor(co);
        m_rect.setSize({ _w, _h });
        m_rect.setPosition({ x, y });

        m_drag_rect.setOutlineThickness(1);
        m_drag_rect.setOutlineColor(sf::Color::Red);
        m_drag_rect.setFillColor(sf::Color::Red);

        m_drag_rect.setPosition(m_rect.getPosition().x, m_rect.getPosition().y);
        m_drag_rect.setSize({ perc * m_rect.getSize().x, 2 });
    }

    void ProgressBar::reset(float _x, float _y, float _w, float _h)
    {
        x = _x; y = _y;
        w = _w; h = _h;
        moving = false;

        m_rect.setSize({ w, h });
        m_rect.setPosition({ x, y });

        m_drag_rect.setPosition(m_rect.getPosition().x, m_rect.getPosition().y);
        m_drag_rect.setSize({ perc * m_rect.getSize().x, 2 });
    }


    void ProgressBar::setTexture(const sf::Texture& tex)
    {
        m_rect.setTexture(&tex);
    }

    void ProgressBar::handleEvent(sf::Event e, const sf::RenderWindow& win, StateBase& current_state)
    {
        auto pos = sf::Mouse::getPosition(win);
        sf::RenderWindow& window = (sf::RenderWindow&) (win);

        switch (e.type)
        {
        case sf::Event::MouseButtonPressed:
            switch (e.mouseButton.button)
            {
            case sf::Mouse::Left:
                if (m_rect.getGlobalBounds().contains((float)pos.x, (float)pos.y))
                {
                    float percent = pos.x / w;
                    if (percent < 0.0) perc = 0.0;
                    if (percent > 1.0) perc = 1.0;
                    setPerc(percent);

                    std::invoke(m_state_func, &current_state, name); // current_state->m_state_func(name)
                }

            default:
                break;
            }
       
        default:
            break;
        }
    }

    void ProgressBar::render(sf::RenderTarget& renderer)
    {
        renderer.draw(m_rect);
        renderer.draw(m_drag_rect);
    }

    void ProgressBar::setPosition(const sf::Vector2f& pos)
    {
        m_position = pos;
        m_rect.setPosition(m_position);

        m_drag_rect.setPosition(m_rect.getPosition().x + perc * m_rect.getSize().x, m_rect.getPosition().y + h / 2 - 2);
        m_drag_rect.setSize({ 4, h + 4 });
    }

    sf::Vector2f ProgressBar::getSize() const
    {
        return m_rect.getSize();
    }
}
