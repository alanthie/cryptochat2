#include "Minimap.h"
#include <iostream>

namespace gui {

    Minimap::Minimap(const std::string& name, float _w, float _h) : gui::Widget(name), w(_w), h(_h)
    {
        m_rect.setOutlineThickness(1);
        m_rect.setOutlineColor(sf::Color::Green);
        m_rect.setFillColor(sf::Color::Black);
        m_rect.setSize({ _w, _h });

        m_drag_rect.setOutlineThickness(1);
        m_drag_rect.setOutlineColor(sf::Color::Red);
        m_drag_rect.setFillColor(sf::Color::Transparent);
        m_drag_rect.setSize({ _w - 1, _h - 1 });
    }

    void Minimap::reset()
    {
        moving = false;
        ratio_offset = { 0.0f, 0.0f };

        const sf::Vector2f pos_rect = m_rect.getPosition();
        const sf::Vector2f wh_rect  = m_rect.getSize();

        m_drag_rect.setPosition(pos_rect.x + 1, pos_rect.y + 1);
        m_drag_rect.setSize({ m_rect.getSize().x - 1, m_rect.getSize().y - 1 });
    }


    void Minimap::setTexture(const sf::Texture& tex)
    {
        m_rect.setTexture(&tex);
    }

    void Minimap::handleEvent(sf::Event e, const sf::RenderWindow& win, StateBase& current_state)
    {
        auto pos = sf::Mouse::getPosition(win);
        sf::RenderWindow& window = (sf::RenderWindow&) (win);

        switch (e.type)
        {
        case sf::Event::MouseButtonPressed:
            if (m_drag_rect.getGlobalBounds().contains((float)e.mouseButton.x, (float)e.mouseButton.y) == false)
            {
                return;
            }

            if (e.mouseButton.button == 0) 
            {
                moving = true;
                oldPos = sf::Vector2f((float)e.mouseButton.x, (float)e.mouseButton.y);
            }
            break;

        case  sf::Event::MouseButtonReleased:
            if (!moving)
                break;

            if (e.mouseButton.button == 0) 
            {
                moving = false;
            }
            break;

        case sf::Event::MouseMoved:
        {
            if (!moving)
                break;

            if (m_rect.getGlobalBounds().contains((float)e.mouseMove.x, (float)e.mouseMove.y) == false)
            {
                return;
            }

            const sf::Vector2f newPos = sf::Vector2f((float)e.mouseMove.x, (float)e.mouseMove.y);
            const sf::Vector2f deltaPos = oldPos - newPos;

            // Check valid
            const sf::Vector2f p = m_drag_rect.getPosition() - deltaPos;
            if (m_rect.getGlobalBounds().contains(p.x, p.y) == false)
            {
                return;
            }
            if (m_rect.getGlobalBounds().contains(p.x + m_drag_rect.getSize().x, p.y + m_drag_rect.getSize().y) == false)
            {
                return;
            }

            m_drag_rect.setPosition(m_drag_rect.getPosition() - deltaPos);
            oldPos = sf::Vector2f((float)e.mouseMove.x, (float)e.mouseMove.y);

            const sf::Vector2f pos = m_drag_rect.getPosition();
            const sf::Vector2f pos_rect = m_rect.getPosition();
            const sf::Vector2f wh = m_drag_rect.getSize();
            const sf::Vector2f delta_pos = (pos - pos_rect - sf::Vector2f{ 1.0f, 1.0f });
            ratio_offset = sf::Vector2f{ 0.0f + (delta_pos.x / wh.x), 0.0f + (delta_pos.y / wh.y) };

            // Notifying change
            std::invoke(m_state_func, &current_state, name); // current_state->m_state_func(name)

            break;
        }
 
        //case sf::Event::MouseWheelScrolled:
        //    // Ignore the mouse wheel unless we're not moving
        //    if (moving)
        //        break;

        //    // Determine the scroll direction and adjust the zoom level
        //    // Again, you can swap these to invert the direction
        //    if (e.mouseWheelScroll.delta <= -1)
        //        zoom = std::min(2.f, zoom + .1f);
        //    else if (e.mouseWheelScroll.delta >= 1)
        //        zoom = std::max(.5f, zoom - .1f);

        //    // ...
        //    break;

        default:
            break;
        }
    }

    void Minimap::render(sf::RenderTarget& renderer)
    {
        renderer.draw(m_rect);
        renderer.draw(m_drag_rect);
    }

    void Minimap::setPosition(const sf::Vector2f& pos)
    {
        m_position = pos;
        m_rect.setPosition(m_position);

        const sf::Vector2f pos_rect = m_rect.getPosition();
        const sf::Vector2f wh = m_drag_rect.getSize();
        const sf::Vector2f wh_rect = m_rect.getSize();

        m_drag_rect.setPosition(pos_rect.x + 1.0f + std::min(ratio_offset.x * wh.x, wh_rect.x - 2.0f - m_drag_rect.getSize().x),
                                pos_rect.y + 1.0f + std::min(ratio_offset.y * wh.y, wh_rect.y - 2.0f - m_drag_rect.getSize().y));
    }

    sf::Vector2f Minimap::getSize() const
    {
        return m_rect.getSize();
    }

    void Minimap::set_view(float canvas_w, float canvas_h, sf::FloatRect canvas_bounds)
    {
        const sf::Vector2f pos_rect = m_rect.getPosition();
        const sf::Vector2f wh_rect  = m_rect.getSize();
        const sf::Vector2f pos_offset_ratio = sf::Vector2f{ 0.0f + (-1.0f * canvas_bounds.left / canvas_w), 0.0f + (-1.0f * canvas_bounds.top / canvas_h) };

        float w_ratio = 1.0f + std::max(1.0f, canvas_bounds.width/ canvas_w);
        float h_ratio = 1.0f + std::max(1.0f, canvas_bounds.height / canvas_h);

        sf::Vector2f r = m_rect.getSize() - sf::Vector2f{ 1.0f, 1.0f };
        m_drag_rect.setSize({(r.x / w_ratio)  , (r.y / h_ratio) });
        m_drag_rect.setPosition(pos_rect.x + 1.0f + std::min(pos_offset_ratio.x * m_drag_rect.getSize().x, wh_rect.x - 2.0f - m_drag_rect.getSize().x),
                                pos_rect.y + 1.0f + std::min(pos_offset_ratio.y * m_drag_rect.getSize().y, wh_rect.y - 2.0f - m_drag_rect.getSize().y));

    }
}
