#pragma once

#include <functional>
#include "Widget.h"

typedef void (StateBase::*StateBaseMemFn)(std::string& name);

namespace gui
{
    class Minimap : public gui::Widget
    {
    public:
        Minimap(const std::string& name, float w, float h);
        void reset();

        void setFunction(StateBaseMemFn f) { m_state_func = f; }
        void setTexture(const sf::Texture& tex);

        void handleEvent(sf::Event e, const sf::RenderWindow& window, StateBase& current_state) override;
        void render(sf::RenderTarget& renderer) override;
        void setPosition(const sf::Vector2f& pos)   override;

        sf::Vector2f getSize() const override;

        float w;
        float h;

        sf::Vector2f    m_position;
        Rectangle       m_rect;
        StateBaseMemFn  m_state_func;

        Rectangle       m_drag_rect;
        sf::Vector2f    oldPos;
        bool            moving = false;
        //float           zoom = 1;
        sf::Vector2f    ratio_offset = { 0.0f, 0.0f };

        void set_view(float canvas_w, float canvas_h, sf::FloatRect canvas_bounds);
    };
}