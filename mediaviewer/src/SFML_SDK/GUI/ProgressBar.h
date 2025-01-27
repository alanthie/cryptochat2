#pragma once

#include <functional>
#include "Widget.h"

typedef void (StateBase::*StateBaseMemFn)(std::string& name);

namespace gui
{
    class ProgressBar : public gui::Widget
    {
    public:
        ProgressBar(const std::string& name, float x, float y, float w, float h);
        void reset(float _x, float _y, float w, float h);

        void setFunction(StateBaseMemFn f) { m_state_func = f; }
        void setTexture(const sf::Texture& tex);

        void handleEvent(sf::Event e, const sf::RenderWindow& window, StateBase& current_state) override;
        void render(sf::RenderTarget& renderer) override;
        void setPosition(const sf::Vector2f& pos)   override;

        void setPerc(float _perc) { perc = _perc; }

        sf::Vector2f getSize() const override;

        float x;
        float y;
        float w;
        float h;
        float perc = 0.0f;

        sf::Vector2f    m_position;
        Rectangle       m_rect;
        StateBaseMemFn  m_state_func;

        Rectangle       m_drag_rect;
        sf::Vector2f    oldPos;
        bool            moving = false;

    };
}