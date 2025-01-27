#pragma once

#include <functional>
#include "Widget.h"

typedef void (StateBase::*StateBaseMemFn)(std::string& name);

namespace gui
{
    enum class ButtonSize
    {
        Small,
        Wide,
    };

    class Button : public gui::Widget
    {
        public:
            Button(const std::string& name, ButtonSize s = ButtonSize::Wide);

            void setFunction(StateBaseMemFn f) { m_state_func = f; }
            void setText    (const std::string& str);
            void setTexture (const sf::Texture& tex);

            void handleEvent    (sf::Event e, const sf::RenderWindow& window, StateBase& current_state) override;
            void render         (sf::RenderTarget& renderer) override;
            void setPosition    (const sf::Vector2f& pos)   override;
            sf::Vector2f getSize() const    override;

            void updateText();
            bool hasMouse(const sf::RenderWindow& window);

            sf::Vector2f    m_position;
            Rectangle       m_rect;
            Text            m_text;
            StateBaseMemFn  m_state_func;
    };

    inline std::unique_ptr<Button> makeButton(const std::string& n) { return std::make_unique<Button>(n); }
    inline std::shared_ptr<Button> makeSharedButton(const std::string& n) { return std::make_shared<Button>(n); }
}