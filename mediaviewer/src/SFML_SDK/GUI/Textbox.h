#pragma once

#include <functional>

#include "Widget.h"

namespace gui
{
    class TextBox : public gui::Widget
    {
        public:
            TextBox(const std::string& n, std::string& modString);

            void setLabel       (const std::string& str);
            //void setTexture     (const sf::Texture& tex); // TODO

            void handleEvent    (sf::Event e, const sf::RenderWindow& window, StateBase& g) override;
            void render         (sf::RenderTarget& renderer)    override;
            void setPosition    (const sf::Vector2f& pos)       override;
            sf::Vector2f getSize() const                        override;

        private:
            void handleClick    (sf::Event e, const sf::RenderWindow& window);
            void handleTextInput(sf::Event e);

            bool isValidCharacter   (unsigned char keyCode);
            bool isBackspace        (unsigned char keycode);

            sf::Vector2f    m_position;

            Rectangle       m_rect;
            Text            m_text;
            Text            m_label;
            std::string*    m_pModString;

            bool m_isActive = false;
    };

    inline std::unique_ptr<TextBox> makeTextBox(const std::string& n, std::string& modStr) { return std::make_unique<TextBox>(n, modStr); }
}
