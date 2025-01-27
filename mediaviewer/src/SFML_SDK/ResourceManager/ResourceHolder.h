#pragma once

#include <SFML/Graphics.hpp>
#include <SFML/Audio.hpp>

#include "ResourceManager.h"
#include "../Util/NonCopyable.h"
#include "../Util/NonMoveable.h"

class ResourceHolder : public NonCopyable, public NonMovable
{
    public:
        static void init(const std::string& apath_to_res);
        static ResourceHolder& get();

        ResourceManager<sf::Font>           fonts;
        ResourceManager<sf::Texture>        textures;
        ResourceManager<sf::SoundBuffer>    soundBuffers;

    private:
        ResourceHolder(const std::string& apath_to_res);

        static ResourceHolder* _instance;

        ~ResourceHolder()
        {
            if (_instance!=nullptr)
                delete _instance;
        }

};
