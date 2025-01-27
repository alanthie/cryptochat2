#pragma once

#include <unordered_map>
#include <string>

/**
    Holds all the resources of the game
*/
template<typename Resource>
class ResourceManager
{
    public:
        ResourceManager (const std::string& path_to_res, const std::string& folder, const std::string& extention)
        :   m_folder    (path_to_res + "/" + folder + "/")
            //m_folder    ("res/" + folder + "/")
        ,   m_extention ("." + extention)
        {
            if (path_to_res.empty())
            {
            }
        }

        const Resource& get(const std::string& name)
        {
            if (!exists(name)) {
                add(name);
            }

            return m_resources.at(name);
        }

        bool exists(const std::string& name) const
        {
            return m_resources.find(name) != m_resources.end();
        }

//text1.setCharacterSize(30);
// SFML provides a default built-in font, which is Arial with a character size of 30
//    When working with small fonts, it’s recommended to load the font with a character size that matches the size you intend to use for your text. For instance,
//    if you want to display text with a size of 15, you should load the font with a character size of 15:
//    if (!font.loadFromFile("arial.ttf", 15)) {
//        // Handle error
//    }
        void add(const std::string& name)
        {
            Resource r;

            //if the resource fails to load, then it adds a default "fail" resource
            if(!r.loadFromFile(getFullFilename(name)))
            {
                Resource fail;
                fail.loadFromFile(m_folder + "_fail_" + m_extention);
                m_resources.insert(std::make_pair(name, fail));
            }
            else
            {
                m_resources.insert(std::make_pair(name, r));
            }
        }

    private:
        std::string getFullFilename(const std::string& name)
        {
            return m_folder + name + m_extention;
        }

        const std::string m_folder;
        const std::string m_extention;

        std::unordered_map<std::string, Resource> m_resources;
};
