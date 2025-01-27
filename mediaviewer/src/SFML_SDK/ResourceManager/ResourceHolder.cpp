#include "ResourceHolder.h"

ResourceHolder* ResourceHolder::_instance = nullptr;

void ResourceHolder::init(const std::string& apath_to_res)
{
    if (_instance == nullptr)
    {
        _instance = new ResourceHolder(apath_to_res);
    }
    else
    {
		 // get was call before init...
	}
}

ResourceHolder& ResourceHolder::get()
{
    //static ResourceHolder holder;
    if (_instance == nullptr)
    {
        _instance = new ResourceHolder("res"); // TODO error...
    }
    return *_instance;;
}

ResourceHolder::ResourceHolder(const std::string& apath_to_res)
    :   fonts           (apath_to_res, "fonts", "ttf")
    ,   textures        (apath_to_res, "txrs", "png")
    ,   soundBuffers    (apath_to_res, "sfx", "ogg")
{
}



