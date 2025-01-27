//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved
//                  License: MIT License
//=================================================================================================
#pragma once

#include "FolderNavigation.h"
#include "UIState.h"
//#include "tinyfiledialogs/tinyfiledialogs.h"
#include "tinyfiledialogsv318/tinyfiledialogs.h"
#include <iostream>
#include <stdio.h>
#include <atomic>
#include <future>
#include <cassert>

FolderNavigation::FolderNavigation(UIState& st,
                                    const std::string& _path_dir,
                                    const std::vector<std::string>& _exclude_folder,
                                    const std::vector<std::string>& _img,
                                    int pverbose) :
    _state(st),
    path_dir(_path_dir),
    exclude_folder(_exclude_folder),
    img(_img),
    verbose(pverbose)
{
    if (verbose > 0)
    	std::cout <<"FolderNavigation::FolderNavigation()" << std::endl;

    // root = filesystem::path("..\\res\\topic");
    root            = filesystem::path(path_dir);
    root_files      = filesystem::path::get_directory_file(root, false, true); // no recursive, ONLY FOLDERS

    current_parent  = filesystem::path(root);
    filesystem::path lEmptyPath = filesystem::path();
    current_path    = find_next_folder(root, lEmptyPath);
}

void FolderNavigation::reset(const std::string& new_root, const filesystem::path& new_current_path)
{
    if (verbose > 0)
		std::cout <<"FolderNavigation::reset()" << std::endl;

    path_dir    = new_root;
    root        = filesystem::path(new_root);
    root_files  = filesystem::path::get_directory_file(root, false, true);
    current_parent  = filesystem::path(root);
    current_path    = new_current_path;
}

FolderNavigation::~FolderNavigation()
{
}

void FolderNavigation::load_root()
{
    if (verbose > 0)
    		std::cout <<"FolderNavigation::load_root()" << std::endl;

    // Restart
    current_parent  = filesystem::path(root);
    filesystem::path lEmptyPath = filesystem::path();
    current_path    = find_next_folder(root, lEmptyPath);

    if (current_path.empty() == false)
    {
        _state.load_path(current_path);
    }
    else
    {
        assert(false);
    }
}


std::vector<std::string> FolderNavigation::get_img_files(filesystem::path& p)
{
    if (verbose > 0)
    	std::cout <<"FolderNavigation::get_img_files()" << std::endl;

    std::vector<std::string> imgfiles;
    std::vector<std::string> files = filesystem::path::get_directory_file(p, false);
    for (size_t i = 0; i < files.size(); i++)
    {
        filesystem::path pv = files.at(i);
        if (pv.is_file())
        {
            std::string s = pv.extension();
            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
            if (std::find(img.begin(), img.end(), s) != img.end())
            {
                imgfiles.push_back(pv.make_absolute().str());
            }
        }
    }
    return imgfiles;
}

void FolderNavigation::next_path(bool no_deepening)
{
    if (verbose > 0)
		std::cout <<"FolderNavigation::next_path()" << std::endl;

    filesystem::path save_current_path = current_path;
    filesystem::path save_current_parent = save_current_path.parent_path();

	if (save_current_parent.empty())
	{
		std::cerr <<"Unexpect error in FolderNavigation::next_path - save_current_parent.empty()" << std::endl;
		std::cerr <<"		  current_path " << current_path.str() << std::endl;
	}
    assert(save_current_parent.empty() == false);

    current_path = find_next_folder(save_current_parent, save_current_path, no_deepening);

    std::string str_current_path;
    std::string str_root;
    if (current_path.empty() == true)
    {
		try
		{
			str_current_path = save_current_parent.make_absolute().str();
		}
		catch(...)
		{
			std::cerr <<"Unexpect error in FolderNavigation::next_path - save_current_parent.make_absolute().str()" << std::endl;
		}
		try
		{
			str_root = root.make_absolute().str();
		}
		catch(...)
		{
			std::cerr <<"Unexpect error in FolderNavigation::next_path - root.make_absolute().str()" << std::endl;
		}
    }

    if (current_path.empty() == false)
    {
        if (current_parent != current_path.parent_path())
        {
            current_parent = current_path.parent_path();
        }

        if (current_path.empty() == false)
        {
            _state.load_path(current_path);
        }
        else
        {
            assert(false);
        }
    }
    else if (str_current_path == str_root)
    {
        // Restart
        load_root();
        return;
    }
    else
    {
        current_path = save_current_parent;
        current_parent = save_current_parent.parent_path();
        try
        {
            str_current_path = save_current_parent.make_absolute().str();
        }
        catch(...)
        {
            std::cerr <<"Unexpect error in FolderNavigation::next_path 2 - save_current_parent.make_absolute().str()" << std::endl;
        }
        try
        {
            str_root = root.make_absolute().str();
        }
        catch(...)
        {
            std::cerr <<"Unexpect error in FolderNavigation::next_path 2 - root.make_absolute().str()" << std::endl;
        }

        if (str_current_path == str_root)
        {
            // Restart
            load_root();
            return;
        }

        current_path = find_next_folder(current_parent, current_path, true);
        while (current_path.empty() == true)
        {
            current_path = save_current_parent.parent_path();
            current_parent = save_current_parent.parent_path().parent_path();
            try
            {
                str_current_path = current_path.make_absolute().str();
            }
            catch(...)
            {
                std::cerr <<"Unexpect error in FolderNavigation::next_path 2 - save_current_parent.make_absolute().str()" << std::endl;
            }
            try
            {
                str_root = root.make_absolute().str();
            }
            catch(...)
            {
                std::cerr <<"Unexpect error in FolderNavigation::next_path 2 - root.make_absolute().str()" << std::endl;
            }

            if (str_current_path == str_root)
            {
                // Restart
                load_root();
                return;
            }

            next_path(true);
        }

        if (current_path.empty() == false)
        {
            _state.load_path(current_path);
        }
        else
        {
            std::cerr <<"Error in FolderNavigation::next_path - current_path.empty()" << std::endl;
            assert(false);
        }
    }
}

void FolderNavigation::prev_path(bool no_deepening)
{
    if (verbose > 0)
       std::cout <<"FolderNavigation::prev_path()" << std::endl;

    filesystem::path save_current_path = current_path;
    filesystem::path save_current_parent = save_current_path.parent_path();

    current_path = find_prev_folder(save_current_parent, save_current_path, no_deepening);
    if (current_path.empty() == false)
    {
        current_parent = current_path.parent_path();
        if (current_path.make_absolute().str() == root.make_absolute().str())
        {
            // Restart
            load_root();
            return;
        }
        else
        {
            if (current_path.empty() == false)
            {
                _state.load_path(current_path);
            }
            else
            {
                assert(false);
            }
        }
    }
    else
    {
        current_path = save_current_parent;
        current_parent = save_current_parent.parent_path();

        if ((current_path.empty() == true) || (current_path.make_absolute().str() == root.make_absolute().str()))
        {
            // Restart
            load_root();
            return;
        }

        if (current_path.empty() == false)
        {
            current_parent = current_path.parent_path();
            _state.load_path(current_path);
        }
        else
        {
            assert(false);
        }
    }
}

filesystem::path FolderNavigation::find_next_folder(filesystem::path& parent_folder, filesystem::path& last_folder, bool no_deepening)
{
    if (verbose > 0)
        std::cout <<"FolderNavigation::find_next_folder()" << std::endl;

    filesystem::path p;
    if (last_folder.empty())
    {
        std::vector<std::string> v = filesystem::path::get_directory_file(parent_folder, false, true);
        for (size_t i = 0; i < v.size(); i++)
        {
            if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v[i]).filename()) == exclude_folder.end())
            {
                filesystem::path lImgPath = filesystem::path(v[i]);
                std::vector<std::string> vf = get_img_files(lImgPath);
                if (vf.size() > 0)
                {
                    p = filesystem::path(v[i]);
                    return p;
                }
                else
                {
                    std::vector<std::string> v_sub = filesystem::path::get_directory_file(filesystem::path(v[i]), false, true);
                    for (size_t j = 0; j < v_sub.size(); j++)
                    {
                        if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v_sub[j]).filename()) == exclude_folder.end())
                        {
                            filesystem::path lImgPathJ = filesystem::path(v_sub[j]);
                            std::vector<std::string> vf = get_img_files(lImgPathJ);
                            if (vf.size() > 0)
                            {
                                p = filesystem::path(v_sub[j]);
                                return p;
                            }
                            else
                            {
                                std::vector<std::string> v_sub_sub = filesystem::path::get_directory_file(filesystem::path(v_sub[j]), false, true);
                                for (size_t k = 0; k < v_sub_sub.size(); k++)
                                {
                                    if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v_sub_sub[k]).filename()) == exclude_folder.end())
                                    {
                                        filesystem::path lImgPathK = filesystem::path(v_sub_sub[k]);
                                        std::vector<std::string> vff = get_img_files(lImgPathK);
                                        if (vff.size() > 0)
                                        {
                                            p = filesystem::path(v_sub_sub[k]);
                                            return p;
                                        }
                                        else
                                        {
                                            // TODO...
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        std::vector<std::string> v = filesystem::path::get_directory_file(parent_folder, false, true);
        int k = 0;
        for (int i = 0; i < v.size(); i++)
        {
            if (v[i] == last_folder.make_absolute().str())
            {
                k = i;
                break;
            }
        }

        if (no_deepening == false)
        {
            std::vector<std::string> v_sub = filesystem::path::get_directory_file(last_folder, false, true);
            for (size_t j = 0; j < v_sub.size(); j++)
            {
                if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v_sub[j]).filename()) == exclude_folder.end())
                {
                    filesystem::path lImgPathJ = filesystem::path(v_sub[j]);
                    std::vector<std::string> vf_sub = get_img_files(lImgPathJ);
                    if (vf_sub.size() > 0)
                    {
                        p = filesystem::path(v_sub[j]);
                        return p;
                    }
                    else
                    {
                        std::vector<std::string> v_sub_sub = filesystem::path::get_directory_file(filesystem::path(v_sub[j]), false, true);
                        for (size_t k = 0; k < v_sub_sub.size(); k++)
                        {
                            if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v_sub_sub[k]).filename()) == exclude_folder.end())
                            {
                                filesystem::path lImgPathK = filesystem::path(v_sub_sub[k]);
                                std::vector<std::string> vff = get_img_files(lImgPathK);
                                if (vff.size() > 0)
                                {
                                    p = filesystem::path(v_sub_sub[k]);
                                    return p;
                                }
                                else
                                {
                                    // TODO...
                                }
                            }
                        }
                    }
                }
            }
        }

        for (int i = k + 1; i < v.size(); i++)
        {
            if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v[i]).filename()) == exclude_folder.end())
            {
                filesystem::path lImgPathi = filesystem::path(v[i]);
                std::vector<std::string> vf = get_img_files(lImgPathi);
                if (vf.size() > 0)
                {
                    p = filesystem::path(v[i]);
                    break;
                }
            }

            std::vector<std::string> v_sub = filesystem::path::get_directory_file(filesystem::path(v[i]), false, true);
            for (size_t j = 0; j < v_sub.size(); j++)
            {
                if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v_sub[j]).filename()) == exclude_folder.end())
                {
                    filesystem::path lImgPathj = filesystem::path(v_sub[j]);
                    std::vector<std::string> vf_sub = get_img_files(lImgPathj);
                    if (vf_sub.size() > 0)
                    {
                        p = filesystem::path(v_sub[j]);
                        return p;
                    }
                }
            }
        }

    }

    return p;
}

filesystem::path FolderNavigation::find_last_folder(filesystem::path& parent_folder)
{
    if (verbose > 0)
    	std::cout <<"FolderNavigation::find_last_folder()" << std::endl;

    filesystem::path p;

    std::vector<std::string> v = filesystem::path::get_directory_file(parent_folder, false, true);
    for (size_t i = v.size() - 1; i >= 0; i--)
    {
        if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v[i]).filename()) == exclude_folder.end())
        {
            filesystem::path lImgPath = filesystem::path(v[i]);
            std::vector<std::string> vf = get_img_files(lImgPath);
            if (vf.size() > 0)
            {
                p = filesystem::path(v[i]);
                break;
            }
        }
    }
    return p;
}

filesystem::path FolderNavigation::find_prev_folder(filesystem::path& parent_folder, filesystem::path& last_folder, bool no_deepening)
{
    if (verbose > 0)
    	std::cout <<"FolderNavigation::find_prev_folder()" << std::endl;

    filesystem::path p;
    if (last_folder.empty())
    {
        std::vector<std::string> v = filesystem::path::get_directory_file(parent_folder, false, true);
        for (size_t i = 0; i < v.size(); i++)
        {
            if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v[i]).filename()) == exclude_folder.end())
            {
                filesystem::path lImgPath = filesystem::path(v[i]);
                std::vector<std::string> vf = get_img_files(lImgPath);
                if (vf.size() > 0)
                {
                    p = filesystem::path(v[i]);
                    break;
                }
            }
        }
    }
    else
    {
        std::vector<std::string> v = filesystem::path::get_directory_file(parent_folder, false, true);
        int k = 0;
        for (int i = 0; i < v.size(); i++)
        {
            if (v[i] == last_folder.make_absolute().str())
            {
                k = i;
                break;
            }
        }

        for (int i = k - 1; i >= 0; i--)
        {
            if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v[i]).filename()) == exclude_folder.end())
            {
                filesystem::path lImgPath = filesystem::path(v[i]);
                std::vector<std::string> vf = get_img_files(lImgPath);
                if (vf.size() > 0)
                {
                    p = filesystem::path(v[i]);
                    break;
                }
            }
        }

        // at root
    }

    return p;
}


filesystem::path FolderNavigation::preview_next_path(bool no_deepening)
{
    if (verbose > 0)
    	std::cout <<"FolderNavigation::preview_next_path()" << std::endl;

    filesystem::path ret_path;
    filesystem::path save_current_path      = current_path;
    filesystem::path save_current_parent    = save_current_path.parent_path();

    assert(save_current_parent.empty() == false);

    current_path = find_next_folder(save_current_parent, save_current_path, no_deepening);
    if (current_path.empty() == false)
    {
        if (current_parent != current_path.parent_path())
        {
            current_parent = current_path.parent_path();
        }

        if (current_path.empty() == false)
        {
            ret_path        = current_path;
            current_path    = save_current_path;
            current_parent = save_current_parent;
            return ret_path;
        }
        else
        {
            assert(false);
        }
    }
    else if (save_current_parent.make_absolute().str() == root.make_absolute().str())
    {
        // Restart
        //load_root();
        filesystem::path lEmptyPath = filesystem::path();
        ret_path        = find_next_folder(root, lEmptyPath);
        current_path    = save_current_path;
        current_parent  = save_current_parent;
        return ret_path;
    }
    else
    {
        current_path = save_current_parent;
        current_parent = save_current_parent.parent_path();
        if (current_path.make_absolute().str() == root.make_absolute().str())
        {
            // Restart
            //load_root();
            filesystem::path lEmptyPath = filesystem::path();
            ret_path        = find_next_folder(root, lEmptyPath);
            current_path    = save_current_path;
            current_parent  = save_current_parent;
            return ret_path;
        }

        current_path = find_next_folder(current_parent, current_path, true);
        while (current_path.empty() == true)
        {
            current_path = save_current_parent.parent_path();
            current_parent = save_current_parent.parent_path().parent_path();

            if (current_path.make_absolute().str() == root.make_absolute().str())
            {
                // Restart
                //load_root();
                filesystem::path lEmptyPath = filesystem::path();
                ret_path        = find_next_folder(root, lEmptyPath);
                current_path    = save_current_path;
                current_parent  = save_current_parent;
                return ret_path;
            }

            ret_path        = preview_next_path(true);
            current_path    = save_current_path;
            current_parent = save_current_parent;
            return ret_path;
        }

        if (current_path.empty() == false)
        {
            ret_path        = current_path;
            current_path    = save_current_path;
            current_parent  = save_current_parent;
            return ret_path;
        }
        else
        {
            assert(false);
        }
    }
    return ret_path;
}

std::string FolderNavigation::select_folder(char const * const aDefaultPath)
{
    char const * lTheSelectFolderName;
    lTheSelectFolderName = tinyfd_selectFolderDialog("Select a directory", aDefaultPath);
    if (!lTheSelectFolderName)
    {
        return std::string();
    }
    if (strcmp(aDefaultPath, lTheSelectFolderName) != 0)
        return std::string(lTheSelectFolderName);
    return std::string();
}
