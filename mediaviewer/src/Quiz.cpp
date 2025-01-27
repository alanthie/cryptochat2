//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved  
//                  License: MIT License
//=================================================================================================
#pragma once

#include "Quiz.h"
#include "filesystem/path.h"
#include "filesystem/resolver.h"
#include "ini_parser/ini_parser.hpp"
#include <SFML/Graphics/Texture.hpp>

#include <opencv2/opencv.hpp>

#include <iostream>
#include <fstream> 


int Quiz::read_xml(const std::string& filename)
{
    tinyxml2::XMLDocument doc;
    doc.LoadFile(filename.c_str());
    int  r = doc.ErrorID();

    Quiz& quiz = *this;;

    if (r == XML_SUCCESS)
    {
        {
            XMLElement* element = doc.FirstChildElement("Quiz")->FirstChildElement("Type");
            const char* str = element->GetText();
            if (strcmp(str, "one_response") == 0) quiz._type = quiz_type::one_response;
            else quiz._type = quiz_type::multi_response;
        }
        {
            XMLElement* element = doc.FirstChildElement("Quiz")->FirstChildElement("Subject");
            const char* str = element->GetText();
            quiz._subject = std::string(str);
        }
        {
            XMLElement* element = doc.FirstChildElement("Quiz")->FirstChildElement("Question");
            const char* str = element->GetText();
            quiz._question = std::string(str);
        }
        {
            XMLElement* element = doc.FirstChildElement("Quiz")->FirstChildElement("Image");
            const char* str = element->GetText();
            quiz._image = std::string(str);
        }

        {
            XMLElement* element = doc.FirstChildElement("Quiz")->FirstChildElement("Choice");
            while (true)
            {
                QuizChoice choix;
                {
                    XMLElement* element2 = element->FirstChildElement("Text");
                    const char* str = element2->GetText();
                    choix._text = std::string(str);
                }
                {
                    XMLElement* element2 = element->FirstChildElement("Response");
                    const char* str = element2->GetText();
                    choix._is_true = (std::string(str) == "true" ? true : false);
                }

                quiz._choice.push_back(choix);

                element = element->NextSiblingElement();
                if (element == nullptr)
                    break;
            }
        }
    }

    return r;
}


void QuizMaker::make_multi_image(const filesystem::path& current_path, const std::vector<filesystem::path>& img_files)
{
    const int MAX_IMG = 18;
    std::string fsave = current_path.make_absolute().str() + "\\" + "000_all.jpg";
    filesystem::path filesave(fsave);
    if ((filesave.empty() == false) && (filesave.exists() == false))
    {
        if ((current_path.empty() == false) && (current_path.exists() == true) && (current_path.is_directory() == true))
        {
            int cnt = 0;
            std::vector<std::string> img = { "jpg",  "png", "jpeg", "bmp" };

            for (size_t i = 0; i < img_files.size(); i++)
            {
                if (std::find(img.begin(), img.end(), img_files[i].extension()) != img.end())
                {
                    cnt++;
                    if (cnt >= MAX_IMG)
                        break;
                }
            }

            if (cnt == 0)
                return;

            int rows = 1 + (int)((cnt - 1) / 3);
            int cols = 3;
            if (cnt < 3) cols = cnt;
            const int W = 800;
            const int H = 800;

            // Create a white image
            cv::Mat3b res(rows * H, cols * W, cv::Vec3b(255, 255, 255));

            int r = 0;
            int c = -1;
            int n = 0;
            for (size_t i = 0; i < img_files.size(); i++)
            {
                if (std::find(img.begin(), img.end(), img_files[i].extension()) != img.end())
                {
                    cv::Mat3b img1 = cv::imread(img_files[i].make_absolute().str());
                    if (img1.empty() == false)
                    {
                        n++;
                        if (n > cnt)
                            break;

                        c++;
                        if (c >= 3)
                        {
                            r++;
                            c = 0;
                        }

                        float ratio_x = img1.cols / (float)W;
                        float ratio_y = img1.rows / (float)H;
                        float factor = 1.0f / std::max(ratio_x, ratio_y);

                        cv::Mat3b outImg;
                        if (factor < 1.0)
                            cv::resize(img1, outImg, cv::Size( (int) (img1.cols * factor), int (img1.rows * factor) ), 0, 0, cv::INTER_AREA);
                        else
                            cv::resize(img1, outImg, cv::Size( (int) (img1.cols * factor), int (img1.rows * factor)) , 0, 0, cv::INTER_LINEAR);

                        // Copy image in correct position
                        outImg.copyTo(res(cv::Rect(c*W, r*H, outImg.cols, outImg.rows)));
                    }
                }
            }
            //cv::imshow("Result", res);
            cv::imwrite(fsave, res);
        }
    }
}

void QuizMaker::dump_folders(const filesystem::path& path, bool recursive, const std::string& outfilename, bool overwrite)
{
    std::vector<std::string> exclude_folder = { ".Thumbs" };
    std::vector<std::string> v = filesystem::path::get_directory_file(path, recursive, true);
    std::string root = path.make_absolute().str() + "\\";

    filesystem::path f_outfilename(outfilename);
    if (overwrite == false)
    {
        if (f_outfilename.exists() == true)
            return;
    }

    std::ofstream outfile(outfilename);
    for (size_t j = 0; j < v.size(); j++)
    {
        if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v[j]).filename()) == exclude_folder.end())
        {
            size_t n = v[j].find(root);
            std::string s = v[j].substr(n + root.size());
            outfile << s << "\n";
        }
    }
    outfile.close();
}

std::vector<std::string> QuizMaker::read_file(const std::string& infilename)
{
    std::vector<std::string> v;
    filesystem::path f_outfilename(infilename);
    if (f_outfilename.exists() == false)
        return v;

    std::string s;
    std::ifstream infile(infilename);

    if (infile.is_open())
    {
        while (std::getline(infile, s))
        {
            v.push_back(s);
        }
    }
    infile.close();
    return v;
}

void QuizMaker::make_all_plant_quiz(const std::string& quiz_folder, int start_sequ, const std::string& plant_folder, const std::string& plant_file)
{
    std::vector<std::string> img = { "jpg",  "png", "jpeg", "bmp" };

    //QuizMaker::dump_folders(filesystem::path("Y:\\000 plant\\p"), true, "../res/plant.txt", false);
    //std::vector<std::string> v = QuizMaker::read_file("../res/plant.txt");
    QuizMaker::dump_folders(filesystem::path(plant_folder), true, plant_file, false);
    std::vector<std::string> vp = QuizMaker::read_file(plant_file);

    std::vector<std::string> exclude_folder = { ".Thumbs" };
    std::vector<std::string> v = filesystem::path::get_directory_file(filesystem::path(plant_folder), true, true);
    std::string root = filesystem::path(plant_folder).make_absolute().str() + "\\";

    int sequ = start_sequ;
    for (size_t j = 0; j < v.size(); j++)
    {
        if (std::find(exclude_folder.begin(), exclude_folder.end(), filesystem::path(v[j]).filename()) == exclude_folder.end())
        {
            std::string jpg = v[j] + "\\" + "000_all.jpg";

            filesystem::path fmake_jpg(jpg);
            if (fmake_jpg.exists() == false)
            {
                std::vector<filesystem::path> img_files;
                std::vector<std::string> files = filesystem::path::get_directory_file(filesystem::path(v[j]), false);
                for (size_t i = 0; i < files.size(); i++)
                {
                    filesystem::path pv = files.at(i);
                    if (pv.is_file())
                    {
                        std::string s = pv.extension();
                        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
                        if (std::find(img.begin(), img.end(), s) != img.end())
                        {
                            img_files.push_back(pv);
                        }
                    }
                }

                if (img_files.size() > 0)
                {
                    QuizMaker::make_multi_image(filesystem::path(v[j]), img_files);
                }            
            }

            filesystem::path f_jpg(jpg);
            if (f_jpg.exists() == true)
            {
                try
                {
                    std::string outxmlfilename = quiz_folder + "\\" + std::to_string(sequ) + ".jpg.quiz.xml";
                    std::ofstream outxmlfile(outxmlfilename);
                    outxmlfile << "<?xml version=\"1.0\"?>" << "\n";
                    outxmlfile << "<Quiz>" << "\n";

                    outxmlfile << "<Type>one_response</Type>" << "\n";
                    outxmlfile << "<Subject>Plant Identification</Subject>" << "\n";
                    outxmlfile << "<Question>What is the name of this plant?</Question>" << "\n";
                    outxmlfile << "<Image>" << jpg << "</Image>" << "\n";

                    size_t n = v[j].find(root);
                    std::string s = v[j].substr(n + root.size());

                    int r = rand() % 6;
                    for (int i = 0; i < 6; i++)
                    {
                        if (i == r)
                        {
                            outxmlfile << "<Choice>" << "\n";
                            outxmlfile << "<Text>" << s << "</Text>" << "\n";
                            outxmlfile << "<Response>true</Response>" << "\n";
                            outxmlfile << "</Choice>" << "\n";
                        }
                        else
                        {
                            int c = rand() % vp.size();

                            outxmlfile << "<Choice>" << "\n";
                            outxmlfile << "<Text>" << vp[c] << "</Text>" << "\n";
                            outxmlfile << "<Response>false</Response>" << "\n";
                            outxmlfile << "</Choice>" << "\n";
                        }
                    }
                    outxmlfile << "</Quiz>" << "\n";
                    outxmlfile.close();

                    std::string outjpgfilename = quiz_folder + "\\" + std::to_string(sequ) + ".jpg";
                    copy_file(jpg, outjpgfilename);
                }
                catch (...)
                {
                    std::cout << "error" << std::endl;
                }
                sequ++;
            }
        }
    }
}


void QuizMaker::copy_file(const std::string& src, const std::string& dst)
{
    std::ifstream source(src, std::ios::binary);
    std::ofstream dest(dst, std::ios::binary);

    // file size
    source.seekg(0, std::ios::end);
    std::ifstream::pos_type size = source.tellg();
    source.seekg(0);
    // allocate memory for buffer
    char* buffer = new char[size];

    // copy file    
    source.read(buffer, size);
    dest.write(buffer, size);

    // clean up
    delete[] buffer;
    source.close();
    dest.close();
}
