//=================================================================================================
//                  Copyright (C) 2018 Alain Lanthier, Samuel Lanthier - All Rights Reserved  
//                  License: MIT License
//=================================================================================================
#pragma once

#include "tinyxml2/tinyxml2.h"
#include "filesystem/path.h"
#include <string>
#include <vector>

using namespace tinyxml2;

//< ? xml version = "1.0" ? >
//
//<Quiz>
//  <Type>one_response</Type>
//  <Subject>Plant Identification</Subject>
//  <Question>What is the name of this plant ? </Question>
//  <Image> .. / dandelion.jpg</Image>
//  <Choice>
//      <Text>Dandelion</Text>
//  <Response>true</Response>
//  </Choice>
//  <Choice>
//      <Text>Burdock</Text>
//  <Response>false</Response>
//  </Choice>
//  <Choice>
//      <Text>Sow Thistle</Text>
//  <Response>false</Response>
//  </Choice>
//  <Choice>
//      <Text>Salsify</Text>
//      <Response>false</Response>
//  </Choice>
//</Quiz>

enum class quiz_type { one_response, multi_response};

class QuizChoice
{
public:
    std::string _text;
    bool _is_true;
};

class Quiz
{
public:
    quiz_type _type;
    std::string _subject;
    std::string _question;
    std::string _image;
    std::vector<QuizChoice> _choice;

    int read_xml(const std::string& filename);
    void clear() { _choice.clear(); }
};

class QuizMaker
{
public:

    static void make_multi_image(const filesystem::path& current_path, const std::vector<filesystem::path>& img_files);
    static void dump_folders(const filesystem::path& current_path, bool recursive, const std::string& outfilename, bool overwrite);
    static std::vector<std::string> read_file(const std::string& infilename);

    static void make_all_plant_quiz(const std::string& quiz_folder, int start_sequ, const std::string& plant_folder, const std::string& plant_file);

    static void copy_file(const std::string& src, const std::string& dst);
};