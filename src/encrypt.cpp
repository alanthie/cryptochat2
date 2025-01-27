#ifndef _INCLUDES_encrypt_H
#define _INCLUDES_encrypt_H

#include <cstdint>
#include <sstream>
#include <iostream>
#include <string>

#include "../include/encrypt.h"
#include "../include/Base64.h"
#include "../include/vigenere.hpp"
#include "../include/netw_msg.hpp"


template <typename T> std::string makehex(T value, unsigned int size = 2 * sizeof(T), bool caps = false) {
    if (!size) {
        std::stringstream out;
        out << std::hex << value;
        return out.str();
    }

    std::string out(size, '0');
    while (value && size) {
        if (caps) {
            out[--size] = "0123456789ABCDEF"[value & 15];
        }
        else {
            out[--size] = "0123456789abcdef"[value & 15];
        }
        value >>= 4;
    }
    return out;
}

// https://stackoverflow.com/questions/17316506/strip-invalid-utf8-from-string-in-c-c
std::string sanitize_utf8(const std::string& str)
{
    int i,f_size= (int)str.size();
    unsigned char c,c2,c3,c4;
    c2=0;
    std::string to;
    to.reserve(f_size);

    for(i=0 ; i<f_size ; i++)
    {
        c=(unsigned char)(str)[i];
        if(c<32)
        {
            //control char
            if(c==9 || c==10 || c==13){//allow only \t \n \r
                to.append(1,c);
            }
            continue;
        }
        else if(c<127)
        {
            //normal ASCII
            to.append(1,c);
            continue;
        }
        else if(c<160){//control char (nothing should be defined here either ASCI, ISO_8859-1 or UTF8, so skipping)
            if(c2==128){//fix microsoft mess, add euro
                to.append(1, (char)226);
                to.append(1, (char)130);
                to.append(1, (char)172);
            }
            if(c2==133){//fix IBM mess, add NEL = \n\r
                to.append(1,10);
                to.append(1,13);
            }
            continue;
        }else if(c<192){//invalid for UTF8, converting ASCII
            to.append(1,(unsigned char)194);
            to.append(1,c);
            continue;
        }else if(c<194){//invalid for UTF8, converting ASCII
            to.append(1,(unsigned char)195);
            to.append(1,c-64);
            continue;
        }else if(c<224 && i+1<f_size){//possibly 2byte UTF8
            c2=(unsigned char)(str)[i+1];
            if(c2>127 && c2<192){//valid 2byte UTF8
                if(c==194 && c2<160){//control char, skipping
                    ;
                }else{
                    to.append(1,c);
                    to.append(1,c2);
                }
                i++;
                continue;
            }
        }else if(c<240 && i+2<f_size){//possibly 3byte UTF8
            c2=(unsigned char)(str)[i+1];
            c3=(unsigned char)(str)[i+2];
            if(c2>127 && c2<192 && c3>127 && c3<192){//valid 3byte UTF8
                to.append(1,c);
                to.append(1,c2);
                to.append(1,c3);
                i+=2;
                continue;
            }
        }else if(c<245 && i+3<f_size){//possibly 4byte UTF8
            c2=(unsigned char)(str)[i+1];
            c3=(unsigned char)(str)[i+2];
            c4=(unsigned char)(str)[i+3];
            if(c2>127 && c2<192 && c3>127 && c3<192 && c4>127 && c4<192){//valid 4byte UTF8
                to.append(1,c);
                to.append(1,c2);
                to.append(1,c3);
                to.append(1,c4);
                i+=3;
                continue;
            }
        }
        //invalid UTF8, converting ASCII (c>245 || string too short for multi-byte))
        to.append(1,(unsigned char)195);
        to.append(1,c-64);
    }
    return to;
}

std::string encrypt_simple_string(const std::string& msg, const std::string& key)
{
    std::vector<char> msg2(msg.begin(), msg.end());
    std::string b64_str = Base64::encode(msg2);
    std::string vigenere_msg = cryptoAL_vigenere::encrypt_vigenere(b64_str, key);

    return vigenere_msg;
}

std::string decrypt_simple_string(const std::string& encrypted_msg, const std::string& key)
{
    std::string s;

    std::string newKey = cryptoAL_vigenere::extend_key(encrypted_msg, key);
    std::string b64_encoded_str = cryptoAL_vigenere::decrypt_vigenere(encrypted_msg, newKey);
    std::vector<char> b64_decode_vec = Base64::decode(b64_encoded_str);
    std::string b64_decode_str(b64_decode_vec.begin(), b64_decode_vec.end());
    //s = sanitize_utf8(b64_decode_str);
    s = b64_decode_str;

    return s;
}

#endif // _INCLUDES_encrypt_H
