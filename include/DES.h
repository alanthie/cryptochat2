/*
DES.h

Copyright (c) 2013 - 2017 Jason Lee @ calccrypto at gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef __DES__
#define __DES__

#include <algorithm>

#include "includes.h"
#include "SymAlg.h"
#include "DES_Const.h"

class DES : public SymAlg{
    private:
        uint64_t keys[16];
        std::string run(const std::string & data);

    public:
        DES();
        DES(const std::string & KEY);
        void setkey(const std::string & KEY);
        std::string encrypt(const std::string & DATA);
        std::string decrypt(const std::string & DATA);
        unsigned int blocksize() const;

        // BINARY DES
        DES(const char KEY[4]);
        std::string encrypt_bin(const char* data, int data_size=4);
        void decrypt_bin(const std::string& DATA, char* out, int out_size=4);
};

#endif
