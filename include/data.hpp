#ifndef _INCLUDES_cryptodata
#define _INCLUDES_cryptodata

#include "crypto_const.hpp"
#include "Buffer.hpp"
#include <filesystem>
#include <fstream>
#include <stdio.h>
#include <iostream>
//#include <stacktrace> // c++ 23

namespace cryptoAL
{

class cryptodata
{
public:
    cryptodata(bool verb = false) {verbose = verb;}
    virtual ~cryptodata() {}

    virtual bool read_from_file(const std::string& filename, bool allow_realloc = true, std::stringstream* serr = nullptr )
    {
        std::ifstream ifd(filename.data(), std::ios::binary | std::ios::ate);
        if (ifd)
        {
            int32_t sz = (int32_t)ifd.tellg();
            if(sz<=-1)
            {
                if (serr != nullptr)
                    (*serr) << "ERROR read_from_file can not read size" << filename << std::endl;
                ifd.close();
                return false;
            }

            if(sz==0)
            {
                //  empty file
                if (serr != nullptr)
                    (*serr)  << "WARNING read_from_file empty file" << filename << std::endl;
                ifd.close();
                return true;
            }

            uint32_t usz = (uint32_t) sz;

            if (this->allocsize() < usz)
            {
                if (allow_realloc)
                {
                    if (usz < FILE_SIZE_LIM)
                    {
                        realloc(usz);
                    }
                    else
                    {
                        if (serr != nullptr)
                            (*serr) << "ERROR read_from_file FILE_SIZE_LIM " << filename << " " << usz << std::endl;
                        ifd.close();
                        return false;
                    }
                }
                else
                {
                    if (serr != nullptr)
                        (*serr)  << "ERROR read_from_file allow_realloc = false " << filename << " " << usz << std::endl;
                    ifd.close();
                    return false;
                }
            }

            ifd.seekg(0, std::ios::beg);
            int32_t r = buffer.read(ifd, usz, 0);
            if (r <= -1)
            {
                if (serr != nullptr)
                    (*serr) << "ERROR read_from_file buffer.read(ifd, sz, 0);" << filename << " " << usz << std::endl;
                ifd.close();
                return false;
            }

            uint32_t ur = (uint32_t) r;
            if (ur != usz)
            {
                if (serr != nullptr)
                    (*serr)  << "ERROR read_from_file r!=usz" << filename << " " << usz << std::endl;
                ifd.close();
                return false;
            }
            ifd.close();
            return true;
        }
        else
        {
            if (serr != nullptr)
                (*serr)  << "ERROR read_from_file OPENING FAILED " << filename << std::endl;
            //std::stacktrace st = std::stacktrace::current();
            //std::cerr << st << std::endl;
        }
        return false;
    }

    virtual bool save_to_file(const std::string& filename, std::stringstream* serr = nullptr  )
    {
        std::ofstream ofd(filename.data(), std::ios::out | std::ios::binary);
        if (ofd.bad() == false)
        {
            if (buffer.size() > 0) // make empty file
            {
                int32_t r = buffer.write(ofd, buffer.size());
                if (r==-1)
                {
                    if (serr != nullptr)
                        (*serr)  << "ERROR save file " << "Failed for buffer.write(ofd, buffer.size()" << buffer.size() <<  std::endl;
                    ofd.close();
                    return false;
                }
                if (r!=(int32_t)buffer.size())
                {
                    if (serr != nullptr)
                        (*serr)  << "ERROR save file " << "Failed for buffer.write(ofd, buffer.size() " << r << std::endl;
                    ofd.close();
                    return false;
                }
            }
            ofd.close();
            return true;
        }
        else
        {
            if (serr != nullptr)
                (*serr)   << "ERROR save file " << "Failed to open file " << filename << std::endl;
        }
        return false;
    }

    void append(char* p, uint32_t n)        {buffer.write(p, n, -1);}
    void append(const char* p, uint32_t n)  {buffer.write(p, n, -1);}

	int32_t get_first(size_t n, Buffer& rout, std::stringstream* serr = nullptr )
	{
        if (buffer.size() < n)
        {
            if (serr != nullptr)
                (*serr) << "WARNING get_first" << "Failed for (buffer.size() < n) " << n << std::endl;
            return -1;
        }
        rout.erase();
        rout.write(buffer.getdata(), (int32_t)n, 0);
        return (int32_t)n;
	}

	int32_t get_last(size_t n, Buffer& rout, std::stringstream* serr = nullptr )
	{
        if (buffer.size() < n)
        {
            if (serr != nullptr)
                (*serr) << "WARNING get_last" << "Failed for (buffer.size() < n) " << n << std::endl;
            return -1;
        }
        rout.erase();
        rout.write(buffer.getdata() + buffer.size() - n, (uint32_t)n, 0);
        return (int32_t) n;
	}

    bool copy_buffer_to(cryptodata& dst)
    {
        dst.realloc(buffer.size() + 1);
        dst.buffer.write(buffer.getdata(), buffer.size(), 0);
        return true;
    }

    void clear_data()           {buffer.clear();}
    void erase()                {buffer.erase();}
    void realloc(uint32_t sz)   {buffer.realloc(sz);}
    uint32_t allocsize()        {return buffer.allocsize();}

    Buffer buffer;
    bool verbose;
};


}
#endif
