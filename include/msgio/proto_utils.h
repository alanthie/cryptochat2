#ifndef __PROTO_UTILS_H
#define __PROTO_UTILS_H

#include <exception>
#include <functional>
#include <cstdint>
#include <string>

namespace msgio 
{

class error: public std::exception
{
public:
    error(int code);
    ~error();

    int code() const;
protected:
    int mCode;
};

enum
{
    error_listener_failed  = 1000,
    error_base_failed      = 1001
};

typedef std::function<void(const void* buffer, size_t len)> msg_arrived;

class msgparser
{
public:
    static const uint32_t MAGIC = 0x372947;
    struct header
    {
        uint32_t mMagic = 0;
        uint32_t mLength = 0xFFFFFFFF;
    };

    msgparser();
    ~msgparser();

    void set_callback(msg_arrived cb);
    void parse(const void* buffer, size_t num);

protected:
    msg_arrived mCallback;
    header mHeader;
    std::string mBuffer;
};

}
#endif
