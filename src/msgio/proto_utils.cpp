#include "../../include/msgio/proto_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <event2/thread.h>
#include <cstdint>
#include <string>

using namespace msgio;

error::error(int code)
    :mCode(code)
{
}

error::~error()
{

}

int error::code() const
{
    return mCode;
}

msgparser::msgparser()
{}

msgparser::~msgparser()
{}

void msgparser::set_callback(msg_arrived cb)
{
    mCallback = cb;
}

void msgparser::parse(const void* buffer, size_t num)
{
    // Add to buffer
    mBuffer.append(reinterpret_cast<const char*>(buffer), num);

    while (mBuffer.size() > mHeader.mLength || (mHeader.mLength == 0xFFFFFFFF && mBuffer.size() >= sizeof(mHeader)))
    {
        if (mHeader.mLength == 0xFFFFFFFF)
        {
            // Length header is not fetched yet
            assert(sizeof(mHeader) == 8);

            if (mBuffer.size() >= sizeof(mHeader))
            {
                mHeader.mMagic = *reinterpret_cast<const uint32_t*>(mBuffer.c_str());
                mHeader.mMagic = ntohl(mHeader.mMagic);

                mHeader.mLength = *reinterpret_cast<const uint32_t*>(mBuffer.c_str() + sizeof(uint32_t));
                mHeader.mLength = ntohl(mHeader.mLength);

                mBuffer.erase(0, sizeof(mHeader));

                // Check magic
                if (mHeader.mMagic != msgparser::MAGIC)
                {
                    // Send zero buffer to signal about error
                    if (mCallback)
                        mCallback(nullptr, 0xFFFFFFFF);
                }
            }
        }
        else
        if (mBuffer.size() >= mHeader.mLength)
        {
            if (mCallback)
                mCallback(mBuffer.c_str(), mHeader.mLength);
            mBuffer.erase(0, mHeader.mLength);
            mHeader.mLength = 0xFFFFFFFF;
            mHeader.mMagic = 0;
        }
    }
}

// --------------- initializer --------------------
class initializer
{
public:
    initializer()
    {
        evthread_use_pthreads();
    }
    ~initializer()
    {}
};

static initializer thread_initializer;
