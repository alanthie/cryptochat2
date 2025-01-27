#include <iostream>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../include/msgio/proto_client.h"
#include "../../include/msgio/proto_utils.h"

namespace msgio
{

msgio_client::msgio_client()
    : base_(nullptr),
      timeout_event(nullptr),
      buffer_event(nullptr)
{
}

msgio_client::~msgio_client()
{
    stop();
}

void msgio_client::set_target(const std::string& atarget)
{
    target = atarget;
}

std::string msgio_client::get_target() const
{
    return target;
}

void msgio_client::set_callbacks(
      on_connected      conn,
      on_disconnected   disconn,
      on_read           aread,
      on_timeout        atimeout)
{
    connected_cb =      conn;
    disconnected_cb =   disconn;
    read_cb =           aread;
    timeout_cb =        atimeout;
}


void msgio_client::start()
{
    if (buffer_event)
        return;

    int retcode = 0;

    base_ = event_base_new();

    // Find IP address
    uint16_t port = static_cast<uint16_t>(DEFAULT_PORT);
    std::string::size_type p = target.find(':');
    if (p != std::string::npos)
        port = static_cast<uint16_t>(std::atoi(target.c_str() + p + 1));

    sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    if (evutil_inet_pton(AF_INET, target.c_str(), &sin.sin_addr.s_addr) != 0)
        throw error(errno);
    sin.sin_port = htons(port);

    // Prepare bufferevent
    buffer_event = bufferevent_socket_new(base_, -1, BEV_OPT_CLOSE_ON_FREE);

    // No write callback for now
    bufferevent_setcb(buffer_event, readcb, nullptr, eventcb, this);
    bufferevent_enable(buffer_event, EV_READ | EV_WRITE);

    // evbuffer_add(bufferevent_get_output(bev), message, block_size);

    retcode = bufferevent_socket_connect(buffer_event, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin));
    if (retcode < 0)
        throw error(retcode);
}

void msgio_client::start_with_delay(int seconds)
{
    if (buffer_event)
        return;

    base_ = event_base_new();

    timeval timeout_value;
    timeout_value.tv_sec = seconds;
    timeout_value.tv_usec = 0;

    timeout_event = evtimer_new(base_, timeoutcb, this);
    evtimer_add(timeout_event, &timeout_value);
}

void msgio_client::stop()
{
    if (!base_)
        return;

    if (buffer_event)
    {
        bufferevent_free(buffer_event);
        buffer_event = nullptr;
    }

    if (timeout_event)
    {
        event_free(timeout_event);
        timeout_event = nullptr;
    }

    if (base_)
    {
        event_base_free(base_);
        base_ = nullptr;
    }
}

void msgio_client::write(const void* buffer, size_t num)
{
    if (buffer_event)
    {
        evbuffer_add(bufferevent_get_output(buffer_event), buffer, num);
    }
}

/*
static void set_tcp_no_delay(evutil_socket_t fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,   &one, sizeof one);
}
*/


void msgio_client::timeoutcb(evutil_socket_t fd, short what, void *arg)
{
    // Time to start connecting
    msgio_client* c = reinterpret_cast<msgio_client*>(arg);
    try
    {
        c->start();
    }
    catch (const error& e)
    {
    }
}

void msgio_client::readcb(struct bufferevent *bev, void *ctx)
{
    msgio_client* c = reinterpret_cast<msgio_client*>(ctx);

    /* This callback is invoked when there is data to read on bev. */
    struct evbuffer *input = bufferevent_get_input(bev);
    // struct evbuffer *output = bufferevent_get_output(bev);

    char readbuf[1024];
    size_t read = 0;

    while( (read = static_cast<size_t>(evbuffer_remove(input, &readbuf, sizeof(readbuf)))) > 0)
    {
        c->on_read_handler(readbuf, read);
    }
}

void msgio_client::on_read_handler(const void *buf, size_t num)
{
    if (read_cb)
        read_cb(*this, buf, num);
}

void msgio_client::eventcb(struct bufferevent *bev, short events, void *ptr)
{
    msgio_client* c = reinterpret_cast<msgio_client*>(ptr);
    if (events & BEV_EVENT_CONNECTED)
    {
        // Connected
        if (c->connected_cb)
            c->connected_cb(*c);
        //evutil_socket_t fd = bufferevent_getfd(bev);
        //set_tcp_no_delay(fd);
    } else if (events & BEV_EVENT_ERROR)
    {
        //printf("NOT Connected\n");
        if (c->disconnected_cb)
            c->disconnected_cb(*c, errno);
    } else if (events & BEV_EVENT_EOF)
    {
        if (c->disconnected_cb)
            c->disconnected_cb(*c, 0);
    }
}

void msgio_client::update()
{
    if (base_)
        event_base_loop(base_, EVLOOP_NONBLOCK);
}

// ------------ msgclient --------------
msgclient::msgclient()
{
    parser.set_callback([this](const void* buf, size_t num)
    {
       if (buf == nullptr && num == 0xFFFFFFFF)
       {
           // Format error, disconnect
           if (disconnected_cb)
               disconnected_cb(*this, 200);
           stop();
       }
       if (message_cb)
           message_cb(*this, buf, num);
    });
}

msgclient::~msgclient()
{}

void msgclient::set_message_callback(on_message cb)
{
    message_cb = cb;
}

void msgclient::on_read_handler(const void *buf, size_t num)
{
    parser.parse(buf, num);
}

void msgclient::send_msg(const void* buf, size_t num)
{
    msgparser::header hdr;
    hdr.mMagic = htonl(msgparser::MAGIC);
    hdr.mLength = htonl(static_cast<uint32_t>(num));

    write(&hdr, sizeof(hdr));
    write(buf, num);
}

} // end of namespace
