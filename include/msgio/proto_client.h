#include <event2/event.h>
#include <functional>
#include "proto_utils.h"

namespace msgio
{

class msgio_client
{
public:
    const int IO_TIMEOUT    = 5;         // Seconds
    const int DEFAULT_PORT  = 9000;      // Default port number for target

    typedef std::function<void(msgio_client&)>                    on_connected;
    typedef std::function<void(msgio_client&,int)>                on_disconnected;
    typedef std::function<void(msgio_client&,const void*,size_t)> on_read;
    typedef std::function<void(msgio_client&)>                    on_timeout;

    msgio_client();
    virtual ~msgio_client();

    void set_target(const std::string& target);
    std::string get_target() const;

    void set_callbacks(on_connected conn,
                       on_disconnected disconn,
                       on_read read,
                       on_timeout timeout);
    void start();
    void start_with_delay(int seconds);

    void stop();
    void write(const void* buffer, size_t num);

    void update();

protected:
    static void timeoutcb(evutil_socket_t fd, short what, void *arg);
    static void readcb(struct bufferevent *bev, void *ctx);
    static void eventcb(struct bufferevent *bev, short events, void *ptr);

    on_connected    connected_cb;
    on_disconnected disconnected_cb;
    on_read         read_cb;
    on_timeout      timeout_cb;

    event_base*   base_;
    event*        timeout_event;
    bufferevent*  buffer_event;

    std::string target;

    virtual void on_read_handler(const void* buf, size_t num);
};


class msgclient: public msgio_client
{
public:
    typedef std::function<void(msgclient&, const void* , size_t )> on_message;

    msgclient();
    ~msgclient();

    void set_message_callback(on_message cb);
    void send_msg(const void* buf, size_t num);

protected:
    msgparser parser;
    on_message message_cb;

    void on_read_handler(const void* buf, size_t num) override;
};

}
