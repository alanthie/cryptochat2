extern "C" {
    #include <sys/socket.h>
    #include <event2/bufferevent.h>
    #include <event2/buffer.h>
    #include <event2/listener.h>
    #include <event2/util.h>
    #include <event2/event.h>
}

#include "../../include/msgio/proto_server.h"
#include "../../include/msgio/proto_utils.h"
#include "../../include/netw_msg.hpp"

#include "../../include/crypto_server1.hpp"

#include <memory.h>
#include <signal.h>
#include <assert.h>

using namespace msgio;

connection::connection()
{}

connection::~connection()
{}

void connection::setup(int fd, struct bufferevent *bev, msgio_server *srv)
{
    if (DEBUG_INFO) std::cout  << "onnection::setup\n";

    mBufferEvent = bev;
    mFd = fd;
    mServer = srv;
    cryptoserver = dynamic_cast<crypto_server1*>(srv);
}

void connection::send(const void* data, size_t numBytes)
{
    if(bufferevent_write(mBufferEvent, data, numBytes) == -1)
        throw error(errno);
}

void connection::on_read_handler(const void *bufferin, size_t numBytes)
{
    cryptoserver->connection_on_read_handler(this, bufferin, numBytes);

    //typedef std::function<void(msgio_server*, connection*, const void* buffer, size_t num)> on_received;
    //if (mServer->client_recv)
    //    mServer->client_recv(mServer, this, buffer, numBytes);
}

msgio_server::msgio_server()
    :base(nullptr)
    ,signal_event(nullptr)
    ,listener(nullptr)
{
}

msgio_server::~msgio_server()
{
    if(signal_event != nullptr)
    {
        event_free(signal_event);
        signal_event = nullptr;
    }

    if(listener != nullptr)
    {
        evconnlistener_free(listener);
        listener = nullptr;
    }

    if(base != nullptr)
    {
        event_base_free(base);
        base = nullptr;
    }
}

void msgio_server::set_callbacks(
                        on_connected    client_conn,
                        on_disconnected client_disconn,
                        on_accepted     client_accept,
                        on_received     client_recv)
{
    this->client_conn       = client_conn;
    this->client_disconn    = client_disconn;
    this->client_accept     = client_accept;
    this->client_recv       = client_recv;
}

void msgio_server::setup(const unsigned short& port)
{
    base = event_base_new();
    if(!base)
        throw error(error_base_failed);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    if (DEBUG_INFO) std::cout  << "evconnlistener_new_bind\n";
    listener = evconnlistener_new_bind(
         base
        ,msgio_server::listenerCallback
        ,reinterpret_cast<void*>(this)
        ,LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE
        ,-1
        ,reinterpret_cast<struct sockaddr*>(&sin)
        ,sizeof(sin)
    );

    if(!listener)
    {
        if (DEBUG_INFO) std::cout  << "if(!listener)\n";
        throw error(errno);
    }

    /*signal_event = evsignal_new(base, SIGINT, signalCallback, reinterpret_cast<void*>(this));
    if(!signal_event || event_add(signal_event, nullptr) < 0) {

        printf("Cannog create signal event.\n");
        return false;
    }*/
}

//-----------------------------------
 // base loop iteration
//-----------------------------------
void msgio_server::update()
{
    if (DEBUG_INFO) std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
    if(base != nullptr)
    {
        event_base_loop(base, EVLOOP_NONBLOCK);
    }
}

void msgio_server::addConnection(evutil_socket_t fd, connection* connection)
{
    if (DEBUG_INFO) std::cout  << "addConnection\n";
    std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
    connections.insert(std::pair<evutil_socket_t, class connection*>(fd, connection));
}

void msgio_server::removeConnection(evutil_socket_t fd)
{
    if (DEBUG_INFO) std::cout << "msgio_server::removeConnection\n";
    std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
    connections.erase(fd);
}

void msgio_server::sendToAllClients(const char* data, size_t len)
{
    std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);

    typename std::map<evutil_socket_t, connection*>::iterator it = connections.begin();
    while(it != connections.end())
    {
        it->second->send(data, len);
        ++it;
    }
}


void msgio_server::listenerCallback(
     struct evconnlistener* listener
    ,evutil_socket_t fd
    ,struct sockaddr* saddr
    ,int socklen
    ,void* data
)
{
    if (DEBUG_INFO) std::cout  << "listenerCallback\n";

    msgio_server* msgio_server = reinterpret_cast<class msgio_server*>(data);
    struct event_base* base = reinterpret_cast<struct event_base*>(msgio_server->base);
    struct bufferevent* bev;

    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if(!bev)
    {
        event_base_loopbreak(base);
        printf("Error constructing bufferevent!\n");
        return;
    }

    connection* conn = msgio_server->on_create_conn();
    if (!conn)
    {
        printf("Error creation of connection object.");
        return;
    }

    conn->setup(fd, bev, msgio_server);

    msgio_server->addConnection(fd, conn);

    bufferevent_setcb(  bev,
                        msgio_server::readCallback,
                        msgio_server::writeCallback,
                        msgio_server::eventCallback,
                        reinterpret_cast<void*>(conn));

    bufferevent_enable(bev, EV_WRITE | EV_READ);
}

connection* msgio_server::on_create_conn()
{
    if (DEBUG_INFO) std::cout  << "msgio_server::on_create_conn()\n";
    connection* conn = nullptr;
    if (client_accept)
        conn = client_accept(this);
    else
    {
        if (DEBUG_INFO) std::cout  << "conn = new connection()\n";
        conn = new connection();
    }

    return conn;
}

void msgio_server::signalCallback(evutil_socket_t sig, short events, void* data)
{
    msgio_server* msgio_server = reinterpret_cast<class msgio_server*>(data);
    struct event_base* base = msgio_server->base;
    struct timeval delay = {0,0};
    // Caught an interrupt signal; exiting cleanly
    event_base_loopexit(base, &delay);
    // Exited
}

void msgio_server::writeCallback(struct bufferevent* bev, void* data)
{
    // TODO is the callback repetitive???
    // By default, this watermark is set to 0, meaning the write callback
    //    is invoked whenever the output buffer is empty.

    class connection* conn = static_cast<class connection*>(data);
    if (conn->q_msgOUT.size() == 0) return;

    int r = 0;
    struct evbuffer* output = bufferevent_get_output(bev);
    while( r==0 && conn->q_msgOUT.size() > 0)
    {
        auto& packet = conn->q_msgOUT.front();
        r = bufferevent_write(bev, packet.buffer, packet.len);
        if (r == 0)
            conn->q_msgOUT.pop();
        else
        {
            break;
        }

        if (evbuffer_get_length(output) > MAX_OUTPUT)
        {
            if (DEBUG_INFO) std::cout << "writeCallback evbuffer_get_length(output) > MAX_OUTPUT " << evbuffer_get_length(output) << "\n";
            break;
        }
    }

    if (conn->q_msgOUT.size() > 0)
    {
        if (DEBUG_INFO) std::cout << "writeCallback conn->q_msgOUT.size() > 0 " << conn->q_msgOUT.size() << "\n";
    }

    /*
    There is no inherent maximum size limit for bufferevent_write,
    */
}

void msgio_server::readCallback(struct bufferevent* bev, void* connection)
{
    class connection* conn = static_cast<class connection*>(connection);
    struct evbuffer* buf = bufferevent_get_input(bev);
    char readbuf[SIZE_PACKET];
    int read = 0;

    while( (read = evbuffer_remove(buf, &readbuf, sizeof(readbuf))) > 0)
    {
        conn->on_read_handler(readbuf, static_cast<size_t>(read));
    }
}

void msgio_server::eventCallback(struct bufferevent* bev, short events, void* data)
{
    connection* conn = reinterpret_cast<connection*>(data);
    msgio_server* srv = conn->mServer;

    if(events & BEV_EVENT_EOF)
    {
        if (DEBUG_INFO) std::cout << "disconnected\n";

        // Notify about disconnection
        if (srv->client_disconn)
            srv->client_disconn(conn->mServer, conn);

        // Free connection structures
        conn->mServer->removeConnection(conn->mFd);
        bufferevent_free(bev);
    }
    else if(events & BEV_EVENT_ERROR)
    {
        if (DEBUG_INFO) std::cout << "BEV_EVENT_ERROR disconnected\n";

        // Free connection structures
        conn->mServer->removeConnection(conn->mFd);
        bufferevent_free(bev);

        // Notify about disconnection
        if (srv->client_disconn)
            srv->client_disconn(conn->mServer, conn);
    }
    else
    {
        printf("unhandled.\n");
    }
}

