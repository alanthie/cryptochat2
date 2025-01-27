#ifndef __PROTO_SERVER_H
#define __PROTO_SERVER_H

extern "C"
{
    #include <event2/event.h>
    #include <event2/buffer.h>
    #include <event2/bufferevent.h>
}

#include <string>
#include <map>
#include <queue>
#include <functional>
#include <mutex>

#include "proto_utils.h"
#include "../data.hpp" // cryptoAL::cryptodata has Buffer

namespace msgio
{
    class msgio_server;
    class crypto_server1;

    const uint32_t SIZE_PACKET = 1024*4;
    const uint32_t MAX_OUTPUT  = 1024*512;

    struct msg_packet
    {
        uint32_t len = 0;
        uint8_t buffer[SIZE_PACKET];

        msg_packet() {}
        msg_packet(uint8_t* data, uint32_t l)
        {
            len = l;
            memcpy(buffer, data, len);
        }
    };

    [[maybe_unused]] static std::string getDEFAULT_KEY()
	{
		return std::string("ertyewrtyewrt654tg45y66u57u68itik96807iedhywt21t521t2134t3tvgtt3"); // 64x
	}

    class connection
    {
    public:
        connection();
        virtual ~connection();

        void send(const void* data, size_t numBytes);
        void setup(evutil_socket_t fd, struct bufferevent* bev, msgio_server* srv);
        void on_read_handler(const void* buffer, size_t numBytes);

        struct bufferevent* mBufferEvent;
        evutil_socket_t     mFd;
        msgio_server*       mServer;
        msgio::crypto_server1* cryptoserver = nullptr;

        evutil_socket_t getSocketFd() {return mFd;}

    public:
        // client_node
        int  count_initial_key_validation = 0;
		bool initial_key_validation_done = false;
		bool initial_key_validation_waiting_answer = false;
		bool random_key_validation_done = false;

		bool requ_username_waiting_resp = false;
		bool requ_hostname_waiting_resp = false;
		bool requ_machineid_waiting_resp = false;
		bool requ_accept_rnd_waiting_resp = false;
		bool new_pending_random_key_waiting = false;

		std::string initial_key_hint;
		std::string initial_key;
		std::string initial_key64;

		std::string previous_random_key;
		std::string random_key;
		std::string pending_random_key;
		bool new_pending_random_key = false;

		std::string username;
		std::string hostname;
		std::string machine_id;
		uint32_t user_index = 0; // invalid, unique user number like an ip 1 to ffffffff

		size_t msg_counter = 0;
        size_t MSG_VALIDATIONcounter = 0;

        cryptoAL::cryptodata recv_buffer;
        cryptoAL::cryptodata previous_recv_buffer;

        std::queue<msg_packet> q_msgOUT;
    };


    class msgio_server
    {
    friend class connection;

    public:
        void* cryptoserver = nullptr;

        // Callbacks
        typedef std::function<void(msgio_server*, connection*)>   on_connected;
        typedef std::function<void(msgio_server*, connection*)>   on_disconnected;
        typedef std::function<connection*(msgio_server*)>         on_accepted;
        typedef std::function<void(msgio_server*, connection*, const void* buffer, size_t num)> on_received;

        msgio_server();
        virtual ~msgio_server();

        void set_callbacks(on_connected client_conn, on_disconnected client_disconn,
                           on_accepted client_accept, on_received client_recv);
        void setup(const unsigned short& port) ;

        void update();
        void sendToAllClients(const char* data, size_t len);
        void addConnection(evutil_socket_t fd, connection* connection);
        void removeConnection(evutil_socket_t fd);

    protected:
        static void listenerCallback(
             struct evconnlistener* listener
            ,evutil_socket_t socket
            ,struct sockaddr* saddr
            ,int socklen
            ,void* msgio_server
        );

        static void signalCallback(evutil_socket_t sig, short events, void* msgio_server);

        static void writeCallback(struct bufferevent*,  void* connection);
        static void readCallback( struct bufferevent*,  void* connection);
        static void eventCallback(struct bufferevent*,  short, void* connection);

        struct sockaddr_in sin;
        struct event_base* base;
        struct event* signal_event;
        struct evconnlistener* listener;

        std::map<evutil_socket_t, connection*> connections;

        on_connected    client_conn;
        on_disconnected client_disconn;
        on_accepted     client_accept;
        on_received     client_recv;
        std::recursive_mutex mConnectionsMutex;

        virtual connection* on_create_conn();
    };

} // end of namespace

#endif
