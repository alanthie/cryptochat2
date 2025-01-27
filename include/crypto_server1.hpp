/*
 * Author: Alain Lanthier
 **
 */
#ifndef crypto_server1_H
#define crypto_server1_H

#include "netw_msg.hpp"
#include "cfg_srv.hpp"
#include "msgio/proto_server.h"
#include "msgio/proto_utils.h"

#include <vector>
#include <functional>
#include <algorithm>
#include <thread>
#include <mutex>

namespace msgio
{
	const bool USE_BASE64_RND_KEY_GENERATOR = true;
	//AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "; // vigenere

	class crypto_server1 : public msgio::msgio_server
	{
	public:
        crypto_server1(cryptochat::cfg::cfg_srv cfg) :
            msgio::msgio_server(), _cfg(cfg)
        {
            msgio::msgio_server::cryptoserver = this;
        }

    private:
        void setup(const unsigned short& port)
        {
            read_map_machineid_to_user_index();

            //server_test();

            if (USE_BASE64_RND_KEY_GENERATOR == false)
                first_pending_random_key = cryptoAL::random::generate_base10_random_string(NETW_MSG::KEY_SIZE);
            else
                first_pending_random_key = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);

            set_key_hint();

			//set_callbacks(...)

			std::cout  << "port " << port << "\n";
            msgio_server::setup(port);
        }

    public:
        void setup_and_run(const unsigned short& port)
        {
              setup(port);
              while (true)
              {
                  update();
                  std::this_thread::sleep_for(std::chrono::milliseconds(1));
              }
        }

        static void drained_writecb(struct bufferevent *bev, void *ctx)
        {
            class connection* conn = static_cast<class connection*>(ctx);

            /* We were choking the other side until we drained our outbuf a bit.
             * Now it seems drained. */
            bufferevent_setcb(  bev,
                                msgio_server::readCallback,
                                msgio_server::writeCallback,
                                msgio_server::eventCallback,
                                reinterpret_cast<void*>(conn));

            bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
            bufferevent_enable(bev, EV_READ);
        }

        void queue_packet(connection* conn, uint8_t* data, uint32_t len)
        {
            conn->q_msgOUT.push( msg_packet{data, len} );

            // try sending the accumulated packets
            int r = 0;
            struct evbuffer* output = bufferevent_get_output(conn->mBufferEvent);
            while( r==0 && conn->q_msgOUT.size() > 0)
            {
                auto& packet = conn->q_msgOUT.front();
                r = bufferevent_write(conn->mBufferEvent, packet.buffer, packet.len);
                if (r == 0)
                {
                    conn->q_msgOUT.pop();
                }
                else
                {
                    std::cout << "bufferevent_write failed, out size:" << evbuffer_get_length(output) << "\n";
                    break;
                }

                if (evbuffer_get_length(output) > MAX_OUTPUT)
                {
                    std::cout << "evbuffer_get_length(output) > MAX_OUTPUT" << evbuffer_get_length(output) << "\n";
                    // ...change mode ...
                    /* We're giving the other side data faster than it can
                     * pass it on.  Stop reading here until we have drained the
                     * other side to MAX_OUTPUT/2 bytes. */
                    bufferevent_setcb(  conn->mBufferEvent,
                                        msgio_server::readCallback,
                                        drained_writecb,
                                        msgio_server::eventCallback,
                                        reinterpret_cast<void*>(conn));

                    bufferevent_setwatermark(conn->mBufferEvent, EV_WRITE, MAX_OUTPUT/2, MAX_OUTPUT);
                    bufferevent_disable(conn->mBufferEvent, EV_READ); // ??? are we losing data ???

                    break;
                }
            }

            if (conn->q_msgOUT.size() > 0)
            {

                std::cout << "queue_packet conn->q_msgOUT.size() > 0 " << conn->q_msgOUT.size() << "\n";
            }
        }

	public:

        void connection_on_read_handler(connection* conn, const void *bufferin, size_t numBytes);

        void kill_client(connection* conn)
        {
            std::cout << "kill_client\n";
            conn->mServer->removeConnection(conn->mFd);
            bufferevent_free(conn->mBufferEvent); // TODO
        }
        void kill_all_clients();

		void set_key_hint();

		void handle_remove_client();
		void handle_new_client(msgio::connection* new_client);
		void handle_info_client(const evutil_socket_t& t_socket, bool send_to_current_user_only = false);

/*
		// startup tests
		void server_test();
		bool check_default_encrypt(std::string& key);
		bool check_idea_encrypt(std::string& key);
		bool check_salsa_encrypt(std::string& key);
*/

		void sendMessageClients(const std::string& t_message, uint8_t crypto_flag, uint32_t from_user, uint32_t to_user);
		void sendMessageClients(const std::string& t_message, uint8_t msg_type,uint8_t crypto_flag, uint32_t from_user, uint32_t to_user);

		void sendMessageAll(const std::string& t_message, const evutil_socket_t& t_socket, uint8_t crypto_flag, uint32_t from_user, uint32_t to_user);
		void sendMessageAll(const std::string& t_message, const evutil_socket_t& t_socket, uint8_t msg_type, uint8_t crypto_flag, uint32_t from_user, uint32_t to_user);
		void sendMessageAll(NETW_MSG::MSG& msg, const evutil_socket_t& t_socket,uint8_t crypto_flag, uint32_t from_user, uint32_t to_user);

        bool sendMessageOne(NETW_MSG::MSG& msg, uint8_t msg_type, uint8_t crypto_flag, uint32_t from_user, uint32_t to_user);

        bool sendMessageOneBySocket(const std::string& t_message, const evutil_socket_t& t_socket,
                                    uint8_t msg_type, uint8_t crypto_flag, uint32_t from_user, uint32_t to_user);

        int send_packet(const evutil_socket_t& t_socketFd, uint8_t* buffer, uint32_t buffer_len, std::stringstream& serr);

        int send_composite( const evutil_socket_t& t_socketFd, NETW_MSG::MSG& m, std::string key, std::stringstream& serr,
                            uint8_t crypto_flag = 0, uint32_t from_user = 0, uint32_t to_user = 0);

	public:
		void request_all_client_shutdown();
		void request_client_initial_key(msgio::connection* client);
		void request_accept_firstrnd_key(msgio::connection* client);

		cryptochat::cfg::cfg_srv _cfg;

		virtual ~crypto_server1();
		void close_server();

		std::string initial_key_hint;
		std::string initial_key;
		std::string initial_key64;
		std::string first_pending_random_key;

		// to persist
		uint32_t next_user_index = 1;
		struct user_index_status
		{
            uint32_t index;
            int status; // 0 = offline

            friend std::ostream& operator<<(std::ostream& out, Bits<user_index_status&>  my)
            {
                out << bits(my.t.index)
                    << bits(my.t.status);
                return (out);
            }

            friend std::istream& operator>>(std::istream& in, Bits<user_index_status&> my)
            {
                in  >> bits(my.t.index)
                    >> bits(my.t.status);
                return (in);
            }
		};
		std::map<std::string, std::vector<user_index_status> > map_machineid_to_user_index;

		bool read_map_machineid_to_user_index();
		bool save_map_machineid_to_user_index();

		void handle_msg_MSG_CMD_RESP_KEY_HINT(NETW_MSG::MSG& m, msgio::connection* new_client);
		void handle_msg_MSG_CMD_RESP_ACCEPT_RND_KEY(NETW_MSG::MSG& m, msgio::connection* new_client);
		void handle_msg_MSG_CMD_RESP_USERNAME(NETW_MSG::MSG& m, msgio::connection* new_client);
		void handle_msg_MSG_CMD_RESP_MACHINEID(NETW_MSG::MSG& m, msgio::connection* new_client);
		void handle_new_pending_random_key(msgio::connection* new_client);
	};
}

#endif
