/*
 * Author: Alain Lanthier
 **
 */

#ifndef crypto_server_H
#define crypto_server_H

#include "socket_node.hpp"
#include <vector>
#include <functional>
#include <algorithm>
#include <thread>
#include <mutex>

namespace crypto_socket
{
	const bool USE_BASE64_RND_KEY_GENERATOR = true;
	//AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "; // vigenere

	class crypto_server : protected socket_node
	{
	protected:
		void setDefault();

		// message event function
		std::function<void(const std::string& t_message) > m_onMessage = nullptr;
		void showMessage(const std::string& t_message);
		std::mutex m_mu; // showMessage lock

		//--------------------------------------------
		// N recv() threads vector
		// One RECV thread per client
		//--------------------------------------------
		std::vector<std::thread> v_thread;
		void join_all_recv_threads();

		//--------------------------------------------
		// N clients node vector
		//--------------------------------------------
		int m_nodeSize = 0;
		std::mutex vclient_mutex;
		std::vector<client_node*> v_client; // std::map<evutil_socket_t, connection*> connections;

		void close_all_clients();

		void handle_new_client(socket_node* new_client);
		void handle_remove_client();
		void handle_info_client(const int& t_socket, bool send_to_current_user_only = false);

		// server creation sequence
		void createServer();
		void bindServer();
		void listenServer();
		void set_key_hint();
		void handle_accept();

		// stratup tests
		void server_test();
		bool check_default_encrypt(std::string& key);
		bool check_idea_encrypt(std::string& key);
		bool check_salsa_encrypt(std::string& key);

		// message sending
		void sendMessageClients(const std::string& t_message, uint8_t crypto_flag, uint8_t from_user, uint8_t to_user);
		void sendMessageClients(const std::string& t_message, uint8_t msg_type,uint8_t crypto_flag, uint8_t from_user, uint8_t to_user);

		void sendMessageAll(const std::string& t_message, const int& t_socket, uint8_t crypto_flag, uint8_t from_user, uint8_t to_user);
		void sendMessageAll(const std::string& t_message, const int& t_socket, uint8_t msg_type,uint8_t crypto_flag, uint8_t from_user, uint8_t to_user);
		void sendMessageAll(NETW_MSG::MSG& msg, const int& t_socket,uint8_t crypto_flag, uint8_t from_user, uint8_t to_user);

		bool sendMessageOneBySocket(const std::string& t_message, const int& t_socket, uint8_t msg_type, uint8_t crypto_flag, uint8_t from_user, uint8_t to_user);
        bool sendMessageOne(NETW_MSG::MSG& msg, uint8_t msg_type, uint8_t crypto_flag, uint8_t from_user, uint8_t to_user);

	public:
		crypto_server(cryptochat::cfg::cfg_srv cfg);

		void setOnMessage(const std::function<void(const std::string&) >& t_function);

		void runServer();
		void closeServer();
		void request_all_client_shutdown();

		void request_client_initial_key(client_node* client);
		void request_accept_firstrnd_key(client_node* client);

		void close_client(client_node* client, bool force = false);

		// config
		cryptochat::cfg::cfg_srv _cfg;

		virtual ~crypto_server();

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
                in >> bits(my.t.index)
                    >> bits(my.t.status);
                return (in);
            }
		};
		std::map<std::string, std::vector<user_index_status> > map_machineid_to_user_index;

		bool read_map_machineid_to_user_index();
		bool save_map_machineid_to_user_index();

		void handle_msg_MSG_CMD_RESP_KEY_HINT(NETW_MSG::MSG& m, client_node* new_client);
		void handle_msg_MSG_CMD_RESP_ACCEPT_RND_KEY(NETW_MSG::MSG& m, client_node* new_client);
		void handle_msg_MSG_CMD_RESP_USERNAME(NETW_MSG::MSG& m, client_node* new_client);
		void handle_msg_MSG_CMD_RESP_MACHINEID(NETW_MSG::MSG& m, client_node* new_client);
		void handle_new_pending_random_key(client_node* new_client);
	};

}

#endif
