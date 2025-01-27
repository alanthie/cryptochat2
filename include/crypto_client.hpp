/*
 * Author: Alain Lanthier
 */

#ifndef crypto_client_H
#define crypto_client_H

#include <iostream>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

#include "socket_node.hpp"
#include "cfg_cli.hpp"
#include "repository.hpp"
#include "cfg_crypto.hpp"
#include "encryptor.hpp"
#include "decryptor.hpp"
#include "mediaviewer_interface.hpp"

namespace crypto_socket {

	struct userinfo
	{
		std::string host;
		std::string usr;
		//uint32_t user_index; // Key - 4 bytes - unique user id
	};

	class crypto_client : public client_node
	{
		const int HISTORY_SIZE = 2000;

	public:
		cryptoAL::encryptor* _encryptor = nullptr; // TEST
		cryptoAL::decryptor* _decryptor = nullptr; // TEST

		std::string my_machineid;
		uint32_t my_user_index = 0;
		uint32_t chat_with_other_user_index = 0;

	protected:
		void setDefault();
		std::string get_input(const std::string& q);

		// message event function
		std::function<void(const std::string& t_message) > m_onMessage = nullptr;
		void showMessage(const std::string& t_message);

		// server
		std::string m_serverName = "localhost";

		// thread
		std::thread m_recv_thread; // RECV thread
		std::thread m_send_thread; // SEND thread to handle all send...
		// client_UI is a loop in main thread

		void _connectServer();

    public:
		void recv_thread(bool auto_ui = false);
		void send_pending_file_packet_thread();
		void client_UI(bool auto_ui = false); // main THREAD

		std::mutex _key_mutex;
		std::mutex _vhistory_mutex;
		bool key_valid = false;
		bool rnd_valid = false;
		bool user_valid = false;
		std::atomic<bool> input_interrupted = false;

		std::mutex _send_message_mutex;

        cryptochat::cfg::cfg_cli    _cfg_cli;
        const std::string&          _cfgfile;

		// Repository of public/private keys of users
		cryptochat::db::Repository	_repository;
		bool repository_root_set = false;

		// MediaViewer interface
		cryptochat::viewer::MediaViewer _mediaviewer;

		// user index is machineid
		std::map<uint32_t, cryptochat::cfg::cfg_crypto_params> map_active_user_to_crypto_cfg;
		std::map<uint32_t, std::string> map_active_user_to_urls;

		size_t file_counter = 0;
		std::atomic<bool> ui_dirty = true;
		std::atomic<bool> ui_user_view_dirty = true;
		int challenge_attempt = 0;
		size_t history_cnt = 0;
		std::vector<NETW_MSG::netw_msg> vhistory;

		std::atomic<bool> cryto_on = false;
		std::atomic<size_t> cli_byte_recv = 0;

		size_t mediaviewer_file_cnt = 1;

	public:
		crypto_client(cryptochat::cfg::cfg_cli cfg, const std::string& cfgfile);

		void connectServer(bool auto_ui = false);
		void closeConnection();

		std::string get_DEFAULT_KEY() { return getDEFAULT_KEY(); }
		std::string get_initial_key() { return initial_key; }
		std::string get_initial_key64() { return initial_key64; }
		std::string get_random_key()  { return random_key; }

		std::map<uint32_t, userinfo> map_user_index_to_user; // user_index is key
		void handle_info_client(uint32_t user_index, const std::string& in_host, const std::string& in_usr);
		void handle_new_client( uint32_t user_index, const std::string& in_host, const std::string& in_usr);

		bool crypto_encrypt(uint32_t from_user, uint32_t to_user, NETW_MSG::MSG& msgin, NETW_MSG::MSG& msgout, bool log = false);
		bool crypto_decrypt(uint32_t from_user, uint32_t to_user, char* buffer, uint32_t buffer_len, NETW_MSG::MSG& msgout, bool log = false);;

		int send_message_buffer(const int& t_socketFd, NETW_MSG::MSG& msgin, const std::string& key,
             uint8_t crypto_flag = 0, uint8_t from_user = 0, uint8_t to_user = 0, bool log=false);

		int get_socket() { return m_socketFd; }

		std::vector<NETW_MSG::netw_msg> get_vhistory(size_t& histo_cnt)
		{
			// copy between threads
			std::lock_guard l(_vhistory_mutex);// recursive mutex deadlock to watch for
			histo_cnt = history_cnt;
			return vhistory;
		}

		void add_to_history(bool is_receive, bool crypto, uint32_t from_user, uint32_t to_user, uint8_t msg_type, std::string& msg, 
							std::string filename = {}, std::string filename_key = {}, bool is_for_display = true)
		{
			std::lock_guard l(_vhistory_mutex);// recursive mutex deadlock to watch for
			vhistory.push_back({ is_receive, crypto, from_user, to_user, msg_type, msg, filename, filename_key, "", is_for_display, {} });
			history_cnt++;
			while (vhistory.size() > HISTORY_SIZE)
			{
				vhistory.erase(vhistory.begin());
			}
		}
		
		void update_history_mediaviwer_file(const std::string& filename, const std::string& filename_key , const std::string& filename_mv)
		{
			std::lock_guard l(_vhistory_mutex);
			for(size_t i=0;i<vhistory.size();i++)
			{
				if ((vhistory[i].filename == filename) && (vhistory[i].filename_key == filename_key) )
				{
					vhistory[i].filename_mediaviewer = filename_mv;
					break;
				}
			}
		}

		// client only
		std::map<std::string, NETW_MSG::MSG_BINFILE> map_file_to_send;
		std::map<std::string, NETW_MSG::MSG_BINFILE> map_file_to_recv;
		std::mutex _map_file_to_send_mutex;
		std::mutex _map_file_to_recv_mutex;

		bool add_file_to_send(const std::string& filename, const std::string& filename_key);
		bool add_file_to_recv(const std::string& filename, const std::string& filename_key);
		bool get_info_file_to_send(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done);
		bool get_info_file_to_recv(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done);
		std::string get_file_to_send(const std::string& filename_key);
		std::string get_file_to_recv(const std::string& filename_key);

		bool send_next_pending_file_packet(const int& t_socketFd, const std::string& key, int& send_status);

        void set_ui_dirty(bool v = true)
        {
            ui_dirty = v;
        }
        bool get_ui_dirty()
        {
            return ui_dirty;
        }

        void set_user_view_dirty(bool v = true)
        {
            ui_user_view_dirty = v;
        }
        bool get_user_view_dirty()
        {
            return ui_user_view_dirty;
        }

        std::string get_key()
        {
            std::lock_guard l(_key_mutex);

            if (!key_valid)	return get_DEFAULT_KEY();
            else if (!rnd_valid) return get_initial_key64();
            return get_random_key();
        }

		static bool is_got_chat_cli_signal();

		virtual ~crypto_client();
	};

}

#endif
