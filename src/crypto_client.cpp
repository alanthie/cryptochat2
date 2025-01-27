/*
 * Author: Alain Lanthier
 */

#include <iostream>
#include <string>
#ifdef _WIN32
#include <conio.h>
#else
#endif

#include <stdlib.h>
#include <chrono>
#include <iostream>
#include <fstream>

#include "../include/crypto_const.hpp"
#include "../include/crypto_client.hpp"
#include "../include/crc32a.hpp"
#include "../include/Menu.h"
#include "../include/chat_cli.hpp" // std::atomic<int> cryptochat::cli::chat_cli::got_chat_cli_signal
#include "../include/main_global.hpp"
#include "../include/data.hpp"
#include "../include/challenge.hpp"
#include "../include/file_util.hpp"
#include "../include/encdec_algo.hpp"
#include "../include/machineid.h"

#include <ciso646>
#include <iostream>
#include <string>
#include <filesystem>

//extern int main_client_ui( crypto_socket::crypto_client* netw_client, bool auto_ui);
extern int main_client_ui1(crypto_socket::crypto_client* netw_client, bool auto_ui);

namespace crypto_socket
{

	bool crypto_client::is_got_chat_cli_signal()
	{
		if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1) return true;
		return false;
	}

	void crypto_client::setDefault() {
		inet_pton(AF_INET, this->m_serverName.c_str(), &this->m_socketInfo.sin_addr);
	}

	void crypto_client::_connectServer()
	{
		this->createSocket();

		int r = connect(this->m_socketFd, reinterpret_cast<sockaddr*> (&this->m_socketInfo), this->m_addressLen);
		if (r == -1)
		{
#ifdef _WIN32
			int r = WSAGetLastError();
			std::stringstream ss; ss << "WSAGetLastError() = " << r;
			main_global::log(ss.str());
			ss.str({});
#endif
            //std::cout << "ERROR - connect error: " << errno << "\n";
			throw std::runtime_error("could not connect to server");

			//Linux Error 111: Connection Refused
			//netstat -tlnp | grep 14003
			//telnet 127.0.0.1 14003
		}
	}

	// SEND FILE FRAGMENT THREAD
	void crypto_client::send_pending_file_packet_thread()
	{
		this->m_send_thread = std::move(std::thread([=, this]
		{
			while (true)
			{
				if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
				{
					std::stringstream ss;
					ss << "Exiting thread send_pending_file_packet_thread " << std::endl;
					main_global::log(ss.str(), true);
					ss.str({});
					break;
				}

				std::string key = get_key();
				int send_status;
				bool r = send_next_pending_file_packet(this->m_socketFd, key, send_status);
				if (r)
                {
                    ui_dirty = true;
				}

				// sleep ...
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}
		}));
	}

    std::string crypto_client::get_input(const std::string& q)
	{
		std::cout << q << ": ";
		std::string message;
		std::cin >> message;
		std::cout << std::endl;

		std::cin.ignore(0x7fffffffffffffff, '\n');
		std::cin.clear();

		return message;
	}

	// RECV THREAD
	void crypto_client::recv_thread(bool auto_ui_)
	{
		this->m_recv_thread = std::move(std::thread([=, this]
		{
            bool auto_ui = auto_ui_;
			bool msg_ok = true;
			int len;
			size_t byte_recv = 0;
			uint32_t expected_len = 0;
			char message_buffer[NETW_MSG::MESSAGE_SIZE + 1];
			char message_previous_buffer[NETW_MSG::MESSAGE_SIZE + 1];

			std::stringstream ss;
			while (msg_ok && this->m_state == STATE::OPEN)
			{
				if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
				{
					ss << " Exiting thread recv_thread " << std::endl;
					main_global::log(ss.str());
					ss.str({});
					msg_ok = false;
					break;
				}

				if (byte_recv > 0)
				{
					memcpy(message_buffer, message_previous_buffer, byte_recv);
				}

				while (byte_recv < NETW_MSG::MESSAGE_HEADER && msg_ok==true)
				{
					if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
					{
						ss << " Exiting thread recv_thread " << std::endl;
						main_global::log(ss.str());
						ss.str({});
						msg_ok = false;
						break;
					}

					//--------------
					// RECV
					//--------------
					len = recv(this->m_socketFd, message_buffer + byte_recv, NETW_MSG::MESSAGE_HEADER - byte_recv, 0);
					if (len < 0 && errno == EINTR)
					{
                        // continue
                        ss << "WARNING recv() EINTR signal interrupted" << std::endl;
                        main_global::log(ss.str());
						ss.str({});
					}
					else if (len > 0)
					{
						byte_recv += len;
						cli_byte_recv = byte_recv;
					}
					else if (len == 0)
                    {
                        ss << "client disconnected"  << " " << "\n";
                        msg_ok = false;
						main_global::log(ss.str(), true);
						ss.str({});
						break;
                    }
					else if (errno != EAGAIN && errno != EWOULDBLOCK)
					{
						ss << "ERROR - 1 recv() failed with error: " << errno << " " << strerror(errno) << "\n";
						msg_ok = false;
						main_global::log(ss.str(), true);
						ss.str({});
						break;
					}
					else
					{
                        // continue
                        ss << "WARNING recv() EAGAIN or EWOULDBLOCK" << std::endl;
                        main_global::log(ss.str());
						ss.str({});
					}
				}

				expected_len = NETW_MSG::MSG::byteToUInt4(message_buffer + 1);

				cryptoAL::cryptodata recv_buffer; // new instance ...use reset TODO
				if (byte_recv > 0)
				{
					recv_buffer.buffer.write(message_buffer, byte_recv);
				}

				size_t len_recv_buffer_call = 0;
				while (byte_recv < expected_len && msg_ok==true)
				{
					if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
					{
						ss << " Exiting thread recv_thread " << std::endl;
						main_global::log(ss.str());
						ss.str({});
						msg_ok = false;
						break;
					}

					len_recv_buffer_call = expected_len - byte_recv;
					if (len_recv_buffer_call > NETW_MSG::MESSAGE_SIZE) len_recv_buffer_call = NETW_MSG::MESSAGE_SIZE;

					//--------------
					// RECV
					//--------------
					len = recv(this->m_socketFd, message_buffer, len_recv_buffer_call, 0);
					if (len < 0 && errno == EINTR)
					{
                        // continue
                        ss << "WARNING recv() EINTR signal interrupted" << std::endl;
                        main_global::log(ss.str());
						ss.str({});
					}
					else if (len > 0)
					{
						byte_recv += len;
						cli_byte_recv = byte_recv;
						recv_buffer.buffer.write(message_buffer, len);
					}
					else if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
					{
                        // continue
                        ss << "WARNING recv() EAGAIN or EWOULDBLOCK" << std::endl;
                        main_global::log(ss.str());
						ss.str({});
					}
					else
					{
						if (len == 0)
							ss << "WARNING recv() - socket closed" << std::endl;
						else
							ss << "WARNING recv() - socket error" << std::endl;

						msg_ok = false;
						main_global::log(ss.str());
						ss.str({});
						break;
					}
				}

				if (msg_ok)
				{
					if (byte_recv >= expected_len)
					{
						byte_recv = byte_recv - expected_len;
						if (byte_recv > 0)
						{
							if (byte_recv <= NETW_MSG::MESSAGE_SIZE)
								memcpy(message_previous_buffer, message_buffer, byte_recv);
							else
							{
                                // not possible...
								ss << "WARNING recv() - excess data recv" << byte_recv << std::endl;
								main_global::log(ss.str());
                                ss.str({});
							}
						}
					}
				}

				if (!msg_ok)
				{
					break;
				}

				uint8_t original_flag = recv_buffer.buffer.getdata()[NETW_MSG::MESSAGE_FLAG_START];
				bool crypto_msg = (original_flag > 0) ? true : false;
				uint32_t from_user	= NETW_MSG::MSG::byteToUInt4((char*)recv_buffer.buffer.getdata() + NETW_MSG::MESSAGE_FROM_START);
				uint32_t to_user	= NETW_MSG::MSG::byteToUInt4((char*)recv_buffer.buffer.getdata() + NETW_MSG::MESSAGE_TO_START);

				if (DEBUG_INFO)
				{
					ss << "recv msg"
						<< " type:" << std::to_string((int)recv_buffer.buffer.getdata()[0])
						<< " crypto:" << std::to_string((int)original_flag)
						<< " from_user: " << from_user
						<< " to_user: " << to_user
						<< " len: " << expected_len
						<< std::endl;
//std::cout << ss.str() << std::endl;
					main_global::log(ss.str());
					ss.str({});
				}

				bool r = true;
				NETW_MSG::MSG m;
				NETW_MSG::MSG msgout;

				//-----------------------------------------------
				// Parse message
				//	call make_decrypt_msg()
				// 	call crypto_decrypt()
				//-----------------------------------------------
				if (r == true)
				{
					{
						std::lock_guard l(_key_mutex);

						if (!key_valid)	        r = m.parse((char*)(char*)recv_buffer.buffer.getdata(), expected_len, getDEFAULT_KEY(), ss);
						else if (!rnd_valid)    r = m.parse((char*)(char*)recv_buffer.buffer.getdata(), expected_len, get_initial_key64(), ss);
						else                    r = m.parse((char*)(char*)recv_buffer.buffer.getdata(), expected_len, random_key, ss, previous_random_key, pending_random_key);
					}

					if (r==false)
					{
                        ss << "WARNING - Parsing error - msg dropped" << std::endl;
                        main_global::log(ss.str()); ss.str({});
					}

					if (r)
					{
                        if (original_flag > 0) // crypto flag
                        {
                            r = crypto_decrypt(from_user, to_user, (char*)m.buffer, m.buffer_len, msgout);

                            if (!r)
                            {
                                ss << "WARNING - Failed to decrypt recv message" << std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }
                            else
                            {
                                ss << "crypto_decrypt ok - msgin len: " << m.buffer_len << " ==> msgout len: " << msgout.buffer_len << std::endl;
                                main_global::log(ss.str());
                                ss.str({});

                                m.reset();
                                m.make_msg(msgout.buffer, msgout.buffer_len);
                            }
                        }
                    }

                    if (r)
                    {
                        std::string str_message = m.get_data_as_string();

                        if (m.type_msg == NETW_MSG::MSG_CMD_REQU_SHUTDOWN)
                        {
                            {
                                ss << "recv MSG_CMD_REQU_SHUTDOWN" << std::endl;
                                main_global::log(ss.str());ss.str({});
                            }

                            std::string key = get_key();
                            msg_ok = false;
                            cryptochat::cli::chat_cli::got_chat_cli_signal = 1;

                            // socked should stop after next send or recv
                            NETW_MSG::MSG m;
                            m.make_msg(NETW_MSG::MSG_CMD_RESP_SHUTDOWN, "shutdown", key);

                            ss << "send MSG_CMD_RESP_SHUTDOWN" << std::endl;
                            main_global::log(ss.str());ss.str({});
                            send_message_buffer(this->m_socketFd, m, key);
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_KEY_HINT)
                        {
                            challenge_attempt++;
                            {
                                ss << "recv MSG_CMD_REQU_KEY_HINT" << std::endl;
                                main_global::log(ss.str()); ss.str({});
                            }

                            if (_cfg_cli.map_challenges.contains(str_message))
                            {
                                ss << "using known challenge answer" << std::endl;
                                ss << "send MSG_CMD_RESP_KEY_HINT" << std::endl;

                                {
                                    std::lock_guard l(_key_mutex);
                                    initial_key_hint = str_message;
                                    initial_key = _cfg_cli.map_challenges[str_message]; // but key_valid = false until confirmed
                                    initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
                                }
                                ss << "initial_key_hint set" << std::endl;
                                main_global::log(ss.str()); ss.str({});

                                NETW_MSG::MSG m;
                                m.make_msg(NETW_MSG::MSG_CMD_RESP_KEY_HINT, _cfg_cli.map_challenges[str_message], getDEFAULT_KEY());

                                ss << "send MSG_CMD_RESP_KEY_HINT" << std::endl;
                                main_global::log(ss.str());ss.str({});
                                this->send_message_buffer(this->m_socketFd, m, getDEFAULT_KEY());
                            }
                            else if (auto_ui)
                            {
                                {
                                    std::lock_guard l(_key_mutex);
                                    initial_key_hint = str_message;
                                    initial_key = "27919";
                                    initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
                                }

                                //ss << "initial_key_hint set" << std::endl;
                                //main_global::log(ss.str()); ss.str({});

                                NETW_MSG::MSG m;
                                m.make_msg(NETW_MSG::MSG_CMD_RESP_KEY_HINT, "27919", getDEFAULT_KEY());

                                ss << "send MSG_CMD_RESP_KEY_HINT" << std::endl;
                                main_global::log(ss.str());ss.str({});
                                this->send_message_buffer(this->m_socketFd, m, getDEFAULT_KEY());
                            }
                            else
                            {
                                std::string work = str_message;
                                std::vector<std::string> lines = NETW_MSG::split(work, "\n");
                                std::vector<std::string> comments;
                                std::vector<std::string> questions;
                                std::vector<int> question_types;
                                for (size_t i = 0; i < lines.size(); i++)
                                {
                                    if (lines[i][0] == 'C')
                                        comments.push_back(lines[i].substr(1, lines[i].size() - 1));
                                    else if (lines[i][0] == 'F')
                                    {
                                        questions.push_back(lines[i].substr(1, lines[i].size() - 1));
                                        question_types.push_back(1);
                                    }
                                    else if (lines[i][0] == 'T')
                                    {
                                        questions.push_back(lines[i].substr(1, lines[i].size() - 1));
                                        question_types.push_back(0);
                                    }
                                }

                                std::vector< std::string> a;
                                for (size_t i = 0; i < questions.size(); i++) a.push_back({});

                                bool menu_abort = false;
                                while (true)
                                {
                                    if (is_got_chat_cli_signal())
                                    {
                                        ss << "Terminating menu" << std::endl;
                                        main_global::log(ss.str()); ss.str({});
                                        menu_abort = true;
                                        break;
                                    }

                                    Menu qa;
                                    qa.set_heading(std::string("Challenges (q TO QUIT MENU)")
                                        + std::string(" [Attempt: ") + std::to_string(challenge_attempt) + "]",
                                        comments);

                                    qa.set_max_len(120);
                                    for (size_t i = 0; i < questions.size(); i++)
                                        qa.add_field(std::string("[" + std::to_string(i + 1) + "] ") + questions[i] + " : " + a[i], nullptr);

                                    // Blocking....to do
                                    int c = qa.get_menu_choice();
                                    if (c == 'q')
                                    {
    # ifdef _WIN32
                                        system("cls");
    # else
                                        system("clear");
    # endif
                                        break;
                                    }

                                    int idx = c - '1';
                                    if ((idx >= 0) && (idx < questions.size()))
                                    {
                                        // Blocking....to do
                                        a[idx] = get_input("Enter answer [" + std::to_string(idx + 1) + "]");
                                    }
                                }

                                if (!menu_abort)
                                {
                                    std::string r;
                                    for (size_t i = 0; i < questions.size(); i++)
                                    {
                                        if (question_types[i] == 1)
                                        {
                                            std::string out_answer;
                                            std::string out_error;
                                            bool r = NETW_MSG::challenge_answer(a[i], out_answer, out_error);
                                            if (r)
                                            {
                                                a[i] = out_answer;
                                            }
                                        }
                                        r += a[i];
                                    }

                                    {
                                        {
                                            ss << "recv MSG_CMD_REQU_KEY_HINT" << std::endl;
                                            main_global::log(ss.str());
                                            ss.str({});
                                        }

                                        {
                                            std::lock_guard l(_key_mutex);
                                            initial_key_hint = str_message;
                                            initial_key = r; // but key_valid = false until confirmed
                                            initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
                                        }

                                        NETW_MSG::MSG m;
                                        m.make_msg(NETW_MSG::MSG_CMD_RESP_KEY_HINT, r, getDEFAULT_KEY());

                                        ss << "send MSG_CMD_RESP_KEY_HINT" << std::endl;
                                        main_global::log(ss.str());ss.str({});
                                        this->send_message_buffer(this->m_socketFd, m, getDEFAULT_KEY());
                                    }
                                }
                            }
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_KEY_VALID)
                        {
                            {
                                ss << "recv MSG_CMD_INFO_KEY_VALID" << std::endl;

                                // CONFIRMED new key
                                key_valid = true;
                                if (initial_key_hint.size() > 0)
                                {
                                    std::string serr;
                                    _cfg_cli.map_challenges[initial_key_hint] = initial_key;

                                   //ss << "saving challenge answer" << std::endl;
                                    bool ret = _cfg_cli.save_cfg(_cfgfile, serr);
                                    if (ret == false)
                                    {
                                        ss << serr;
                                    }

                                    initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, getDEFAULT_KEY());
                                }
                                else
                                {
                                    ss << "WARNING initial_key_hint empty" << std::endl;
                                }
                                main_global::log(ss.str());
                                ss.str({});

                                add_to_history(true, crypto_msg, from_user, my_user_index, NETW_MSG::MSG_CMD_INFO_KEY_VALID, str_message);
                            }
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_KEY_INVALID)
                        {
                            {
                                ss << "recv MSG_CMD_INFO_KEY_INVALID" << std::endl;
                                main_global::log(ss.str()); ss.str({});
                            }

                            key_valid = false;

                            add_to_history(true, crypto_msg, from_user, my_user_index, NETW_MSG::MSG_CMD_INFO_KEY_INVALID, str_message);
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_ACCEPT_USERNAME)
                        {
                            ss << "recv MSG_CMD_ACCEPT_USERNAME " << str_message << std::endl;
                            this->username = str_message;

                            if (map_user_index_to_user.contains(my_user_index))
                            {
                                std::string h;
                                char host[80] = { 0 };
                                if (gethostname(host, 80) == 0)
                                {
                                    h = std::string(host);
                                    this->hostname = h;
                                }

                                userinfo ui;
                                ui.host = h;
                                ui.usr = str_message;
                                map_user_index_to_user[user_index] = ui;
                                set_user_view_dirty(true);
                            }
                            main_global::log(ss.str()); ss.str({});
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_ACCEPT_RND_KEY)
                        {
                            pending_random_key = str_message;
                            std::string work = pending_random_key;

                            SHA256 sha;
                            sha.update((uint8_t*)work.data(), work.size());
                            uint8_t* digestkey = sha.digest();
                            std::string str_digest = sha.toString(digestkey);
                            delete[]digestkey;

                            ss << "recv MSG_CMD_REQU_ACCEPT_RND_KEY" << std::endl;

                            if (DEBUG_INFO)
                            {
                                ss << "Random key recv ["
                                    + file_util::get_summary_hex((char*)work.data(), work.size()) + "]" << std::endl;

                                ss << "Random key digest recv [" + str_digest + "]" << std::endl;

                                CRC32 chk;
                                chk.update((char*)work.data(), work.size());
                                ss << "Random key CRC32 recv [" << chk.get_hash() << "]" << std::endl;
                            }
                            main_global::log(ss.str()); ss.str({});

                            std::string key = get_key();

                            NETW_MSG::MSG m;
                            m.make_msg(NETW_MSG::MSG_CMD_RESP_ACCEPT_RND_KEY, str_digest, key);

                            ss << "send MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
                            main_global::log(ss.str());ss.str({});
                            this->send_message_buffer(this->m_socketFd, m, key);

                            // CONFIRMED new rnd key immediately
                            // On the reception of resp, the server will change rnd key
                            // So next TEXT msg send, must use the new rnd key
                            {
                                std::lock_guard l(_key_mutex);
                                previous_random_key = random_key;
                                random_key = pending_random_key;
                                rnd_valid = true;
                            }
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_RND_KEY_VALID)
                        {
                            {
                                {
                                    ss << "recv MSG_CMD_INFO_RND_KEY_VALID" << std::endl;
                                    main_global::log(ss.str());
                                    ss.str({});
                                }
                            }
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_USERNAME)
                        {
                            {
                                ss << "recv MSG_CMD_REQU_USERNAME" << std::endl;
                                main_global::log(ss.str()); ss.str({});
                            }

                            if (_cfg_cli._username.size() == 0)
                            {
                                std::string r;
                                if (auto_ui)
                                {
                                    pid_t pid = getpid();
                                    r = "usr_" + std::to_string((int)pid);
                                }
                                else
                                {
                                    r = get_input("Enter username");
                                    if (r.size() == 0) r = "user_xyz"; // TODO validate
                                }
                                _cfg_cli._username = r;

                                std::string serr;
                                bool ret =  _cfg_cli.save_cfg(_cfgfile, serr);
                                if (!ret)
                                {
                                    ss <<  serr << std::endl;
                                    main_global::log(ss.str());
                                    ss.str({});
                                }
                            }
                            user_valid = true;

                            {
                                ss << "send MSG_CMD_RESP_USERNAME : " << _cfg_cli._username << std::endl;
                                main_global::log(ss.str()); ss.str({});
                            }

                            NETW_MSG::MSG m;
                            std::string key = get_key();

                            m.make_msg(NETW_MSG::MSG_CMD_RESP_USERNAME, _cfg_cli._username, key);
                            this->send_message_buffer(this->m_socketFd, m, key);
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_HOSTNAME)
                        {
                            {
                                ss << "recv MSG_CMD_REQU_HOSTNAME" << std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }

                            char host[80] = { 0 };
                            if (gethostname(host, 80) == 0)
                            {
                                std::string h = std::string(host);
                                this->hostname = h;

                                NETW_MSG::MSG m;
                                std::string key = get_key();

                                m.make_msg(NETW_MSG::MSG_CMD_RESP_HOSTNAME, h, key);

                                ss << "send MSG_CMD_RESP_HOSTNAME : " << h << std::endl;
                                main_global::log(ss.str());ss.str({});
                                this->send_message_buffer(this->m_socketFd, m, key);
                            }
                            else
                            {
                                ss << "WARNING gethostname failed" << std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_REQU_MACHINEID)
                        {
                            {
                                ss << "recv MSG_CMD_REQU_MACHINEID" << std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }

                            //-------------------------------------------
                            // my_machineid
                            //-------------------------------------------
                            std::string my_machineid = machineid::machineHash();
                            this->machine_id = my_machineid;

                            {
                                NETW_MSG::MSG m;
                                std::string key = get_key();

                                ss << "send MSG_CMD_RESP_MACHINEID : " << my_machineid << std::endl;
                                main_global::log(ss.str());ss.str({});
                                m.make_msg(NETW_MSG::MSG_CMD_RESP_MACHINEID, my_machineid, key);

                                std::stringstream serr;
                                this->send_composite(this->m_socketFd, m, key, serr);
                                main_global::log(serr.str());
                                ss.str({});
                            }
                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_USERINDEX)
                        {
                            {
                                ss << "recv MSG_CMD_INFO_USERINDEX " << str_message << std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }

                            //-------------------------------------------
                            // my_user_index
                            //-------------------------------------------
                            my_user_index = (uint32_t)NETW_MSG::str_to_ll(str_message);

                            {
                                ss << "My USERINDEX set to " << str_message << std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }

                        }
                        else if (m.type_msg == NETW_MSG::MSG_CMD_INFO_USERLIST)
                        {
                            {
                                ss << "recv MSG_CMD_INFO_USERLIST : " << std::endl;
                                ss << "     " << str_message << std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }

                            //s = v_client[i]->std::to_string(v_client[i]->user_index) + ";" + v_client[i]->hostname + ";" + v_client[i]->username + ";";
                            std::string work = str_message;
                            std::vector<std::string> tokens = NETW_MSG::split(work, ";");

                            uint32_t user_index;
                            std::string in_host;
                            std::string in_usr;

                            int cnt = 0;
                            bool new_user = false;
                            uint32_t new_user_index = 0;
                            for (size_t i = 0; i < tokens.size(); i++)
                            {
                                if (cnt == 0)
                                {
                                    user_index = (uint32_t)NETW_MSG::str_to_ll(tokens[i]);
                                }
                                else if (cnt == 1) in_host = tokens[i];
                                else if (cnt == 2) in_usr = tokens[i];

                                if (cnt == 2)
                                {
                                    if (user_index > 0 && in_host.size() > 0 && in_usr.size() > 0)
                                    {
                                        if (user_index != my_user_index)
                                        if (map_user_index_to_user.contains(user_index) == false)
                                        {
                                            new_user_index = user_index;
                                            new_user = true;
                                        }
                                        handle_info_client(user_index, in_host, in_usr);
                                    }
                                }
                                cnt++;
                                if (cnt >= 3) cnt = 0;
                            }
                            if (new_user && _cfg_cli.default_new_user_cmd.empty() == false)
                                std::system(_cfg_cli.default_new_user_cmd.c_str());
                            //std::system("mpg123 -q /home/allaptop/dev/toot/quothello-therequot-158832.mp3");
                        }
                        else if (m.type_msg == NETW_MSG::MSG_TEXT)
                        {
                            {
                                ss << "recv MSG_TEXT : " << "..."<< std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }

                            add_to_history(true, crypto_msg, from_user, my_user_index, NETW_MSG::MSG_TEXT , str_message);
                            ui_dirty = true;
                        }

                        else if (m.type_msg == NETW_MSG::MSG_FILE)
                        {
                            {
                                ss << "recv MSG_FILE : " << str_message << std::endl;
                                main_global::log(ss.str());
                                ss.str({});
                            }

                            std::string filename;
                            std::string filename_key;
                            int for_display = true;

                            bool ok = false;
                            if (str_message.size() > 6)
                            {
                                for (size_t p = 1; p < str_message.size(); p++)
                                {
                                    if (str_message[p] == ',')
                                    {
                                        filename = str_message.substr(1, p - 1);
                                        for (size_t k = p+1; k < str_message.size(); k++)
                                        {
                                            if (str_message[k] == ',')
                                            {
                                                filename_key = str_message.substr(p + 1, k - 1 - p);
                                                if (str_message[k + 1] == '1') for_display = true;
                                                else for_display = false;

                                                ok = true;
                                                break;
                                            }
                                        }
                                        break;
                                    }
                                }
                            }

                            if (ok)
                            {
                                add_to_history(true, crypto_msg, from_user, my_user_index, NETW_MSG::MSG_FILE, str_message, filename, filename_key, for_display);
                                ui_dirty = true;
                            }
                        }

                        else if (m.type_msg == NETW_MSG::MSG_FILE_FRAGMENT)
                        {
//                            {
//                                ss << "recv MSG_FILE_FRAGMENT" << std::endl;
//                                main_global::log(ss.str()); ss.str({});
//                            }

                            NETW_MSG::MSG_FILE_FRAGMENT_HEADER mh;
                            bool r = NETW_MSG::MSG::parse_file_fragment_header_from_msg(m, mh);
                            if (r)
                            {
                                r = add_file_to_recv(mh.filename, mh.filename_key);
                                if (r)
                                {
                                    // LOCK
                                    std::lock_guard lck(_map_file_to_recv_mutex);

                                    size_t idx_fragment;
                                    r = map_file_to_recv[mh.filename_key].add_recv_fragment_data(mh,
                                                        m.buffer + NETW_MSG::MESSAGE_HEADER + mh.header_size(),
                                                        m.buffer_len - (NETW_MSG::MESSAGE_HEADER + mh.header_size()), idx_fragment);
                                    if (r)
                                    {
                                        auto& binfile = map_file_to_recv[mh.filename_key];
                                        binfile.set_fragment_processed(idx_fragment, m.buffer_len - (NETW_MSG::MESSAGE_HEADER + mh.header_size()) );

                                        //----------------------------------------------------
                                        // save file if fully received for media viewing
                                        // TODO -   Use a staging folder to sync file between chat and mediaviewer
                                        //          Notify media viewer of new staging file - IPC
                                        //          _repository.get_staging_folder_chat_session()
                                        //----------------------------------------------------
                                        if (binfile._is_processing_done)
                                        {
                                            if (binfile._file != nullptr)
                                            {
                                                std::string strcnt = std::to_string(1000000+mediaviewer_file_cnt).substr(1);

                                                std::string save_file = _repository.get_folder_chat_session_current()
                                                                        + cryptochat::db::Repository::file_separator()
                                                                        + strcnt + "_" + binfile._filename;

                                                bool is_mp4 = false;
                                                bool is_mp3 = false;
                                                std::filesystem::path p(save_file);
                                                std::string extension = p.extension().string();
                                                if (extension == ".mp4") is_mp4 = true;
                                                //if (extension == ".mp3") is_mp3 = true;

                                                std::filesystem::path praw(save_file);
                                                praw.replace_extension("");
                                                std::string rawname = praw.string();

												bool r = true;
/*
                                                if (is_mp3)
                                                {
													// rename if required
													//...
													r = binfile._file->save_to_file(save_file, &ss);
													if (!r)
													{
														ss << "WARNING unable to save file: " << save_file << std::endl;
														main_global::log(ss.str()); ss.str({});
													}
													else
													{
														ss  << "recv file saved to: [" << save_file << "] " << std::endl;
														main_global::log(ss.str()); ss.str({});
													}

													if (r)
													{
														// make an mp4 with blank images
														std::string mp4file = save_file + ".mp4";
														std::string cmd = std::string("ffmpeg -f lavfi -i color=c=black:s=1280x720:r=5 -i ")
																		+ "\"" + save_file + "\""
																		+ std::string(" -c:v libx264 -tune stillimage -c:a aac -b:a 192k -pix_fmt yuv420p -shortest ")
																		+ "\"" + mp4file + "\""
																		+ std::string(" -loglevel quiet");
														//ffmpeg -f lavfi -i color=c=black:s=1280x720:d=300 -i t.mp3 -c:v libx264 -tune stillimage -c:a aac -b:a 192k -pix_fmt yuv420p -shortest tt.mp4
														//ffmpeg -f lavfi -i color=c=black:s=1280x720:r=5 -i audio.mp3 -crf 0 -c:a copy -shortest output.mp4

														std::string result;
														int res = cryptochat::db::Repository::syscommand(cmd.c_str(), result);
														if (res != 0)
														{
															ss  << "ffmpeg mp4 creation from mp3 failed from file: " << save_file << std::endl;
															main_global::log(ss.str()); ss.str({});
															r = false;
														}
														else
														{
															ss  << "ffmpeg mp4 created to file: " << mp4file << std::endl;
															main_global::log(ss.str()); ss.str({});

															save_file = mp4file;
															is_mp4 = true;
															extension = ".mp4";
															std::filesystem::path praw(save_file);
															praw.replace_extension("");
															rawname = praw.string();
														}

														// delete the mp3 file
														//...
													}
                                                }
*/
												std::string audio_file = save_file + ".wav";
												if (r)
												{
													int cnt = 1;

													// rename if required
													while (file_util::fileexists(save_file) ||
														   (is_mp4 && file_util::fileexists(audio_file) )
														  )
													{
														save_file  = strcnt + "_" + rawname + "_" + std::to_string(cnt) + extension;
														audio_file = save_file + ".wav";
														cnt++;
													}

													r = binfile._file->save_to_file(save_file, &ss);
													if (!r)
													{
														ss << "WARNING unable to save file: " << save_file << std::endl;
														main_global::log(ss.str()); ss.str({});
													}
													else
													{
														std::filesystem::path filepath(save_file);
														std::string vext = filepath.extension().string();
														binfile._filename_mediaviewer = filepath.filename().stem().string() +  vext;	
														
														// Update vhistory
														update_history_mediaviwer_file(binfile._filename, binfile._filename_key, binfile._filename_mediaviewer);
																					
                                                        mediaviewer_file_cnt++;
														ss  << "recv file saved to:   [" << save_file << "] " << std::endl;
														ss  << "filename_mediaviewer: [" << binfile._filename_mediaviewer  << "] " << std::endl;
														main_global::log(ss.str()); ss.str({});
													}

													// DONT keep binfile in memory
													{
														if (binfile._file != nullptr)
														{
															delete binfile._file ;
															binfile._file = nullptr;
														}
													}
												}
												else
												{
													// DONT keep binfile in memory
													{
														if (binfile._file != nullptr)
														{
															delete binfile._file ;
															binfile._file = nullptr;
														}
													}
												}

												// extract sound ffmpeg -i 0001.mp4 0001.mp4.wav
                                                if (r && is_mp4)
                                                {
                                                    if (file_util::fileexists(audio_file) == false)
                                                    {
#ifndef _WIN32
                                                        std::string cmd = "ffmpeg -y -i \""
                                                                            + save_file + "\" \""
                                                                            + audio_file + "\""
                                                                            + " -loglevel quiet";

                                                        std::string result;
                                                        int res = cryptochat::db::Repository::syscommand(cmd.c_str(), result);
                                                        if (res != 0)
                                                        {
                                                            ss  << "ffmpeg sound extract failed from file: " << save_file << std::endl;
                                                            main_global::log(ss.str()); ss.str({});
                                                        }
                                                        else
                                                        {
                                                            ss  << "ffmpeg sound extract to file: " << audio_file << std::endl;
                                                            main_global::log(ss.str()); ss.str({});
                                                        }
#else
//....
//                                                        {
//                                                            filesystem::path cmd_path("..\\tools");
//                                                            std::string cmd = cmd_path.make_absolute().str()+"\\ffmpeg.exe -y -nostdin -i \"" + _file + "\" \"" + _file + ".wav\"";
//                                                            //std::cout << cmd << std::endl;
//                                                            int r = system(cmd.c_str());
//                                                        }
#endif
                                                    }
                                                    else
                                                    {
                                                        // unreachable
                                                    }
                                                }

                                                if (r)
                                                {
                                                    // TODO
                                                    // Notify mediaviewer process - IPC
                                                }
                                            }
                                            else
                                            {
                                                ss << "WARNING received file not save - binfile._file == nullptr" << std::endl;
                                                main_global::log(ss.str()); ss.str({});
                                            }
                                        }
                                        ui_dirty = true;
                                    }
                                    else
                                    {
                                        ss << "WARNING map_file_to_recv error of a MSG_FILE_FRAGMENT" << std::endl;
                                        main_global::log(ss.str()); ss.str({});
                                    }
                                }
                                else
                                {
                                    ss << "WARNING add_file_to_recv error of a MSG_FILE_FRAGMENT" << std::endl;
                                    main_global::log(ss.str());  ss.str({});
                                }
                            }
                            else
                            {
                                ss << "WARNING parsing header error of a MSG_FILE_FRAGMENT" << std::endl;
                                main_global::log(ss.str()); ss.str({});
                            }
                        }
                    }
                }
			}

			{
                ss << "recv thread done"<< std::endl;
                main_global::log(ss.str());
                ss.str({});
			}
			this->m_state = STATE::CLOSED;
		}));
	}


	void crypto_client::handle_info_client(uint32_t user_index, const std::string& in_host, const std::string& in_usr)
	{
		bool changed = false;
		std::stringstream ss;
		if (map_user_index_to_user.contains(user_index) == false)
		{
			userinfo ui;
			ui.host = in_host;
			ui.usr = in_usr;
			map_user_index_to_user[user_index] = ui;
			set_user_view_dirty(true);
			changed = true;

			ss << "New user added to active user list " << user_index << " " << in_host << " " << in_usr << std::endl;
			main_global::log(ss.str());
			ss.str({});
		}
		else
		{
			if (in_host.size() > 0 && map_user_index_to_user[user_index].host.size() == 0)
			{
				map_user_index_to_user[user_index].host = in_host;
				changed = true;
			}
			if (in_usr.size() > 0 && map_user_index_to_user[user_index].usr.size() == 0)
			{
				map_user_index_to_user[user_index].usr = in_usr;
				changed = true;
			}
		}
		if (changed)
			handle_new_client(user_index, in_host, in_usr);
	}

	void crypto_client::handle_new_client(uint32_t user_index, const std::string& in_host, const std::string& in_usr)
	{
		bool r = false;
		std::stringstream ss;
		std::string serr;

		ss << "handle_new_client " << user_index << " " << in_host << " " << in_usr<<std::endl;

		if (repository_root_set && user_index > 0 /*&& user_index == my_user_index*/) // multi instance on same machineid MUST have their own repository
		{
			r = _repository.user_exist(user_index, in_host, in_usr);
			if (r == false)
			{
				r = _repository.add_user(user_index, in_host, in_usr, serr);
				if (r)
				{
					ss << "INFO - New user add to repository " << user_index << std::endl;
					ss << serr << std::endl;
				}
				else
				{
					// multi instance...
					if (_repository.user_exist(user_index, in_host, in_usr) == false)
					{
						ss << "WARNING - Failed to add user to repository " << user_index << std::endl;
						ss << serr << std::endl;
					}
				}
			}
		}

		if (repository_root_set && user_index > 0)
		{
			r = _repository.user_exist(user_index, in_host, in_usr);
			if (r == true)
			{
				cryptochat::cfg::cfg_crypto cc;
				if (map_active_user_to_crypto_cfg.contains(user_index) == false)
				{
					std::string inifile = _repository.get_crypto_cfg_filename(user_index);
					if (!inifile.empty())
					{
						r = cc.read(inifile, serr, false);
						if (r)
						{
							map_active_user_to_crypto_cfg[user_index] = cc._p;
						}
						else
						{
							ss << "WARNING - cannot read crypto_cfg " << inifile << std::endl;
						}
					}
					else
					{
						r = false;
						ss << "WARNING - no crypto_cfg file " << inifile << std::endl;
					}
				}

				{
					if (map_active_user_to_urls.contains(user_index) == false)
					{
						map_active_user_to_urls[user_index] = cc._p.filename_urls;
					}
				}
			}
		}
		main_global::log(ss.str());
		ss.str({});
	}

	void crypto_client::client_UI(bool auto_ui)
	{
		int cnt = 0;
		std::string message = "";
		bool term_ok = true;

		while (this->m_state == STATE::OPEN && term_ok)
		{
			if (cryptochat::cli::chat_cli::got_chat_cli_signal == 1)
			{
				std::stringstream ss;
				ss << " Exiting loop client_UI " << std::endl;
				main_global::log(ss.str());
				ss.str({});
				break;
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(100));

			if (cnt == 0)
			{
                // 1th message required
				message = "hello";
				NETW_MSG::MSG m;
				std::stringstream serr;

				std::string key = get_key();
				m.make_msg(NETW_MSG::MSG_FIRST, message, key);
				this->send_composite(this->m_socketFd, m, key, serr);

                main_global::log(serr.str());
                serr.str({});
				cnt++;
			}

			if (key_valid && rnd_valid && user_valid)
			{
				// UI
				int r = main_client_ui1(this, auto_ui);
				term_ok = false;
                break;
			}

			{
                // MSG_VALIDATION until all request info obtained
                message = "validation";
				NETW_MSG::MSG m;
				std::stringstream serr;

				std::string key = get_key();
				m.make_msg(NETW_MSG::MSG_VALIDATION, message, key);
				this->send_composite(this->m_socketFd, m, key, serr);

                main_global::log(serr.str());
                serr.str({});
				cnt++;

				std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
		}
    }

	crypto_client::crypto_client(cryptochat::cfg::cfg_cli cfg, const std::string& cfgfile) :
		client_node(cfg._port),
        m_serverName(cfg._server),
        _cfg_cli(cfg),
        _cfgfile(cfgfile)
	{
		setDefault();

		std::string serr;
		if (_repository.set_root(_cfg_cli._repo_root_path, serr) == false)
		{
			repository_root_set = false;

			std::stringstream ss;
			ss << serr << std::endl;
            main_global::log(ss.str());
            ss.str({});
		}
		else
		{
			repository_root_set = true;

			std::stringstream ss;
			ss << "INFO - Repository path set to : " << _cfg_cli._repo_root_path << std::endl;
			main_global::log(ss.str());
			ss.str({});
		}

		cryptoAL::encryptor* _encryptor = nullptr;
		cryptoAL::decryptor* _decryptor = nullptr;

		//-------------------------------
		// TEST mediaviewer launch
		//-------------------------------
		_cfg_cli.mv_cfg.mediaviewer_title = "Chat Session";
		_cfg_cli.mv_cfg.data_folder = _repository.get_folder_chat_session();
		_cfg_cli.mv_cfg.res_dir     = _cfg_cli.mediaviewer_res_dir;

        std::string inifile = _mediaviewer.make_ini(_cfg_cli.mv_cfg, _cfg_cli._repo_root_path, serr);
        {
            std::stringstream ss;
			ss << serr << std::endl;
            main_global::log(ss.str());
            ss.str({}); serr = "";
        }

        // TODO make a desc.ini

        // Rename current to current_dt
        std::string fcurrent = _repository.get_folder_chat_session_current();

        //if (file_util::fileexists(_cfg_cli.mv_cfg.data_folder) == true)
        if (file_util::fileexists(fcurrent))
        {
            pid_t pid = getpid();
            time_t now = time(0);
            tm* ltm = localtime(&now);
            char date_string[100];
            strftime(date_string, 100, "%Y%m%d_%H%M%S", ltm);

            std::string prev = _repository.get_folder_chat_session_current() + "_" + std::string(date_string);

            std::filesystem::path old_path = _repository.get_folder_chat_session_current();
            std::filesystem::path new_path = prev;

            try
            {
                std::filesystem::rename(old_path, new_path);
            }
            catch (std::filesystem::filesystem_error& e)
            {
                serr += std::string("Error renaming current folder to previous: ") + e.what() + std::string("\n");
            }
        }

        if (inifile.size() > 0)
        {
			// Need a subfolder mv_cfg.data_folder/current
			std::string f = _repository.get_folder_chat_session_current();
			if (file_util::fileexists(f) == false)
				std::filesystem::create_directories(f);

			// Copy res/chat_data files
            // ...

            // Launch
            _mediaviewer.create(serr,_cfg_cli.mediaviewer_folder, inifile);
		}

		{
            std::stringstream ss;
			ss << serr << std::endl;
            main_global::log(ss.str()); ss.str({});serr = "";
        }
	}

	void crypto_client::connectServer(bool auto_ui)
	{
		this->_connectServer();
		std::cout << "Connection successful ..." << std::endl;

		this->recv_thread(auto_ui);
		this->send_pending_file_packet_thread();
	}

	void crypto_client::closeConnection()
	{
        try{
            this->closeSocket();
		}
		catch(...)
		{
		}

		if (this->m_recv_thread.joinable()) {
			this->m_recv_thread.join();
		}

		if (this->m_send_thread.joinable()) {
			this->m_send_thread.join();
		}
	}

	crypto_client::~crypto_client()
	{
		this->closeConnection();

		if (_encryptor != nullptr) delete _encryptor;
		if (_decryptor != nullptr) delete _decryptor;
	}


	bool crypto_client::add_file_to_send(const std::string& filename, const std::string& filename_key)
	{
		std::lock_guard lck(_map_file_to_send_mutex);
		if (!map_file_to_send.contains(filename_key))
		{
			map_file_to_send[filename_key] = NETW_MSG::MSG_BINFILE();

			NETW_MSG::MSG_BINFILE& binfile = map_file_to_send[filename_key];
			binfile.init(filename, filename_key, true);

			ui_dirty = true;
			return true;
		}
		return true; // already exist
	}

	bool crypto_client::add_file_to_recv(const std::string& filename, const std::string& filename_key)
	{
		std::lock_guard lck(_map_file_to_recv_mutex);
		if (!map_file_to_recv.contains(filename_key))
		{
			map_file_to_recv[filename_key] = NETW_MSG::MSG_BINFILE();

			NETW_MSG::MSG_BINFILE& binfile = map_file_to_recv[filename_key];
			binfile.init(filename, filename_key, false);

			ui_dirty = true;
			return true;
		}
		return true; // already exist
	}

	bool crypto_client::get_info_file_to_send(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done)
	{
		std::lock_guard lck(_map_file_to_send_mutex);
		if (map_file_to_send.contains(filename_key))
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_send[filename_key];
			byte_processed = binfile.byte_send;
			total_size = binfile.data_size_in_fragments();
			is_done = binfile._is_processing_done;
			return true;
		}
		return false;
	}

	bool crypto_client::get_info_file_to_recv(const std::string& filename_key, size_t& byte_processed, size_t& total_size, bool& is_done)
	{
		std::lock_guard lck(_map_file_to_recv_mutex);
		if (map_file_to_recv.contains(filename_key))
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_recv[filename_key];
			byte_processed = binfile.byte_recv;
			//total_size = binfile.data_size_in_fragments();
			total_size = binfile.total_size_read_from_fragment;
			is_done = binfile._is_processing_done;
			return true;
		}
		return false;
	}

	std::string crypto_client::get_file_to_send(const std::string& filename_key)
	{
		std::string r;
		std::lock_guard lck(_map_file_to_send_mutex);
		if (map_file_to_send.contains(filename_key))
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_send[filename_key];
			if (binfile._file != nullptr)
			{
				r = std::string(binfile._file->buffer.getdata(), binfile._file->buffer.size());
			}
		}
		return r;
	}
	std::string crypto_client::get_file_to_recv(const std::string& filename_key)
	{
		std::string r;
		std::lock_guard lck(_map_file_to_recv_mutex);
		if (map_file_to_recv.contains(filename_key))
		{
			NETW_MSG::MSG_BINFILE& binfile = map_file_to_recv[filename_key];
			if (binfile._file != nullptr)
			{
				r = std::string(binfile._file->buffer.getdata(), binfile._file->buffer.size());
			}
		}
		return r;
	}

	bool crypto_client::send_next_pending_file_packet(const int& t_socketFd, const std::string& key, int& send_status)
	{
		send_status = 0;
		bool msg_sent = false;

		std::string filename_with_pending_processing;

		{
			std::lock_guard lck(_map_file_to_send_mutex);

			if (map_file_to_send.size() == 0)
				return false;

			for (auto& [filename, binfile] : map_file_to_send)
			{
				if (binfile.has_unprocess_fragment())
				{
					filename_with_pending_processing = filename;
					break;
				}
			}
		}

		if (filename_with_pending_processing.size() > 0)
		{
            if (map_file_to_send.contains(filename_with_pending_processing) == false)
            {
                {
					std::stringstream ss;
					ss << "WARNING no file in map_file_to_send: " << filename_with_pending_processing << std::endl;
					main_global::log(ss.str(), true);
					ss.str({});
					return false;
				}
            }

			NETW_MSG::MSG_BINFILE& binfile = map_file_to_send[filename_with_pending_processing];
			NETW_MSG::MSG m;

			bool r = m.make_next_file_fragment_to_send(binfile, key, true);
			if (r)
			{
				// TODO flag is asociated with MSG_FILE file...

				uint8_t crypto_flag = (this->cryto_on == true) ? 1 : 0;
                if (this->chat_with_other_user_index == 0) crypto_flag = 0;

//				{
//					std::stringstream ss;
//					if (crypto_flag==1)
//                        ss  << "Send file fragment to " << chat_with_other_user_index
//                            << ", crypto_flag=1" << std::endl;
//					else
//                        ss  << "Send file fragment to " << chat_with_other_user_index
//                            << ", crypto_flag=0" << std::endl;
//					main_global::log(ss.str(), crypto_flag==1);ss.str({});
//				}
				send_status = send_message_buffer(	t_socketFd, m, key,
													crypto_flag,
													my_user_index,
													chat_with_other_user_index,
													false);
				msg_sent = true;
				ui_dirty = true;
			}
			else
			{
                {
					std::stringstream ss;
					ss << "WARNING make_next_file_fragment_to_send FAILED" << std::endl;
					main_global::log(ss.str(), true);
					ss.str({});
				}
			}
		}

		return msg_sent;
	}

#include "crypto_client_encdec.cpp"

}
