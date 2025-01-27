/*
 * Author: Alain Lanthier
 */
#include "../include/challenge.hpp"
#include "../include/crc32a.hpp"
#include "../include/SHA256.h"
#include "../include/crypto_server1.hpp"
#include "../include/file_util.hpp"
#include "../include/encdec_algo.hpp"
#include <iostream>
#include <string>

#ifdef _WIN32
#pragma warning(disable : 4996)
#endif

namespace msgio
{
    // The 3 callbacks on every connection
    //      bufferevent_setcb(  bev,
    //                          msgio_server::readCallback,     // new data has arrive in input buffer
    //                          msgio_server::writeCallback,    // output buffer was writteen
    //                          msgio_server::eventCallback,    // error happens
    //                          reinterpret_cast<void*>(conn));

    void crypto_server1::connection_on_read_handler(connection* conn, const void *bufferin, size_t numBytes)
    {
        crypto_server1* cryptoserver = this;
        bool msg_ok = true;
        uint32_t expected_len = 0;

        if (conn->previous_recv_buffer.buffer.size() + numBytes < NETW_MSG::MESSAGE_HEADER)
        {
            // wait for more data
            conn->previous_recv_buffer.append((char*)bufferin, (uint32_t)numBytes);
            return;
        }
        else
        {
            conn->recv_buffer.buffer.clear();
            if (conn->previous_recv_buffer.buffer.size() > 0)
            {
                conn->recv_buffer.append((char*)conn->previous_recv_buffer.buffer.getdata(), conn->previous_recv_buffer.buffer.size());
            }
            conn->recv_buffer.append((char*)bufferin, (uint32_t)numBytes);
        }

        if (conn->recv_buffer.buffer.size() == 0)
        {
            return;
        }

// Process all full messages recv
int n_msg_processed = 0;
while ( (n_msg_processed == 0) ||
        (n_msg_processed > 0 && conn->previous_recv_buffer.buffer.size() >= NETW_MSG::MESSAGE_HEADER))
{
        if (n_msg_processed > 0)
        {
            conn->recv_buffer.buffer.clear();
            conn->recv_buffer.append((char*)conn->previous_recv_buffer.buffer.getdata(), conn->previous_recv_buffer.buffer.size());
        }

        //------------------------------------------------------
        // Validate 1 th message send by a client - abort if wrong
        //------------------------------------------------------
        if (conn->msg_counter == 0)
        {
            bool ok = true;

            uint8_t  original_flag	= conn->recv_buffer.buffer.getdata()[NETW_MSG::MESSAGE_FLAG_START];
            uint32_t from_user		= NETW_MSG::MSG::byteToUInt4((char*)conn->recv_buffer.buffer.getdata()+NETW_MSG::MESSAGE_FROM_START);
            uint32_t to_user		= NETW_MSG::MSG::byteToUInt4((char*)conn->recv_buffer.buffer.getdata()+NETW_MSG::MESSAGE_TO_START);

            if (memcmp(conn->recv_buffer.buffer.getdata() + NETW_MSG::MESSAGE_SIGNATURE_START, NETW_MSG::MESSAGE_SIGNATURE, 20) != 0)
            {
                std::cout << "Validate 1 th message failed MESSAGE_SIGNATURE\n";
                ok = false;
            }

             // TODO
            if (ok)
            {
                uint8_t t = (uint8_t) (conn->recv_buffer.buffer.getdata()[0]);
                if (t != NETW_MSG::MSG_FIRST)
                {
                    std::cout << "Validate 1 th message failed != NETW_MSG::MSG_FIRST\n";
                    std::cout << "code= " << (int32_t) t << "\n";
                    ok = false;
                }
            }
            if (ok && from_user != 0)
            {
                std::cout << "Validate 1 th message failed if (ok && from_user != 0)\n";
                ok = false;
            }
            if (ok && to_user != 0)
            {
                std::cout << "Validate 1 th message failed if (ok && to_user != 0)\n";
                ok = false;
            }
            //...

            if (ok == false)
            {
                msg_ok = false;

                // KILL client
                std::cout << "Validate 1 th message failed, kill_client\n";
                conn->previous_recv_buffer.buffer.clear();
                kill_client(conn);
                return;
            }
        }

        if (msg_ok == false)
        {
            return;
        }

        expected_len = NETW_MSG::MSG::byteToUInt4(conn->recv_buffer.buffer.getdata_nc() + 1);
        if (conn->msg_counter == 0)
        {
            if (expected_len > NETW_MSG::MESSAGE_SIZE)
            {
                msg_ok = false;
                // KILL client
                std::cout << "Validate 1 th message failed (expected_len > NETW_MSG::MESSAGE_SIZE)\n";
                conn->previous_recv_buffer.buffer.clear();
                kill_client(conn);
                return;
            }
        }

        if (conn->recv_buffer.buffer.size() < expected_len)
        {
            // wait for more data
            conn->previous_recv_buffer.buffer.clear();
            conn->previous_recv_buffer.append((char*)conn->recv_buffer.buffer.getdata(), conn->recv_buffer.buffer.size());
            return;
        }

        // store extra data for next msg
        if (conn->recv_buffer.buffer.size() >= expected_len)
        {
            uint32_t delta = conn->recv_buffer.buffer.size() - expected_len;
            if (delta > 0)
            {
                conn->previous_recv_buffer.buffer.clear();
                conn->previous_recv_buffer.append((char*)conn->recv_buffer.buffer.getdata()+expected_len, delta);
            }
            else
            {
                conn->previous_recv_buffer.buffer.clear();
            }
        }
        else
        {
            // not reachable
        }
        n_msg_processed++;

        connection* new_client  = conn;
        uint8_t original_type	= conn->recv_buffer.buffer.getdata()[0];
        uint8_t original_flag	= conn->recv_buffer.buffer.getdata()[NETW_MSG::MESSAGE_FLAG_START];
        uint32_t from_user		= NETW_MSG::MSG::byteToUInt4((char*)conn->recv_buffer.buffer.getdata()+NETW_MSG::MESSAGE_FROM_START);
        uint32_t to_user		= NETW_MSG::MSG::byteToUInt4((char*)conn->recv_buffer.buffer.getdata()+NETW_MSG::MESSAGE_TO_START);

        if (original_type != NETW_MSG::MSG_VALIDATION)
            std::cout
                    << "recv msg (socket:" << new_client->getSocketFd() << ") no:"
                    << conn->msg_counter + 1
                    << ", type:"         << std::to_string((long)(uint8_t)conn->recv_buffer.buffer.getdata()[0])
                    << ", crypto:"       << std::to_string((int)original_flag)
                    << ", from_user:"   << from_user
                    << ", to_user:"     << to_user
                    << ", expected_len:" << expected_len
                    << ", recv_len:"     << conn->recv_buffer.buffer.size()
                    //<< ", MSG_VALIDATION count=" << conn->MSG_VALIDATIONcounter
                    << std::endl;

        if (original_type == NETW_MSG::MSG_VALIDATION)
            conn->MSG_VALIDATIONcounter++;

        // Parse message
        std::stringstream serr;
        NETW_MSG::MSG m;
        bool r;

        if (conn->recv_buffer.buffer.getdata()[0] == NETW_MSG::MSG_CMD_RESP_KEY_HINT)
            r = m.parse((char*)conn->recv_buffer.buffer.getdata(), expected_len, getDEFAULT_KEY(), serr);
        else if (!new_client->initial_key_validation_done)
            r = m.parse((char*)conn->recv_buffer.buffer.getdata(), expected_len, getDEFAULT_KEY(), serr);
        else if (!new_client->random_key_validation_done)
            r = m.parse((char*)conn->recv_buffer.buffer.getdata(), expected_len, new_client->initial_key64, serr);
        else
            // TODO remove extra key check
            r = m.parse((char*)conn->recv_buffer.buffer.getdata(), expected_len, new_client->random_key, serr, new_client->previous_random_key, new_client->pending_random_key);

        if (r && conn->msg_counter == 0)
        {
            std::string msg1 = m.get_data_as_string();

            if (msg1 != "hello")
            {
                msg_ok = false;
                //  KILL client
                std::cout << "Validate 1 th message failed (msg1 != hello)\n";
                conn->previous_recv_buffer.buffer.clear();
                kill_client(new_client);
                return;
            }
        }

        if (r == true)
        {
            conn->msg_counter++;

//            if (m.type_msg == NETW_MSG::MSG_TEXT)
//            {
//                uint32_t delta = conn->recv_buffer.buffer.size() - expected_len;
//                std::string msg1 = m.get_data_as_string();
//                std::cout
//                        << "recv msg parsed (socket:" << new_client->getSocketFd() << ") no:"
//                        << conn->msg_counter
//                        << ", msg:" << msg1
//                        << ", delta:" << delta
//                        << std::endl;
//             }

            if (m.type_msg == NETW_MSG::MSG_VALIDATION)
            {
                if (!new_client->initial_key_validation_done)
                {
                    if (new_client->count_initial_key_validation < 3)
                    {
                        cryptoserver->request_client_initial_key(new_client);
                    }
                    else
                    {
                        // KILL client
                        std::cout << "Validate failed (new_client->count_initial_key_validation >= 3)\n";
                        conn->previous_recv_buffer.buffer.clear();
                        kill_client(new_client);
                        return;
                    }
                }
                else if (new_client->username.size() == 0 && new_client->requ_username_waiting_resp==false)
                {
                    if (DEBUG_INFO)
                        std::cout << "send MSG_CMD_REQU_USERNAME " << new_client->getSocketFd() << std::endl;

                    NETW_MSG::MSG m;
                    std::string s = "Please, provide your username : ";
                    m.make_msg(NETW_MSG::MSG_CMD_REQU_USERNAME, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

                    new_client->requ_username_waiting_resp = true;

                    std::stringstream serr;
                    cryptoserver->send_composite(new_client->getSocketFd(), m,
                        new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);

                    if (DEBUG_INFO)
                        std::cout << serr.str();
                }
                else if (new_client->machine_id.size() == 0 && new_client->requ_machineid_waiting_resp==false)
                {
                    if (DEBUG_INFO)
                        std::cout << "send MSG_CMD_REQU_MACHINEID " << new_client->getSocketFd() << std::endl;

                    NETW_MSG::MSG m;
                    std::string s = "Please, provide your id : ";
                    m.make_msg(NETW_MSG::MSG_CMD_REQU_MACHINEID, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

                    new_client->requ_machineid_waiting_resp= true;

                    std::stringstream serr;
                    cryptoserver->send_composite(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64,serr);
                    if (DEBUG_INFO)
                        std::cout << serr.str();
                }
                else if (new_client->hostname.size() == 0 && new_client->requ_hostname_waiting_resp == false)
                {
                    if (DEBUG_INFO)
                        std::cout << "send MSG_CMD_REQU_HOSTNAME " << new_client->getSocketFd() << std::endl;

                    NETW_MSG::MSG m;
                    std::string s = "Please, provide your hostname : ";
                    m.make_msg(NETW_MSG::MSG_CMD_REQU_HOSTNAME, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

                    new_client->requ_hostname_waiting_resp = true;

                    std::stringstream serr;
                    cryptoserver->send_composite(new_client->getSocketFd(), m, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64,serr);
                    if (DEBUG_INFO)
                        std::cout << serr.str();
                }
                else if (
                        new_client->initial_key_validation_done &&
                        new_client->username.size() != 0 &&
                        new_client->machine_id.size() != 0 &&
                        new_client->hostname.size() != 0 &&
                        new_client->requ_accept_rnd_waiting_resp == false)
                {
                    cryptoserver->request_accept_firstrnd_key(new_client); // first rnd key
                }
            }

            else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_KEY_HINT)
            {
                cryptoserver->handle_msg_MSG_CMD_RESP_KEY_HINT(m, new_client);
            }
            else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_ACCEPT_RND_KEY)
            {
                cryptoserver->handle_msg_MSG_CMD_RESP_ACCEPT_RND_KEY(m, new_client);
            }
            else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_USERNAME)
            {
                cryptoserver->handle_msg_MSG_CMD_RESP_USERNAME(m, new_client);
            }
            else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_HOSTNAME)
            {
                new_client->requ_hostname_waiting_resp = false;

                if (DEBUG_INFO)
                    std::cout << "send MSG_CMD_RESP_HOSTNAME " << new_client->getSocketFd() << std::endl;

                std::string host = m.get_data_as_string();
                if (host.size() == 0)
                {
                    std::cout << "WARNING - Received empty hostname " << new_client->user_index << std::endl;
                }

                if (DEBUG_INFO)
                    std::cout << "recv MSG_CMD_RESP_HOSTNAME" << std::endl;

                if (host.size() != 0)
                {
                    new_client->hostname = host;
                    std::cout << "INFO client[" << new_client->getSocketFd() << "] hostname:" << new_client->hostname << std::endl;
                }
                else
                {
                    new_client->hostname = "unknown";
                    std::cout << "INFO client[" << new_client->getSocketFd() << "] hostname:" << new_client->hostname << std::endl;
                }
                cryptoserver->handle_info_client(new_client->getSocketFd());
            }
            else if (m.type_msg == NETW_MSG::MSG_CMD_RESP_MACHINEID)
            {
                cryptoserver->handle_msg_MSG_CMD_RESP_MACHINEID(m, new_client);
            }

            // RELAY
            else if (m.type_msg == NETW_MSG::MSG_FILE_FRAGMENT)
            {
                if (DEBUG_INFO) std::cout << "recv MSG_FILE_FRAGMENT : " << std::endl;
                if (DEBUG_INFO) std::cout << std::string((char*)m.buffer + NETW_MSG::MESSAGE_HEADER, 40) << std::endl;

                bool send_to_one = false;

                if (to_user != 0)
                {
                    send_to_one = true;
                }

                if (send_to_one == false)
                {
                    cryptoserver->sendMessageAll(m, new_client->getSocketFd(),original_flag, from_user, to_user);
                }
                else
                {
                    cryptoserver->sendMessageOne(m, m.type_msg, original_flag, from_user, to_user);
                }
            }
            // RELAY
            else if (m.type_msg == NETW_MSG::MSG_FILE)
            {
                if (DEBUG_INFO) std::cout << "recv MSG_FILE : " << std::endl;
                std::string s = m.get_data_as_string(); // filename

                bool send_to_one = false;

                if (to_user != 0)
                {
                    send_to_one = true;
                }

                if (send_to_one == false)
                {
                    cryptoserver->sendMessageAll(m, new_client->getSocketFd(),original_flag, from_user, to_user);
                }
                else
                {
                    cryptoserver->sendMessageOne(m, m.type_msg, original_flag, from_user, to_user);
                }
            }
            // RELAY
            else if (m.type_msg == NETW_MSG::MSG_TEXT)
            {
                //std::cout << "recv MSG_TEXT : " << std::endl;
                bool send_to_one = false;

                if (to_user != 0)
                {
                    send_to_one = true;
                }

                if (send_to_one == false)
                {
                    cryptoserver->sendMessageAll(m, new_client->getSocketFd(),original_flag, from_user, to_user);
                }
                else
                {
                    cryptoserver->sendMessageOne(m, m.type_msg, original_flag, from_user, to_user);
                }

                // new random encryption key per message
                if (new_client->new_pending_random_key == true)
                {
                    cryptoserver->handle_new_pending_random_key(new_client);
                }
                else
                {
                    if (USE_BASE64_RND_KEY_GENERATOR == false)
                        new_client->pending_random_key = cryptoAL::random::generate_base10_random_string(NETW_MSG::KEY_SIZE);
                    else
                        new_client->pending_random_key = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);

                    new_client->new_pending_random_key = true;
                }
            }
        }
        else if (DEBUG_INFO)
        {
            std::cout << serr.str() << std::endl;
        }
        serr.str({});
}

    }

	void crypto_server1::set_key_hint()
	{
		if (_cfg._map_challenges.size() > 0)
		{
			// TODO pick one at random...
			auto iter = _cfg._map_challenges.begin();
			initial_key_hint = iter->first;
			initial_key = iter->second;
			initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, msgio::getDEFAULT_KEY());

			std::cout << std::endl;
			std::cout << "INFO initial challenge set to : " << std::endl;
			_cfg.print_challenge(initial_key_hint, iter->second);
			std::cout << std::endl;
		}
		else
		{
			// TODO ask user...
			//
			// For KEYS: cryptoAL_vigenere::AVAILABLE_CHARS for KEYS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
			initial_key_hint = "1th prime number\n1000th prime number";
			initial_key = "27919";
			initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, msgio::getDEFAULT_KEY());
		}
	}

	void crypto_server1::handle_new_client(msgio::connection* new_client)
	{
		// send current list
		handle_info_client(new_client->getSocketFd(), false);
	}


    void crypto_server1::handle_remove_client()
    {
    }

    void crypto_server1::handle_info_client(const evutil_socket_t& t_socket, bool send_to_current_user_only)
    {
        std::string v;
        std::string s;

    	std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
		for (auto& [sock, client] : connections)
		{
            if (client->user_index > 0 && client->hostname.size() > 0 && client->username.size() > 0)
            {
                s=std::to_string(client->user_index) + ";" + client->hostname + ";" + client->username + ";";
                v+=s;
            }
		}

		// MSG_CMD_INFO_USERLIST
		if (v.size() > 0)
		{
			if (send_to_current_user_only)
				sendMessageOneBySocket(v, t_socket, NETW_MSG::MSG_CMD_INFO_USERLIST,0,0,0);
			else
				sendMessageClients(v, NETW_MSG::MSG_CMD_INFO_USERLIST,0,0,0);
        }
    }


	void crypto_server1::sendMessageClients(const std::string& t_message, uint8_t msg_type,
                                            uint8_t crypto_flag, uint32_t from_user, uint32_t to_user)
	{
        std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
		for (auto& [sock, client] : connections)
		{
            //if (client->getState() == STATE::OPEN)
			{
				NETW_MSG::MSG  m;

				std::string key;
				if (!client->initial_key_validation_done) key = msgio::getDEFAULT_KEY();
				else if (!client->random_key_validation_done) key = client->initial_key64;
				else key = client->random_key;

				m.make_msg(msg_type, t_message, key);
				std::stringstream serr;
				send_composite(client->getSocketFd(), m, key, serr,crypto_flag, from_user, to_user);
				if (DEBUG_INFO)
					std::cout << serr.str();
			}
		}
	}


	void crypto_server1::sendMessageClients(const std::string& t_message,
                                            uint8_t crypto_flag, uint32_t from_user, uint32_t to_user)
	{
		sendMessageClients(t_message, NETW_MSG::MSG_TEXT, crypto_flag, from_user, to_user);
	}


	// Relay message m
	void crypto_server1::sendMessageAll(const std::string& t_message, const evutil_socket_t& t_socket, uint8_t msg_type,
                                        uint8_t crypto_flag, uint32_t from_user, uint32_t to_user)
	{
        std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
		for (auto& [sock, client] : connections)
		{
			if (client->getSocketFd() != t_socket)
			{
				//if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done) key = msgio::getDEFAULT_KEY();
					else if (!client->random_key_validation_done) key = client->initial_key64;
					else key = client->random_key;

					NETW_MSG::MSG m;
					m.make_msg(msg_type, t_message, key);
					std::stringstream serr;
					send_composite(client->getSocketFd(), m, key, serr, crypto_flag, from_user, to_user);
					if (DEBUG_INFO)
						std::cout << serr.str();
				}
			}
		}
	}

	bool crypto_server1::sendMessageOne(NETW_MSG::MSG& m, uint8_t msg_type,
                                        uint8_t crypto_flag, uint32_t in_from_user, uint32_t in_to_user)
	{
		bool r = false;
        std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
		for (auto& [sock, client] : connections)
		{
			if (client->user_index == in_to_user)
			{
				//if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done) key = msgio::getDEFAULT_KEY();
					else if (!client->random_key_validation_done) key = client->initial_key64;
					else key = client->random_key;

					std::stringstream serr;
					int ret = send_composite(client->getSocketFd(), m, key, serr, crypto_flag, in_from_user, in_to_user);
					if (ret >= 0)
						r = true;
                    if (DEBUG_INFO)
                        std::cout << serr.str();
				}
				break;
			}
		}
		return r;
	}

    int crypto_server1::send_packet(const evutil_socket_t& t_socketFd, uint8_t* buffer, uint32_t buffer_len, std::stringstream& serr)
    {
        msgio::connection* client = nullptr;

        std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
        if (connections.contains(t_socketFd))
            client = connections[t_socketFd];

        if (client == nullptr)
        {
            serr << "WARNING - send_packet - no client\n";
			return -1;
        }

		if (buffer_len > msgio::SIZE_PACKET)
		{
			serr << "ERROR - packet too big\n";
			return -1;
		}

        queue_packet(client, buffer, buffer_len);
		return buffer_len;
    }

    int crypto_server1::send_composite( const evutil_socket_t& t_socketFd, NETW_MSG::MSG& m, std::string key, std::stringstream& serr,
                                        uint8_t crypto_flag, uint32_t from_user, uint32_t to_user)
    {
		int r = 0;
		if (cryptoAL::VERBOSE_DEBUG)
			serr << std::endl << "send_composite" << std::endl;

		// chat layer first
		NETW_MSG::MSG m2;
		if (m2.make_encrypt_msg(m, key, crypto_flag, from_user, to_user, serr) == false)
		{
			serr << "ERROR - send_composite - make_encrypt_msg FAILED\n";
			return -1;
		}

		if (cryptoAL::VERBOSE_DEBUG)
			serr << "send_composite - msg encrypted by chat layer, new len:" << m2.buffer_len << std::endl;

		uint32_t expected_len = NETW_MSG::MSG::byteToUInt4((char*)m2.buffer + 1);
		if (expected_len != m2.buffer_len)
		{
			serr << "ERROR - send_composite - (expected_len != m2.buffer_len)" << std::endl;
			return -1;
		}

		if (m2.buffer_len <= SIZE_PACKET)
		{
			if (cryptoAL::VERBOSE_DEBUG)
				serr << "send_composite - sending single packet, len= " << m2.buffer_len <<std::endl;

			return send_packet(t_socketFd, m2.buffer, m2.buffer_len, serr);
		}

		if (cryptoAL::VERBOSE_DEBUG)
			serr << "send_composite - multi packet message" << std::endl;

		uint32_t bytes_sent = 0;
		uint32_t bytes_to_send = 0;

		while (bytes_sent < m2.buffer_len)
		{
			bytes_to_send = m2.buffer_len - bytes_sent;
			if (bytes_to_send > SIZE_PACKET)
				bytes_to_send = SIZE_PACKET;

			if (cryptoAL::VERBOSE_DEBUG)
				serr << "send_composite - sending a packet, len= " << bytes_to_send << std::endl;

			int bytes_s0 = send_packet(t_socketFd, m2.buffer + bytes_sent, bytes_to_send, serr);
			bytes_sent += bytes_s0;
		}

		if (bytes_sent > m2.buffer_len)
		{
			// unreachable
			return -1;
		}

		return m2.buffer_len;
    }


	bool crypto_server1::sendMessageOneBySocket(const std::string& t_message, const evutil_socket_t& t_socket,
                                                uint8_t msg_type,
                                                uint8_t crypto_flag, uint32_t in_from_user, uint32_t in_to_user)
	{
		bool r = false;
		msgio::connection* client = nullptr;

		std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
        if (connections.contains(t_socket))
            client = connections[t_socket];
        if (client == nullptr) return false;

		{
			if (client->getSocketFd() == t_socket)
			{
				//if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done) key = msgio::getDEFAULT_KEY();
					else if (!client->random_key_validation_done) key = client->initial_key64;
					else key = client->random_key;

					NETW_MSG::MSG m;
					m.make_msg(msg_type, t_message, key);

					m.buffer[NETW_MSG::MESSAGE_FLAG_START] = crypto_flag;
					NETW_MSG::MSG::uint4ToByte(in_from_user, (char*)m.buffer + NETW_MSG::MESSAGE_FROM_START);
					NETW_MSG::MSG::uint4ToByte(in_to_user,   (char*)m.buffer + NETW_MSG::MESSAGE_TO_START);

					std::stringstream serr;
					int ret = send_composite(client->getSocketFd(), m, key, serr, crypto_flag, in_from_user, in_to_user);
					if (ret >= 0)
						r = true;
                    if (DEBUG_INFO)
                        std::cout << serr.str();
				}
			}
		}
		return r;
	}


	void crypto_server1::sendMessageAll(NETW_MSG::MSG& m, const evutil_socket_t& t_socket,
                                        uint8_t crypto_flag, uint32_t in_from_user, uint32_t in_to_user)
	{
		std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
		for (auto& [sock, client] : connections)
		{
			if (client->getSocketFd() != t_socket)
			{
				//if (client->getState() == STATE::OPEN)
				{
					std::string key;
					if (!client->initial_key_validation_done) key = msgio::getDEFAULT_KEY();
					else if (!client->random_key_validation_done) key = client->initial_key64;
					else key = client->random_key;

					std::stringstream serr;
					send_composite(client->getSocketFd(), m, key, serr, crypto_flag, in_from_user, in_to_user);
					if (DEBUG_INFO)
                        std::cout << serr.str();
				}

			}
		}
	}

	// NETW_MSG::MSG_TEXT
	void crypto_server1::sendMessageAll( const std::string& t_message, const evutil_socket_t& t_socket,
                                        uint8_t crypto_flag, uint32_t from_user, uint32_t to_user)
	{
		sendMessageAll(t_message, t_socket, NETW_MSG::MSG_TEXT, crypto_flag, from_user, to_user);
	}

    void crypto_server1::request_all_client_shutdown()
	{
        std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
		for (auto& [sock, client] : connections)
		{
            std::string key;
            if (!client->initial_key_validation_done) key = msgio::getDEFAULT_KEY();
            else if (!client->random_key_validation_done) key = client->initial_key64;
            else key = client->random_key;

			NETW_MSG::MSG m;
			m.make_msg(NETW_MSG::MSG_CMD_REQU_SHUTDOWN, "shutdown", key);
			std::stringstream serr;
			send_composite(client->getSocketFd(), m, key, serr);
			if (DEBUG_INFO)
                std::cout << serr.str();
		}
	}

	void crypto_server1::request_client_initial_key(msgio::connection* client)
	{
		if (!client->initial_key_validation_done && client->initial_key_validation_waiting_answer==false)
		{
			if (DEBUG_INFO)
                std::cout << "send MSG_CMD_REQU_KEY_HINT " << client->getSocketFd() << std::endl;

			NETW_MSG::MSG m;
			std::string s = initial_key_hint;
			m.make_msg(NETW_MSG::MSG_CMD_REQU_KEY_HINT, s, msgio::getDEFAULT_KEY());

			client->initial_key_validation_waiting_answer = true;
            client->count_initial_key_validation++;

			std::stringstream serr;
			send_composite(client->getSocketFd(), m, msgio::getDEFAULT_KEY(),serr);
			if (DEBUG_INFO)
                std::cout << serr.str();
		}
	}

	void crypto_server1::request_accept_firstrnd_key(msgio::connection* client)
	{
        //std::cout << "request_accept_firstrnd_key" << client->getSocketFd() << std::endl;

		if (client->requ_accept_rnd_waiting_resp == false)
		{
			if (DEBUG_INFO)
                std::cout << "send MSG_CMD_REQU_ACCEPT_RND_KEY " << client->getSocketFd() << std::endl;
			if (DEBUG_INFO)
				std::cout << "First Random key send ["
				+ file_util::get_summary_hex((char*)first_pending_random_key.data(), first_pending_random_key.size())
				+ "]" << std::endl;

			SHA256 sha;
			sha.update((uint8_t*)first_pending_random_key.data(), first_pending_random_key.size());
			uint8_t* digestkey = sha.digest();
			std::string str_digest = sha.toString(digestkey);
			delete[]digestkey;

			if (DEBUG_INFO)
				std::cout << "First Random key send digest ["
					+ str_digest
					+ "]" << std::endl;

			NETW_MSG::MSG m;
			client->pending_random_key = first_pending_random_key;

			m.make_msg(NETW_MSG::MSG_CMD_REQU_ACCEPT_RND_KEY, client->pending_random_key,
				client->random_key_validation_done ? client->random_key : client->initial_key64);

			client->requ_accept_rnd_waiting_resp = true;

			std::stringstream serr;
			send_composite(client->getSocketFd(), m, client->random_key_validation_done ? client->random_key : client->initial_key64, serr);
			if (DEBUG_INFO)
                std::cout << serr.str();
		}
	}

	void crypto_server1::kill_all_clients()
	{
        request_all_client_shutdown();

        std::unique_lock<std::recursive_mutex> l(mConnectionsMutex);
        while(connections.size() > 0)
        {
            auto iter = connections.begin();
            kill_client(iter->second);
		}
	}

	void crypto_server1::close_server()
	{
		sendMessageClients("Server closed.",0,0,0);

		this->kill_all_clients();
	}

	crypto_server1::~crypto_server1()
	{
		save_map_machineid_to_user_index();
		this->close_server();
	}

	void crypto_server1::handle_msg_MSG_CMD_RESP_KEY_HINT(NETW_MSG::MSG& m, msgio::connection* new_client)
	{
		if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_KEY_HINT" << std::endl;
		if (DEBUG_INFO) std::cout.flush();

		new_client->initial_key_validation_waiting_answer = false;

		std::string s = m.get_data_as_string();
        if (s.size() == 0)
        {
            std::cout << "WARNING - Received empty challenge answer " << new_client->user_index << std::endl;
        }

		if (s == initial_key)
		{
            if (DEBUG_INFO)
                std::cout << "send MSG_CMD_INFO_KEY_VALID " << new_client->getSocketFd() << std::endl;

   			new_client->initial_key = initial_key;
			new_client->initial_key64 = NETW_MSG::MSG::make_key_64(initial_key, msgio::getDEFAULT_KEY());
			new_client->initial_key_validation_done = true;

			NETW_MSG::MSG m;
			m.make_msg(NETW_MSG::MSG_CMD_INFO_KEY_VALID, "Initial key is valid", msgio::getDEFAULT_KEY());

			std::stringstream serr;
			send_composite(new_client->getSocketFd(), m, msgio::getDEFAULT_KEY(), serr);
			std::cout << serr.str();
		}
		else
		{
            std::cout << "INFO - Received invalid challenge answer " << new_client->user_index << std::endl;
		}
	}

	bool crypto_server1::read_map_machineid_to_user_index()
	{
		try
		{
			std::string filename = this->_cfg._machineid_filename;
			std::ifstream infile;
			infile.open(filename, std::ios_base::in);
			infile >> bits(next_user_index);
			infile >> bits(map_machineid_to_user_index);
			infile.close();
		}
		catch (...)
		{
			std::cerr << "WARNING map_machineid can not be read " << this->_cfg._machineid_filename;
			return false;
		}
		for (auto& e : map_machineid_to_user_index)
		{
			for (auto& v : e.second)
			{
				v.status = 0; // no active
			}
		}

		std::cout << "next_user_index: " << next_user_index << std::endl;

		save_map_machineid_to_user_index();
		return true;
	}

	bool crypto_server1::save_map_machineid_to_user_index()
	{
		try
		{
			std::string filename = this->_cfg._machineid_filename;
			std::ofstream out;
			out.open(filename, std::ios_base::out);
			out << bits(next_user_index);
			out << bits(map_machineid_to_user_index);
			out.close();
		}
		catch (...)
		{
			return false;
		}
		return true;
	}

	void crypto_server1::handle_msg_MSG_CMD_RESP_ACCEPT_RND_KEY(NETW_MSG::MSG& m, msgio::connection* new_client)
	{
        new_client->requ_accept_rnd_waiting_resp = false; // first time only
        //new_client->new_pending_random_key_waiting  = false;

        {
            if (DEBUG_INFO)
                std::cout << "recv MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
            if (DEBUG_INFO)
                std::cout.flush();

            std::string s = m.get_data_as_string(); // rnd key digest

            SHA256 sha;
            sha.update((uint8_t*)new_client->pending_random_key.data(), new_client->pending_random_key.size());
            uint8_t* digestkey = sha.digest();
            std::string str_digest = sha.toString(digestkey);
            delete[]digestkey;

            if (s == str_digest)
            {
                if (DEBUG_INFO)
                    std::cout << "send MSG_CMD_INFO_RND_KEY_VALID " << new_client->getSocketFd() << std::endl;

                NETW_MSG::MSG m;
                m.make_msg(NETW_MSG::MSG_CMD_INFO_RND_KEY_VALID, "Random key is valid",
                    new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

                std::stringstream serr;
                send_composite(new_client->getSocketFd(), m,
                    new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);

                if (DEBUG_INFO)
                    std::cout << serr.str();

                new_client->previous_random_key = new_client->random_key;
                new_client->random_key = new_client->pending_random_key;

                new_client->random_key_validation_done = true;
                new_client->new_pending_random_key = false;

                //std::cout << "set new_pending_random_key_waiting to false" << std::endl;
                new_client->new_pending_random_key_waiting = false;
            }
            else
            {
                //std::cout << "recv MSG_CMD_RESP_ACCEPT_RND_KEY" << std::endl;
                //std::cout << "ERROR received invalid random_key digest " << new_client->getSocketFd() << " " << s << std::endl;

                // Kill client
                kill_client(new_client);
                std::cout << "WARNING client invalid random_key digest - closing socket : " << new_client->getSocketFd() << " " << std::endl;
            }
        }
    }

    void crypto_server1::handle_msg_MSG_CMD_RESP_USERNAME(NETW_MSG::MSG& m, msgio::connection* new_client)
    {
        bool requ_username_waiting_resp = false;

        std::string user = m.get_data_as_string();
        if (user.size() == 0)
        {
            std::cout << "WARNING - Received empty username" << new_client->user_index << std::endl;
        }

        if (DEBUG_INFO) std::cout << "recv MSG_CMD_RESP_USERNAME" << std::endl;

        if (user.size() == 0) user = "user";
        new_client->username = user + "_" + std::to_string(new_client->getSocketFd()) ;
        std::cout << "INFO client[" << new_client->getSocketFd() << "] username:" << new_client->username << std::endl;

        {
            if (DEBUG_INFO) std::cout << "send MSG_CMD_ACCEPT_USERNAME " << new_client->getSocketFd() << std::endl;

            NETW_MSG::MSG msg;
            msg.make_msg(NETW_MSG::MSG_CMD_ACCEPT_USERNAME, new_client->username,
                new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

            std::stringstream serr;
            send_composite(new_client->getSocketFd(), msg,
                new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);
            if (DEBUG_INFO)
                std::cout << serr.str();
        }
        handle_info_client(new_client->getSocketFd());
    }

    void crypto_server1::handle_msg_MSG_CMD_RESP_MACHINEID(NETW_MSG::MSG& m, msgio::connection* new_client)
    {
		new_client->requ_machineid_waiting_resp = false;

        if (DEBUG_INFO)
            std::cout << "recv MSG_CMD_RESP_MACHINEID" << std::endl;

        std::string id = m.get_data_as_string();
        if (id.size() == 0)
        {
            std::cout << "NWARNING - Received empty machine id " << new_client->user_index << std::endl;
        }

        if (id.size() != 0)
        {
            new_client->machine_id = id;
            std::cout << "INFO client[" << new_client->getSocketFd() << "] id:" << new_client->machine_id << std::endl;

            if (map_machineid_to_user_index.contains(id) == false)
            {
                new_client->user_index = next_user_index;
                next_user_index++;
                map_machineid_to_user_index[id].push_back({new_client->user_index, 1});
                save_map_machineid_to_user_index();

                std::cout << "New machineid added, user= " << new_client->user_index << std::endl;

                if (DEBUG_INFO)
                    std::cout << "send MSG_CMD_INFO_USERINDEX " << new_client->getSocketFd() << std::endl;

                NETW_MSG::MSG m;
                std::string s = std::to_string(new_client->user_index);
                m.make_msg(NETW_MSG::MSG_CMD_INFO_USERINDEX, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

                std::stringstream serr;
                send_composite(new_client->getSocketFd(), m,
                    new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);
                if (DEBUG_INFO)
                    std::cout << serr.str();

                // new_client->user_index changed =>MSG_CMD_INFO_USERLIST
                handle_info_client(new_client->getSocketFd());
            }
            else if (new_client->user_index == 0)
            {
                // handle multiple instance on same machineid
                bool user_index_exist = false;

                for (auto& v : map_machineid_to_user_index[id])
                {
                    if (v.status == 0)
                    {
                        user_index_exist = true;
                        new_client->user_index = v.index;
                        v.status = 1;
                        break;
                    }
                }

                if (user_index_exist)
                {

                }
                else
                {
                    new_client->user_index = next_user_index;
                    map_machineid_to_user_index[id].push_back({new_client->user_index, 1});
                    next_user_index++;
                    save_map_machineid_to_user_index();
                }

                if (DEBUG_INFO) std::cout << "send MSG_CMD_INFO_USERINDEX " << new_client->getSocketFd() << std::endl;

                NETW_MSG::MSG m;
                std::string s = std::to_string(new_client->user_index);
                m.make_msg(NETW_MSG::MSG_CMD_INFO_USERINDEX, s, new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);
                std::stringstream serr;
                send_composite(new_client->getSocketFd(), m,
                    new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64, serr);
                if (DEBUG_INFO)
                    std::cout << serr.str();

                // new_client->user_index changed =>MSG_CMD_INFO_USERLIST
                handle_info_client(new_client->getSocketFd());
            }
        }
        else
        {
            kill_client(new_client);
            std::cout << "WARNING client no machine id - closing socket : " << new_client->getSocketFd() << " " << std::endl;
        }
    }

    void crypto_server1::handle_new_pending_random_key(msgio::connection* new_client)
    {
        if (new_client->new_pending_random_key_waiting == true)
            return;

        //std::cout << "set new_pending_random_key_waiting to true" << std::endl;
        new_client->new_pending_random_key_waiting = true;

        std::string work = new_client->pending_random_key;

        if (DEBUG_INFO)
            std::cout << "send MSG_CMD_REQU_ACCEPT_RND_KEY " << new_client->getSocketFd() << std::endl;
        if (DEBUG_INFO)
            std::cout << "Random key send ["
            + file_util::get_summary_hex((char*)work.data(), work.size())
            + "]" << std::endl;

        SHA256 sha;
        sha.update((uint8_t*)work.data(), work.size());
        uint8_t* digestkey = sha.digest();
        std::string str_digest = sha.toString(digestkey);
        delete[]digestkey;

        if (DEBUG_INFO)
        {
            std::cout << "Random key send digest ["
                + str_digest
                + "]" << std::endl;

            CRC32 chk;
            chk.update((char*)work.data(), work.size());
            std::cout << "Random key send CRC32 ["
                << chk.get_hash()
                << "]" << std::endl;

            std::cout << "Random key send ["
                << work
                << "]" << std::endl;
        }

        NETW_MSG::MSG m;
        m.make_msg(NETW_MSG::MSG_CMD_REQU_ACCEPT_RND_KEY, new_client->pending_random_key,
            new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64);

        std::stringstream serr;
        send_composite(new_client->getSocketFd(), m,
            new_client->random_key_validation_done ? new_client->random_key : new_client->initial_key64,serr);
        if (DEBUG_INFO)
            std::cout << serr.str();
    }

}
