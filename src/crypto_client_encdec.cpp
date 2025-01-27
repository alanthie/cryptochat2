/*
 * Author: Alain Lanthier
 */

    int crypto_client::send_message_buffer(const int& t_socketFd, NETW_MSG::MSG& msgin, const std::string& key,
                                            uint8_t crypto_flag, uint8_t from_user, uint8_t to_user,
                                            bool log)
    {
        // 2 threads may send
        std::lock_guard lck(_send_message_mutex);

        bool ok = true;
		std::stringstream ss;

		if (log)
		{
            ss << "-------------------------" << std::endl;
            ss << "send_message_buffer entry" << std::endl;
            main_global::log(ss.str(), log); ss.str({});
        }

		if (crypto_flag > 0 && to_user == 0)
		{
			ss << "WARNING - send_message_buffer - CRYPTO encryption with to_user==0 " << std::endl;
			main_global::log(ss.str(), log); ss.str({});
            ok = false;
		}

        if (crypto_flag > 0 && ok)
        {
            NETW_MSG::MSG msgout;

            //-------------------------
            // crypto_encrypt
            //-------------------------
            bool r = crypto_encrypt(from_user, to_user, msgin, msgout);

            if (r)
            {
                main_global::stats().msg2_in_count++;
                main_global::stats().msg2_in_len +=msgin.buffer_len - NETW_MSG::MESSAGE_HEADER;
                main_global::stats().msg2_out_len+=msgout.buffer_len - NETW_MSG::MESSAGE_HEADER;

                if (log)
                {
                    ss  << "crypto_encrypt ok - msgin len: " << msgin.buffer_len << " ==> msgout len: " << msgout.buffer_len << std::endl;
                    main_global::log(ss.str(), log);ss.str({});
                }

				auto ret = send_composite(t_socketFd, msgout, key, ss, crypto_flag, from_user, to_user );
				main_global::log(ss.str(), log);ss.str({});

				if (log)
				{
                    ss << "send_message_buffer exit " << std::endl;
                    ss << "-------------------------" << std::endl;
                    main_global::log(ss.str(), log); ss.str({});
                }

				return ret;
            }
            else
            {
                // SKIP crypto encryption on error (urls keys may be empty, ...)
                ss << "WARNING CRYPTO encryption FAILED  - skipping encryption" << std::endl;
                main_global::log(ss.str(), log);
				ss.str({});
                crypto_flag = 0;
            }
        }

        if (ok)
        {
            auto ret = send_composite(t_socketFd, msgin, key, ss, crypto_flag, from_user, to_user );
			main_global::log(ss.str(), log);
			ss.str({});

			if (log)
			{
                ss << "send_message_buffer exit " << std::endl;
                ss << "-------------------------" << std::endl;
                main_global::log(ss.str(), log); ss.str({});
            }
			return ret;
        }

		main_global::log(ss.str(), log);
		ss.str({});

		if (log)
		{
            ss << "send_message_buffer exit " << std::endl;
            ss << "-------------------------" << std::endl;
            main_global::log(ss.str(), log); ss.str({});
        }
		return 0;
    }

	bool crypto_client::crypto_encrypt( uint32_t from_user, uint32_t to_user,
                                        NETW_MSG::MSG& msgin, NETW_MSG::MSG& msgout,
                                        bool log)
	{
		bool r = false;
		std::stringstream ss;

        ss << "crypto_encrypt" << std::endl;
        main_global::log(ss.str(), log); ss.str({});

        if (repository_root_set == false)
        {
            ss << "WARNING no repository_root_set" << std::endl;
            main_global::log(ss.str(), log);
            ss.str({});

			return false;
        }

		if (to_user == 0)
		{
			ss << "WARNING crypto_encrypt - to_user==0 " << std::endl;
			main_global::log(ss.str(), log);
			ss.str({});
		}

		//if (from_user != my_user_index)
		//{
		//	ss << "WARNING crypto_encrypt - from_user != my_user_index" << std::endl;
		//}

		if (to_user > 0 /*&& from_user == my_user_index*/)
		{
            if (DEBUG_INFO)
                ss << "crypto_encrypt - msgin len " << msgin.buffer_len << std::endl;

			std::string s;
			if (map_active_user_to_crypto_cfg.contains(to_user) == false)
			{
				std::string inifile = _repository.get_crypto_cfg_filename(to_user);
				if (!inifile.empty())
				{
					cryptochat::cfg::cfg_crypto cc;
					r = cc.read(inifile, s, false);
					if (r)
					{
						map_active_user_to_crypto_cfg[to_user] = cc._p;
					}
					else
					{
						ss << "WARNING - cannot read crypto_cfg " << inifile << std::endl;
						main_global::log(ss.str(), log);
                        ss.str({});
					}
				}
			}

			if (map_active_user_to_urls.contains(to_user) == false)
			{
				std::string inifile = _repository.get_crypto_cfg_filename(to_user);
				cryptochat::cfg::cfg_crypto cc;
				r = cc.read(inifile, s, false);
				if (r)
				{
					map_active_user_to_urls[to_user] = cc._p.filename_urls;
				}
				else
				{
					ss << "WARNING - cannot read crypto_cfg " << inifile << std::endl;
					main_global::log(ss.str(), log);
                    ss.str({});
				}
			}

			if (map_active_user_to_crypto_cfg.contains(to_user) && map_active_user_to_urls.contains(to_user))
			{
				std::string msg_input = msgin.get_data_as_string();

				cryptoAL::cryptodata din;
				din.buffer.write(msg_input.data(), msg_input.size());

				std::string user_folder = _repository.get_user_folder(to_user) + cryptochat::db::Repository::file_separator();
                ss << "save to staging file " << user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_msg_data<< std::endl;
                main_global::log(ss.str(), log);
                ss.str({});

                bool r = din.save_to_file(user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_msg_data);

				if (DEBUG_INFO)
                    ss << "crypto_encrypt - msgin without header  " << msg_input.size() << std::endl;

				if (r)
				{
					// padding
					uint32_t len_data = din.buffer.size();
					uint32_t padding = NETW_MSG::MESSAGE_FACTOR - (len_data % NETW_MSG::MESSAGE_FACTOR); // 0-63
					if (padding == 0) padding = 64;
					char cpadding = (char)(uint8_t)padding;
					char space[1]{ ' ' };
					for (int i = 0; i < padding - 1; i++) din.buffer.write(&space[0], 1);
					din.buffer.write(&cpadding, 1);

					ss << "padding: " << padding << std::endl;
					main_global::log(ss.str(), log);
					ss.str({});

					if (DEBUG_INFO)
						ss << "crypto_encrypt padding: :" << padding << std::endl;

                    // ...
					r = din.save_to_file(user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_msg_data);

					if (DEBUG_INFO)
						ss << "crypto_encrypt filename_msg_data.buffer.size(): " << din.buffer.size() << std::endl;
                    if (DEBUG_INFO)
                        ss << "crypto_encrypt - padding " << padding << std::endl;

					if (_encryptor != nullptr)
					{
						delete _encryptor;
						_encryptor = nullptr;
					}

					// try catch...
					_encryptor = new cryptoAL::encryptor(
						{},
						user_folder + map_active_user_to_urls[to_user],
						user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_msg_data,
						{}, // user_folder + map_active_user_to_crypto_cfg[to_user].filename_full_puzzle,
						{}, // map_active_user_to_crypto_cfg[to_user].filename_partial_puzzle,
						{}, // user_folder + map_active_user_to_crypto_cfg[to_user].filename_full_puzzle,
						user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data,
						{}, // map_active_user_to_crypto_cfg[to_user].staging,
						map_active_user_to_crypto_cfg[to_user].folder_local,
						map_active_user_to_crypto_cfg[to_user].folder_my_private_rsa,
						map_active_user_to_crypto_cfg[to_user].folder_other_public_rsa,
						map_active_user_to_crypto_cfg[to_user].folder_my_private_ecc,
						map_active_user_to_crypto_cfg[to_user].folder_other_public_ecc,
						map_active_user_to_crypto_cfg[to_user].folder_my_private_hh,
						map_active_user_to_crypto_cfg[to_user].folder_other_public_hh,
						map_active_user_to_crypto_cfg[to_user].wbaes_my_private_path,
						map_active_user_to_crypto_cfg[to_user].wbaes_other_public_path,
						false,                      // Flag - verbose
						false,                      // Flag - keep staging files
						map_active_user_to_crypto_cfg[to_user].encryped_ftp_user,
						map_active_user_to_crypto_cfg[to_user].encryped_ftp_pwd,
						map_active_user_to_crypto_cfg[to_user].known_ftp_server,
						1,		// map_active_user_to_crypto_cfg[to_user].key_size_factor,          // Parameter - keys size multiplier
						true,	// map_active_user_to_crypto_cfg[to_user].use_gmp,                  // Flag - use gmp for big computation
						false,	// map_active_user_to_crypto_cfg[to_user].self_test,                // Flag - verify encryption
						0,		// map_active_user_to_crypto_cfg[to_user].shufflePerc,              // Parameter - shuffling percentage
						map_active_user_to_crypto_cfg[to_user].auto_flag,	// autoflag
						0 //map_active_user_to_crypto_cfg[to_user].converter
					);
				}
				else
                {
                    {
                        ss << "WARNING crypto_encrypt - invalid file "
							<< user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_msg_data<<std::endl;
                        main_global::log(ss.str(), log);
						ss.str({});
                    }
                }

				if (r)
				{
					/** backup cout buffer and redirect to out.txt **/
					std::ofstream out(user_folder + cryptochat::db::Repository::file_separator() + "cout_encrypt.txt");

					auto* coutbuf = std::cout.rdbuf();
					std::cout.rdbuf(out.rdbuf());

					//--------------------------------
					// CRYPTO encrypt
					//--------------------------------
					r = _encryptor->encrypt(ss, true, &main_global::msg_stats);

					std::cout.rdbuf(coutbuf);

					if (r)
					{
                        {
                            if (map_active_user_to_crypto_cfg.contains(to_user) == false)
                            {
                                ss << "WARNING no map_active_user_to_crypto_cfg[to_user] : " << "\n";
                                ss << "user_folder : " << user_folder << "\n";
                                ss << "to_user : " << to_user << "\n";

                                main_global::log(ss.str(), log);
                                ss.str({});
                                return false;
                            }
                            else if (file_util::fileexists(user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data) == false)
                            {
                                ss << "WARNING missing file " << "\n";
                                ss << "user_folder : " << user_folder << "\n";
                                ss << "to_user : " << to_user << "\n";
                                ss << "map_active_user_to_crypto_cfg[to_user].filename_encrypted_data : " << map_active_user_to_crypto_cfg[to_user].filename_encrypted_data << "\n";
                                ss << "file to read: " << user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data << "\n";

                                main_global::log(ss.str(), log);
                                ss.str({});
                                return false;
                            }
                            else if (DEBUG_INFO)
                            {
                                ss << "user_folder : " << user_folder << "\n";
                                ss << "to_user : " << to_user << "\n";
                                ss << "map_active_user_to_crypto_cfg[to_user].filename_encrypted_data : " << map_active_user_to_crypto_cfg[to_user].filename_encrypted_data << "\n";
                                ss << "file to read: " << user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data << "\n";

                                main_global::log(ss.str(), log);
                                ss.str({});
                            }
                        }

						cryptoAL::cryptodata dout;
						r = dout.read_from_file(user_folder + "encryptor_" + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data, true, &ss);
						if (r)
						{
							if (DEBUG_INFO)
								ss << "crypto_encrypt filename_encrypted_data.buffer.size(): " << dout.buffer.size() << std::endl;

                            if (DEBUG_INFO)
                                ss << "crypto_encrypt - msg encrypted len " << dout.buffer.size() << std::endl;

							// original header
							uint8_t digestkey[32];
							memcpy(&digestkey[0], msgin.buffer + NETW_MSG::MESSAGE_KEYDIGEST_START, 32);

							uint8_t chk[4];
							memcpy(&chk[0], msgin.buffer + NETW_MSG::MESSAGE_CRC_START, 4);
							uint32_t crc = NETW_MSG::MSG::byteToUInt4((char*)msgin.buffer + NETW_MSG::MESSAGE_CRC_START);

							//--------------------------------
                            // msgout
                            //--------------------------------
							msgout.make_msg_with_crc_and_flag_buffer(
								msgin.type_msg, dout.buffer.size(), (uint8_t*)dout.buffer.getdata(), digestkey, crc, 1, from_user, to_user);

                            if (DEBUG_INFO)
                                ss << "crypto_encrypt - msg encrypted with header, len " << msgout.buffer_len << std::endl;

                            uint8_t new_flag = msgout.buffer[NETW_MSG::MESSAGE_FLAG_START];
                            if (new_flag == 0)
                            {
                                ss << "ERROR crypto_encrypt - invalid crypto flag (0)" <<std::endl;
                                main_global::log(ss.str(), log);
								ss.str({});
                            }

							if (SELF_TEST)
							{
								{
									ss << "SELF TEST of encryption decryption" << std::endl;
									ss << "          msgin.size=" << msgin.buffer_len << std::endl;
									main_global::log(ss.str(), log);
									ss.str({});
								}

								NETW_MSG::MSG msgout2;
								r = crypto_decrypt(from_user, to_user,
													(char*)msgout.buffer,msgout.buffer_len,
													msgout2);
								if (r == false)
								{
									ss << "ERROR crypto_decrypt - TEST of encryption decryption FAILED" << std::endl;
									main_global::log(ss.str(), log);
									ss.str({});
									return false;
								}
								else
								{
									if (msgin.buffer_len != msgout2.buffer_len)
									{
										ss << "ERROR crypto_decrypt - SELF TEST of encryption decryption FAILED" << std::endl;
										main_global::log(ss.str(), log);
										ss.str({});
										return false;
									}
									else if (memcmp(msgin.buffer + NETW_MSG::MESSAGE_HEADER, msgout2.buffer + NETW_MSG::MESSAGE_HEADER, msgout2.buffer_len - NETW_MSG::MESSAGE_HEADER) != 0)
									{
										ss << "ERROR crypto_decrypt - SELF TEST of encryption decryption FAILED" << std::endl;
										main_global::log(ss.str(), log);
										ss.str({});
										return false;
									}

									{
										ss << "SELF TEST of encryption decryption OK" << std::endl;
										ss << "          msgout.size=" << msgout2.buffer_len << std::endl;
										main_global::log(ss.str(), log);
										ss.str({});
									}
								}
							}

							main_global::log(ss.str(), log);
							ss.str({});
                            return true;
						}
                        else
                        {
                            ss  << "WARNING crypto_encrypt - invalid file "
                                << user_folder + map_active_user_to_crypto_cfg[to_user].filename_encrypted_data<<std::endl;
                            main_global::log(ss.str(), log);
							ss.str({});
                        }
					}
					else
                    {
                        ss << "WARNING crypto_encrypt - encryptor->encrypt() failed" << std::endl;
                        main_global::log(ss.str(), log);
						ss.str({});
                    }
				}
			}
		}

		main_global::log(ss.str(), log);
		ss.str({});
		return r;
	}


		// called when new message received and crypto flag on
	bool crypto_client::crypto_decrypt(uint32_t from_user, uint32_t to_user,
                                        char* buffer, uint32_t buffer_len, NETW_MSG::MSG& msgout,
                                        bool log)
	{
		bool r = false;
		std::stringstream ss;

		if (repository_root_set == false)
		{
            ss << "WARNING crypto_decrypt() - repository_root_set == false)" << std::endl;
            main_global::log(ss.str(), log);
            ss.str({});
			return false;
        }

		if (DEBUG_INFO)
        {
            ss << "crypto_decrypt(...)" << std::endl;
			ss << "crypto_decrypt msgin.buffer_len: " << buffer_len << std::endl;
        }

		if (from_user == 0) // crypto is between two specific user
		{
            ss << "WARNING crypto_decrypt - invalid user from_user==0 - msg not decrypted" << std::endl;
		}

		// todo
		//if (to_user != my_user_index)
		//{
		//	ss << "WARNING crypto_decrypt - from_user != my_user_index" << std::endl;
		//}

		if (from_user > 0 /*&& to_user == my_user_index*/)//TEST
		{
			std::string s;
			if (map_active_user_to_crypto_cfg.contains(from_user) == false)
			{
				std::string inifile = _repository.get_crypto_cfg_filename(from_user);
				if (!inifile.empty())
				{
					cryptochat::cfg::cfg_crypto cc;
					r = cc.read(inifile, s, false);
					if (r)
					{
						map_active_user_to_crypto_cfg[from_user] = cc._p;
					}
					else
					{
						ss << "WARNING - crypto_decrypt - cannot read crypto_cfg " << inifile << std::endl;
					}
				}
			}

			if (map_active_user_to_urls.contains(from_user) == false)
			{
				std::string inifile = _repository.get_crypto_cfg_filename(from_user);
				cryptochat::cfg::cfg_crypto cc;
				r = cc.read(inifile, s, false);
				if (r)
				{
					map_active_user_to_urls[from_user] = cc._p.filename_urls;
				}
				else
				{
					ss << "WARNING - crypto_decrypt - cannot read crypto_cfg " << inifile << std::endl;
				}
			}

			if (map_active_user_to_crypto_cfg.contains(from_user) && map_active_user_to_urls.contains(from_user))
			{
				// content to decrypt is past the header
				cryptoAL::cryptodata din;
                bool r = true;

				//realloc throw...
                if (buffer_len >= cryptoAL::BUFFER_SIZE_LIM)
                {
                    ss << "WARNING crypto_decrypt buffer_len >= BUFFER_SIZE_LIM" << buffer_len << std::endl;
                    r = false;
                    main_global::log(ss.str(), log); ss.str({});
                }
                else if (buffer_len < NETW_MSG::MESSAGE_HEADER)
                {
                    ss << "WARNING crypto_decrypt buffer_len < NETW_MSG::MESSAGE_HEADER" << buffer_len << std::endl;
                    main_global::log(ss.str(), log); ss.str({});
                    r = false;
                }
                else
                {
                    din.buffer.write(buffer + NETW_MSG::MESSAGE_HEADER, buffer_len - NETW_MSG::MESSAGE_HEADER);
                }
				std::string user_folder = _repository.get_user_folder(from_user) + cryptochat::db::Repository::file_separator();

				if (r)
				{
                    r = din.save_to_file(user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_encrypted_data);
                }

				if (DEBUG_INFO)
					ss << "crypto_decrypt filename_encrypted_data.buffer.size(): " << din.buffer.size() << std::endl;

				if (r)
				{
					if (_decryptor != nullptr)
					{
						delete _decryptor;
						_decryptor = nullptr;
					}

					// try catch...
					_decryptor = new cryptoAL::decryptor(
						{},
						{}, // filename_puzzle
						user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_encrypted_data,
						user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_decrypted_data,
						{}, // staging
						map_active_user_to_crypto_cfg[from_user].folder_local,
						map_active_user_to_crypto_cfg[from_user].folder_my_private_rsa,
						map_active_user_to_crypto_cfg[from_user].folder_other_public_rsa,
						map_active_user_to_crypto_cfg[from_user].folder_my_private_ecc,
						map_active_user_to_crypto_cfg[from_user].folder_other_public_ecc,
						map_active_user_to_crypto_cfg[from_user].folder_my_private_hh,
						map_active_user_to_crypto_cfg[from_user].folder_other_public_hh,
						map_active_user_to_crypto_cfg[from_user].wbaes_my_private_path,
						map_active_user_to_crypto_cfg[from_user].wbaes_other_public_path,
						false,                      // Flag - verbose
						false,                      // Flag - keep staging files
						map_active_user_to_crypto_cfg[from_user].encryped_ftp_user,
						map_active_user_to_crypto_cfg[from_user].encryped_ftp_pwd,
						map_active_user_to_crypto_cfg[from_user].known_ftp_server,
						true,	// use_gmp,
						map_active_user_to_crypto_cfg[from_user].auto_flag,	// autoflag
						false	//converter
					);
				}
				else
				{
                    {
                        ss  << "WARNING crypto_decrypt - invalid file "
                            << user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_encrypted_data << std::endl;
                    }
				}

				if (r)
				{
					std::ofstream out(user_folder + cryptochat::db::Repository::file_separator() +"cout_decrypt.txt");
					auto* coutbuf = std::cout.rdbuf();
					std::cout.rdbuf(out.rdbuf());

					r = _decryptor->decrypt(ss);

					std::cout.rdbuf(coutbuf);

					if (r)
					{
						cryptoAL::cryptodata dout;
						r = dout.read_from_file(user_folder + "decryptor_" + map_active_user_to_crypto_cfg[from_user].filename_decrypted_data, true, &ss);
						if (r)
						{
							if (DEBUG_INFO)
                            {
								ss << "CRYPTO decryption ok" << std::endl;
								ss << "crypto_decrypt filename_decrypted_data.buffer.size(): " << dout.buffer.size() << std::endl;
                            }

							// un padding....
                            // MSG = MESSAGE_HEADER + data + [____pad_end_number(1-64)]
							uint32_t padding = (uint32_t)dout.buffer.getdata()[dout.buffer.size() - 1];
							dout.buffer.remove_last_n_char(padding);

							ss << "un padding: " << padding << std::endl;
                            main_global::log(ss.str(), log);
                            ss.str({});

							// original header
							uint8_t digestkey[32];
							memcpy(&digestkey[0], buffer + NETW_MSG::MESSAGE_KEYDIGEST_START, 32);

							uint8_t chk[4];
							memcpy(&chk[0], buffer + NETW_MSG::MESSAGE_CRC_START, 4);
							uint32_t crc = NETW_MSG::MSG::byteToUInt4((char*)buffer + NETW_MSG::MESSAGE_CRC_START);

							msgout.make_msg_with_crc_and_flag_buffer(
								buffer[0], dout.buffer.size(), (uint8_t*)dout.buffer.getdata(), digestkey, crc, 0, from_user, to_user);

							if (SELF_TEST)
							{
								{
									ss << "SELF TEST of decryption encryption" << std::endl;
									ss << "          msgin.size=" << buffer_len << std::endl;
									main_global::log(ss.str(), log);
									ss.str({});
								}

								NETW_MSG::MSG msgout2;
								r = crypto_encrypt(from_user, to_user, msgout, msgout2);
								if (r == false)
								{
									ss << "ERROR crypto_encrypt - TEST of decryption encryption FAILED" << std::endl;
									main_global::log(ss.str(), log);
									ss.str({});
									return false;
								}
								else
								{
									if (buffer_len != msgout2.buffer_len)
									{
										ss << "ERROR crypto_encrypt - TEST of decryption encryption FAILED" << std::endl;
										main_global::log(ss.str(), log);
										ss.str({});
										return false;
									}
									else if (memcmp(buffer + NETW_MSG::MESSAGE_HEADER, msgout2.buffer + NETW_MSG::MESSAGE_HEADER, msgout2.buffer_len - NETW_MSG::MESSAGE_HEADER) != 0)
									{
										ss << "ERROR crypto_encrypt - TEST of decryption encryption FAILED" << std::endl;
										main_global::log(ss.str(), log);
										ss.str({});
										return false;
									}
								}

								{
									ss << "SELF TEST of decryption encryption OK" << std::endl;
									ss << "          msgout.size=" << msgout2.buffer_len << std::endl;
									main_global::log(ss.str(), log);
									ss.str({});
								}
							}

							main_global::log(ss.str(), log);
							ss.str({});
                            return true;
						}
						else
						{
						    {
                                ss << "WARNING crypto_decrypt - invalid file "
                                << user_folder + map_active_user_to_crypto_cfg[from_user].filename_decrypted_data<<std::endl;
                            }
						}
					}
					else
                    {
                        {
                            ss << "WARNING crypto_decrypt - decryptor->decrypt() failed" << std::endl;
                        }
                    }
				}
			}
			else
            {
                ss << "WARNING crypto_decrypt - no (map_active_user_to_crypto_cfg.contains(from_user) && map_active_user_to_urls.contains(from_user))" << std::endl;
            }
		}
		main_global::log(ss.str(), log);
		ss.str({});
		return r;
	}
