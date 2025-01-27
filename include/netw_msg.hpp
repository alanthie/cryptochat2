#ifndef NETWMSG_H
#define NETWMSG_H

#include <cstring>
#include <stdexcept>
#include <string>
#include "../include/base_const.hpp"
#include "encrypt.h"
#include "random_engine.hpp"
#include "SHA256.h"
#include "IDEA.hpp"
#include "../include/string_util.hpp"


namespace NETW_MSG
{
const int MESSAGE_SIZE = 4 * 1024;
const int MESSAGE_FACTOR = 64;

// MSG = MESSAGE_HEADER + data
const int MESSAGE_HEADER = 1+4+32+20+1+4+2 + 4+4+56; // 64 bytes + 8 (from, to) + 56 = 128
const int MESSAGE_MSGTYPE_START = 0;
const int MESSAGE_LEN_START = MESSAGE_MSGTYPE_START + 1;
const int MESSAGE_KEYDIGEST_START = MESSAGE_LEN_START + 4;
const int MESSAGE_SIGNATURE_START = MESSAGE_KEYDIGEST_START + 32;
const int MESSAGE_FLAG_START = MESSAGE_SIGNATURE_START + 20; // flag == 0 if no extra crypto encoding
const int MESSAGE_CRC_START = MESSAGE_FLAG_START + 1;
const int MESSAGE_MISC_START = MESSAGE_CRC_START + 4;
const int MESSAGE_MISC_END = MESSAGE_MISC_START + 2;
const int MESSAGE_FROM_START = MESSAGE_MISC_END + 1; // from_user
const int MESSAGE_TO_START = MESSAGE_FROM_START + 4; // to_user

const char MESSAGE_SIGNATURE[20+1] = "12345678901234567890";
const char MESSAGE_LAST[7 + 1]{0}; // reset last 7 bytes of first 64 bytes in header

// We can reduce the base chat encryption key (symmetrical) size
// since EXTRA CRYPTO keys (asymmetrical) are available on demand.
// The private asymetrical key part is NEVER transfered on the network.
//
// Note that the base chat encryption key is random and CHANGING at EVERY MESSAGE and at EVERY CLIENT
// At least 3 different encryptions are sequentially performed with the base chat key
// TWO different base chat random encryption key are involved when a message transit from a user to another one
// So, this add up to at least 6 base encryptions for every message
// new_client->pending_random_key = cryptoAL::random::generate_base64_random_string(NETW_MSG::KEY_SIZE);

// KEY_SIZE (bytes) is a multiple of 64 to support all encryption algos
const int KEY_SIZE = 1 * 512; // the key is encrypt and may grow 2x in size

const std::string DEFAULT_USERNAME = "user";

struct encdec_stat
{
    size_t msg_in_count = 0;
    size_t msg_in_len = 0;

    // BASE CHAT ENCRYPTION
    size_t vigenere_key_len = 0;
    size_t idea_key_len = 0;
    size_t salsa20_key_len = 0;

    // EXTRA CRYPTO ENCRYPTION
    size_t msg2_in_count = 0;
    size_t msg2_in_len = 0;
    size_t msg2_out_len = 0;

    size_t embedded_rsa_ecc_key_len = 0;
    size_t rsa_ecc_key_count= 0;
    size_t rsa_ecc_key_len = 0;
    size_t other_key_count= 0;
    size_t other_key_len = 0;

    size_t ALGO_BIN_DES = 0;
    size_t ALGO_BIN_AES256 = 0;
    size_t ALGO_TWOFISH = 0;
    size_t ALGO_Salsa20 = 0;
    size_t ALGO_IDEA = 0;
	size_t ALGO_wbaes = 0;
};

// For msg history in UIf
struct netw_msg
{
	bool is_receive;
	bool crypto_on;
	uint32_t from_user;
	uint32_t to_user;
	uint8_t msg_type;
	std::string msg;        // ONE LINE
	std::string filename;	// MSG_FILE
	std::string filename_key; // in map
	std::string filename_mediaviewer; // in mediaviewer
	bool is_for_display;	// MSG_FILE display or disk saving
	std::vector<std::string> vmsg_extra;   // From MSG_FILE (for display)
};

const uint8_t MSG_EMPTY = 0;
const uint8_t MSG_INVALID = 1;
const uint8_t MSG_TEXT = 2;
const uint8_t MSG_FILE = 3;
const uint8_t MSG_CMD_REQU_KEY_HINT = 4;
const uint8_t MSG_CMD_RESP_KEY_HINT = 5;
const uint8_t MSG_CMD_INFO_KEY_VALID = 6;
const uint8_t MSG_CMD_INFO_KEY_INVALID = 7;

const uint8_t MSG_CMD_REQU_ACCEPT_RND_KEY = 10;
const uint8_t MSG_CMD_RESP_ACCEPT_RND_KEY = 11;
const uint8_t MSG_CMD_INFO_RND_KEY_VALID = 12;

const uint8_t MSG_CMD_REQU_USERNAME = 20;
const uint8_t MSG_CMD_RESP_USERNAME = 21;
const uint8_t MSG_CMD_ACCEPT_USERNAME = 22;

const uint8_t MSG_CMD_REQU_HOSTNAME = 32;
const uint8_t MSG_CMD_RESP_HOSTNAME = 33;
const uint8_t MSG_CMD_REQU_MACHINEID = 34;
const uint8_t MSG_CMD_RESP_MACHINEID = 35;
const uint8_t MSG_CMD_INFO_USERLIST = 36;
const uint8_t MSG_CMD_INFO_USERINDEX = 37;

const uint8_t MSG_FILE_FRAGMENT = 41;
const uint8_t MSG_CMD_REQU_SHUTDOWN = 51;
const uint8_t MSG_CMD_RESP_SHUTDOWN  = 52;

const uint8_t MSG_FIRST = 200;
const uint8_t MSG_VALIDATION = 201;

struct MSG_FILE_FRAGMENT_HEADER
{
	std::string filename;
	std::string filename_key;
	std::string total_size;
	std::string from;
	std::string to;

	size_t data_from;
	size_t data_to;

	bool is_processed = false; // false not processed

	size_t header_size()
	{
		return make_header().size();
	}
	std::string make_header()
	{
		return "[" + filename + "," + filename_key + "," + total_size + "," + from + "," + to + "]";
	}

	size_t get_pos_delimiter(size_t pos_start, const std::string& data, char delim)
	{
		for (size_t p = pos_start; p < data.size(); p++)
		{
			if (data[p] == delim) return p;
		}
		return 0;
	}

	std::string get_substr(size_t pos_start, size_t pos_end, const std::string& data)
	{
		return data.substr(pos_start, pos_end - pos_start + 1);
	}

	bool parse_header(const std::string& data)
	{
		size_t sz = header_size();
		if (data.size() < sz)
			return false;
		size_t pos_file = 1;
		size_t pos_file_key = 1 + get_pos_delimiter(pos_file, data, ',');
		size_t pos_total_size = 1 + get_pos_delimiter(pos_file_key, data, ',');
		size_t pos_from = 1 + get_pos_delimiter(pos_total_size, data, ',');
		size_t pos_to = 1 + get_pos_delimiter(pos_from, data, ',');
		size_t end_bracket = 0 + get_pos_delimiter(pos_to, data, ']');

		filename = get_substr(pos_file, pos_file_key - 2, data);
		filename_key = get_substr(pos_file_key, pos_total_size - 2, data);
		total_size = get_substr(pos_total_size, pos_from - 2, data);
		from = get_substr(pos_from, pos_to - 2, data);
		to = get_substr(pos_to, end_bracket - 1, data);

		return true;
	}

	static bool make_fragments(const std::string& filename, const std::string& filename_key, std::vector<MSG_FILE_FRAGMENT_HEADER>& vout)
	{
		bool r = false;
		cryptoAL::cryptodata file;
		r = file.read_from_file(filename);
		if (r == false)
			return r;

		size_t total_size = file.buffer.size();

		MSG_FILE_FRAGMENT_HEADER h;
		h.filename = filename;
		h.filename_key = filename_key;
		h.total_size = std::to_string(total_size);
		h.from = std::to_string(0);
		h.to = std::to_string(total_size - 1);
		std::string header = h.make_header();

		// Allow for encryption doubling of size....
		size_t fragment_data_size = ( (NETW_MSG::MESSAGE_SIZE/3) - (MESSAGE_HEADER + header.size()) );
		size_t number_fragments = 1 + total_size / fragment_data_size;

		size_t data_count = 0;
		size_t to;
		for (size_t i = 0; i < number_fragments; i++)
		{
			if (data_count < total_size)
			{
				MSG_FILE_FRAGMENT_HEADER h;
				h.filename = filename;
				h.filename_key = filename_key;
				h.total_size = std::to_string(total_size);
				h.from = std::to_string(data_count);

				if (data_count + fragment_data_size - 1 < total_size)
				{
					to = data_count + fragment_data_size - 1;
					h.to = std::to_string(to);
				}
				else
				{
					to = total_size - 1;
					h.to = std::to_string(to);
				}

				if (to >= data_count)
				{
					std::string header = h.make_header();
					h.data_from = data_count;
					h.data_to = to;
					vout.push_back(h);
				}
				data_count += fragment_data_size;
			}
		}
		return r;
	}
};


struct MSG_BINFILE
{
	~MSG_BINFILE()
	{
		if (_file != nullptr)
			delete _file;
	}

	void init(const std::string& filename, const std::string& filename_key, bool to_send)
	{
		if (_file != nullptr)
		{
			delete _file;
			_file = nullptr;
		}

		_to_send = to_send;
		_filename = filename;
		_filename_key = filename_key;
		_file = new cryptoAL::cryptodata();

		if (to_send)
		{
			bool r = _file->read_from_file(filename);
			if (r) r = MSG_FILE_FRAGMENT_HEADER::make_fragments(filename, filename_key, _vfragments);

			if (r) _is_valid = true;
			else  _is_valid = false;
		}
		else
		{
			_is_valid = true;
		}
	}

	size_t data_size_in_fragments()
	{
		size_t n = 0;
		for (size_t i = 0; i < _vfragments.size(); i++)
		{
			n += 1 + _vfragments[i].data_to - _vfragments[i].data_from;
		}
		return n;
	}

	bool _is_valid              = false;
	bool _is_processing_done    = false;
	std::string _filename;
	std::string _filename_key;
	std::string _filename_mediaviewer; // in mediaviewer

	cryptoAL::cryptodata* _file = nullptr; // allow =()
	bool _to_send; // recv or send
	std::vector<MSG_FILE_FRAGMENT_HEADER> _vfragments;

	size_t total_size_read_from_fragment = 0;

	size_t byte_send = 0;
	size_t byte_recv = 0;

	bool has_unprocess_fragment()
	{
		for (size_t i = 0; i < _vfragments.size(); i++)
		{
			if (_vfragments[i].is_processed == false)
				return true;
		}
		return false;
	}

	size_t next_fragment_index_to_process()
	{
		for (size_t i = 0; i < _vfragments.size(); i++)
		{
			if (_vfragments[i].is_processed == false)
				return i;
		}
		return 0;
	}

	void set_fragment_processed(size_t idx, size_t sz_data)
	{
		if (idx >= _vfragments.size())
			return;

		_vfragments[idx].is_processed = true;
		if (_to_send)
		{
			byte_send += sz_data;
			if (byte_send >= data_size_in_fragments())
				_is_processing_done = true;
		}
		else
		{
			byte_recv += sz_data;
			if (byte_recv >= total_size_read_from_fragment)
				_is_processing_done = true;
		}
	}

	bool add_recv_fragment_data(MSG_FILE_FRAGMENT_HEADER& h, uint8_t* data, uint32_t data_len, size_t& idx_fragment)
	{
        // TODO serr..

		long long total_size = str_to_ll(h.total_size);
		long long pos_from = str_to_ll(h.from);
		long long pos_end  = str_to_ll(h.to);
		if (total_size == -1) return false;
		if (pos_from == -1) return false;
		if (pos_end == -1) return false;
		if (pos_from > pos_end) return false;
		if (pos_from > total_size) return false;
		if (pos_end > total_size) return false;
		if (pos_from + data_len > total_size) return false;

		if (_file == nullptr)
		{
            //...
            return false;
		}

		if (_file->buffer.size() < total_size)
			_file->buffer.increase_size((uint32_t)total_size);

		total_size_read_from_fragment = total_size;

		_vfragments.push_back(h);
		idx_fragment = _vfragments.size() - 1;

		// void write(const char* buffer, uint32_t len, int32_t offset = -1)
		_file->buffer.write( (char*)data, data_len, (int32_t)pos_from);
		return true;
	}
};

struct MSG
{
	// HEADER + data
	uint8_t	type_msg = MSG_EMPTY;
	uint32_t buffer_len = 0;
	uint8_t* buffer = nullptr;

	size_t size();
	uint8_t* get_buffer();

	void reset()
	{
		if (buffer != nullptr) delete buffer;
		buffer = nullptr;
		buffer_len = 0;
	}

	std::string get_data_as_string();
	bool is_same(MSG& msgin);

	bool make_encrypt_msg(MSG& msgin, const std::string& key, uint8_t crypto_flag, uint32_t from_user, uint32_t to_user, std::stringstream& serr);
	bool make_decrypt_msg(MSG& msgin, const std::string& key, uint32_t& crc, std::stringstream& serr);

	void make_msg(uint8_t t, const std::string& s, const std::string& key);
	void make_msg(uint8_t t, uint32_t len_data, uint8_t* data, uint8_t* digestkey);

	void make_msg_with_crc_and_flag(uint8_t t, const std::string& s, uint8_t* digestkey, uint32_t crc, uint8_t flag, uint32_t from_user, uint32_t to_user);
	void make_msg_with_crc_and_flag_buffer(	uint8_t t, uint32_t len_data, uint8_t* data,
											uint8_t* digestkey, uint32_t crc, uint8_t flag, uint32_t from_user, uint32_t to_user);

	void make_msg(uint8_t* buffer_in, size_t len);
	void make_msg(uint8_t t, const std::string& s, uint8_t* digestkey);
	bool parse(char* message_buffer, size_t len, std::string key, std::stringstream& serr, std::string previous_key = {}, std::string pending_key = {});

	void make_with_padding(MSG& m);
	void make_removing_padding(MSG& m);

	static std::string add_padding(const std::string& sin);
	static std::string remove_padding(const std::string& sin);

	static std::string make_key_64(const std::string& keyin, const std::string& extend);

	~MSG();

	MSG()
	{
	  type_msg = MSG_EMPTY;
	  buffer_len = 0;
	  buffer = nullptr;
	}

	MSG(const NETW_MSG::MSG& other)
	{
	  if (this != &other)
	  {
	    if (buffer != nullptr)
              delete []buffer;
            buffer = nullptr;

	    type_msg  = other.type_msg ;
	    buffer_len = other.buffer_len;
	    if (other.buffer_len > 0)
            {
              buffer = new uint8_t[other.buffer_len]{ 0 };
              memcpy(buffer, other.buffer, other.buffer_len);
            }
	  }
	}

	// move copy ct
	MSG(MSG&& other): type_msg{ other.type_msg },
					  buffer_len{ other.buffer_len }
	{
	  buffer = other.buffer; // stealing
	}

	static void uint4ToByte(uint32_t k, char buff[])
	{
		//memcpy(buff, &k, 4);
		buff[0] = (char)(k & 0x000000ff);
		buff[1] = (char)((k & 0x0000ff00) >> 8);
		buff[2] = (char)((k & 0x00ff0000) >> 16);
		buff[3] = (char)((k & 0xff000000) >> 24);
	}
	static uint32_t byteToUInt4(char buff[])
	{
		return   ((uint32_t)(unsigned char)buff[3] << 24)
			| ((uint32_t)(unsigned char)buff[2] << 16)
			| ((uint32_t)(unsigned char)buff[1] << 8)
			| (uint32_t)(unsigned char)buff[0];
	}

	static bool parse_file_fragment_header_from_msg(MSG& msgin, MSG_FILE_FRAGMENT_HEADER& header_out)
	{
        // TODO serr..

		//"[" + filename + "," + filename_key + "," + total_size + "," + from + "," + to + "]";
		if (msgin.buffer_len <= MESSAGE_HEADER) return false;
		uint8_t* data = msgin.buffer+ MESSAGE_HEADER;
		if (data[0]!='[') return false;

		size_t pos_start_filename = 1;
		size_t pos_end_filename = 0;
		for (size_t i = pos_start_filename; i < msgin.buffer_len; i++)
		{
			if (data[i] == ',')
			{
				pos_end_filename = i - 1;
				break;
			}
		}
		if (pos_end_filename == 0) return false;

		size_t pos_start_filename_key = pos_end_filename + 2;
		size_t pos_end_filename_key = 0;
		for (size_t i = pos_start_filename_key; i < msgin.buffer_len; i++)
		{
			if (data[i] == ',')
			{
				pos_end_filename_key = i - 1;
				break;
			}
		}
		if (pos_end_filename_key == 0) return false;

		size_t pos_start_total_size = pos_end_filename_key + 2;
		size_t pos_end_total_size = 0;
		for (size_t i = pos_start_total_size; i < msgin.buffer_len; i++)
		{
			if (data[i] == ',')
			{
				pos_end_total_size = i-1;
				break;
			}
		}
		if (pos_end_total_size == 0) return false;

		size_t pos_start_from = pos_end_total_size + 2;
		size_t pos_end_from = 0;
		for (size_t i = pos_start_from; i < msgin.buffer_len; i++)
		{
			if (data[i] == ',')
			{
				pos_end_from = i - 1;
				break;
			}
		}
		if (pos_end_from == 0) return false;

		size_t pos_start_to = pos_end_from + 2;
		size_t pos_end_to = 0;
		for (size_t i = pos_start_to; i < msgin.buffer_len; i++)
		{
			if (data[i] == ']')
			{
				pos_end_to = i - 1;
				break;
			}
		}
		if (pos_end_to == 0) return false;

		size_t header_size = pos_end_to+1;
		if (header_out.parse_header(std::string((char*) & data[0], header_size)) == false)
			return false;

		return true;
	}

	bool make_next_file_fragment_to_send(MSG_BINFILE& binfile,const std::string& key, bool mark_fragment_as_process)
	{
        // TODO serr..

		if (binfile._is_valid == false) return false;
		if (binfile._to_send == false) return false;

		if (binfile.has_unprocess_fragment())
		{
			if (binfile._file == nullptr)
				return false;

			size_t idx = binfile.next_fragment_index_to_process();
			MSG_FILE_FRAGMENT_HEADER packet = binfile._vfragments[idx];
			std::string header_fragm = packet.make_header();

			SHA256 sha;
			sha.update((uint8_t*)key.data(), key.size());
			uint8_t* digestkey = sha.digest();

			cryptoAL::cryptodata data_temp;
			data_temp.buffer.write(header_fragm.data(), (uint32_t)header_fragm.size());
			data_temp.buffer.write(binfile._file->buffer.getdata()+packet.data_from, (uint32_t)(packet.data_to - packet.data_from + 1));

			make_msg(MSG_FILE_FRAGMENT, data_temp.buffer.size(), (uint8_t*)data_temp.buffer.getdata(), digestkey);
			delete[]digestkey;

			if (mark_fragment_as_process)
			{
				binfile.set_fragment_processed(idx, packet.data_to - packet.data_from + 1);
			}

			return true;
		}
		else
		{
			return false;
		}
	}
};

}

#endif
