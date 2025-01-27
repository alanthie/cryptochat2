#ifndef _INCLUDES_decryptor
#define _INCLUDES_decryptor

#include "crypto_const.hpp"
#include "file_util.hpp"
#include "ecc_util.hpp"
#include <iostream>
#include <fstream>
#include "DES.h"
#include "AESa.h"
#include "Buffer.hpp"
#include "SHA256.h"
#include "crypto_file.hpp"
#include "data.hpp"
#include "puzzle.hpp"
#include "IDEA.hpp"
#include "crc32a.hpp"
#include "crypto_shuffle.hpp"
#include "crypto_history.hpp"
#include "crypto_cfg.hpp"
#include "crypto_png.hpp"
#include "qa/aes-whitebox/aes_whitebox.hpp"
#include "qa/menu/menu.h"
#include "qa/SystemProperties.hpp"
#include "crypto_dbmgr.hpp"
#include "hhkey_util.hpp"

namespace cryptoAL
{

class decryptor
{
const size_t NDISPLAY = 32;

friend class crypto_package;
private:
    decryptor() : cfg("") , dbmgr(cfg) {}

public:

	decryptor(  std::string ifilename_cfg,
				std::string ifilename_puzzle,
                std::string ifilename_encrypted_data,
			 	std::string ifilename_decrypted_data,
			 	std::string istaging,
			 	std::string ifolder_local,
                std::string ifolder_my_private_rsa,
				std::string ifolder_other_public_rsa,
				std::string ifolder_my_private_ecc,
                std::string ifolder_other_public_ecc,
			 	std::string ifolder_my_private_hh,
			 	std::string ifolder_other_public_hh,
                std::string iwbaes_my_private_path,
                std::string iwbaes_other_public_path,
			 	bool verb = false,
			 	bool keep = false,
                std::string iencryped_ftp_user = "",
                std::string iencryped_ftp_pwd  = "",
                std::string iknown_ftp_server  = "",
                bool iuse_gmp = false,
                bool autoflag = false,
				bool icheck_converter = false)
        : cfg(ifilename_cfg, false), dbmgr(cfg)
	{
		filename_cfg = ifilename_cfg;
        filename_puzzle = ifilename_puzzle;
        filename_encrypted_data = ifilename_encrypted_data;
        filename_decrypted_data = ifilename_decrypted_data;

        staging =istaging;
        folder_local = ifolder_local;
        folder_my_private_rsa = ifolder_my_private_rsa;
		folder_other_public_rsa = ifolder_other_public_rsa;
        folder_my_private_ecc = ifolder_my_private_ecc;
        folder_other_public_ecc  = ifolder_other_public_ecc;
        folder_my_private_hh = ifolder_my_private_hh;
        folder_other_public_hh = ifolder_other_public_hh;
        wbaes_my_private_path = iwbaes_my_private_path;
        wbaes_other_public_path = iwbaes_other_public_path;

        verbose = verb;
        keeping = keep;

        encryped_ftp_user = iencryped_ftp_user;
        encryped_ftp_pwd  = iencryped_ftp_pwd;
        known_ftp_server  = iknown_ftp_server;

        use_gmp     = iuse_gmp;
        auto_flag   = autoflag;
		use_gmp     = iuse_gmp;
		check_converter = icheck_converter;

		puz.verbose = verb;

        if (filename_cfg.size() > 0)
        {
            cfg_parse_result = cfg.parse();
            if (cfg_parse_result)
            {
                process_cfg_param();

				cfg.get_active_algos(vAlgo);
				if (vAlgo.size() > 0)
				{
					has_cfg_algo=true;
				}
            }
        }

		if (staging.size()==0)
        {
            staging ="./";
        }

        if (filename_decrypted_data.size() == 0)
        {
            if (filename_encrypted_data.size() > 0)
            {
                filename_decrypted_data = filename_encrypted_data + ".decrypted";
            }
            else
            {
                // ?
            }
        }

//        if (verbose)
//            show_param();

	}
    ~decryptor()
    {
    }

	void show_param()
	{
		std::cout << "-------------------------------------------------" << std::endl;
		std::cout << "Parameters:" << std::endl;
		std::cout << "-------------------------------------------------" << std::endl;
        std::cout << "filename_puzzle:         " << filename_puzzle << std::endl;
        std::cout << "filename_encrypted_data: " << filename_encrypted_data << std::endl;
        std::cout << "filename_decrypted_data: " << filename_decrypted_data << std::endl;

        std::cout << "staging:                 " << staging << std::endl;
        std::cout << "folder_local:            " << folder_local << std::endl;
        std::cout << "folder_my_private_rsa:   " << folder_my_private_rsa << std::endl;
        std::cout << "folder_other_public_rsa: " << folder_other_public_rsa << std::endl;
        std::cout << "folder_my_private_ecc:   " << folder_my_private_ecc << std::endl;
        std::cout << "folder_other_public_ecc: " << folder_other_public_ecc << std::endl;
        std::cout << "folder_my_private_hh:    " << folder_my_private_hh << std::endl;
        std::cout << "folder_other_public_hh:  " << folder_other_public_hh << std::endl;
		std::cout << "wbaes_my_private_path:    " << wbaes_my_private_path << std::endl;
        std::cout << "wbaes_other_public_path:  " << wbaes_other_public_path << std::endl;

        std::cout << "keeping:   " << keeping << std::endl;
        std::cout << "use_gmp:   " << use_gmp << std::endl;
        std::cout << "auto_flag: " << auto_flag << std::endl;
		std::cout << "check_converter (png): " << check_converter << std::endl;
		std::cout << "verbose:   " << verbose << std::endl;
        std::cout << "-------------------------------------------------" << std::endl<< std::endl;
	}

	void process_cfg_param()
	{
		if (filename_puzzle.size() == 0) 		    filename_puzzle 	= cfg.cmdparam.filename_puzzle;
		if (filename_encrypted_data.size() == 0)    filename_encrypted_data = cfg.cmdparam.filename_encrypted_data;
		if (filename_decrypted_data.size() == 0)    filename_decrypted_data = cfg.cmdparam.filename_decrypted_data;

		if (staging.size() == 0) 					staging 				= cfg.cmdparam.folder_staging;
		if (folder_local.size() == 0) 				folder_local 			= cfg.cmdparam.folder_local;
		if (folder_my_private_rsa.size() == 0) 		folder_my_private_rsa 	= cfg.cmdparam.folder_my_private_rsa;
		if (folder_other_public_rsa.size() == 0)	folder_other_public_rsa = cfg.cmdparam.folder_other_public_rsa;
		if (folder_my_private_ecc.size() == 0) 		folder_my_private_ecc 	= cfg.cmdparam.folder_my_private_ecc;
		if (folder_other_public_ecc.size() == 0)	folder_other_public_ecc = cfg.cmdparam.folder_other_public_ecc;
		if (folder_my_private_hh.size() == 0)		folder_my_private_hh 	= cfg.cmdparam.folder_my_private_hh;
		if (folder_other_public_hh.size() == 0)		folder_other_public_hh 	= cfg.cmdparam.folder_other_public_hh;
		if (wbaes_my_private_path.size() == 0)		wbaes_my_private_path 	= cfg.cmdparam.wbaes_my_private_path;
		if (wbaes_other_public_path.size() == 0)	wbaes_other_public_path = cfg.cmdparam.wbaes_other_public_path;

		if (verbose == false) 					if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.verbose) == 1) verbose = true;
		if (keeping == false) 					if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.keeping) == 1) keeping = true;
		if (use_gmp == false) 					if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.use_gmp) == 1) use_gmp = true;
		if (auto_flag == false) 				if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.auto_flag) == 1) auto_flag = true;
		if (check_converter == false) 			if (cfg.get_positive_value_negative_if_invalid(cfg.cmdparam.check_converter) == 1) check_converter = true;
	}

    bool read_urlinfo(std::stringstream& serr, Buffer& temp, urlkey& out_uk)
	{
		bool r = true;
        uint32_t pos = 0;

        out_uk.crypto_algo = temp.readUInt16(pos); pos+=2;
		if ((out_uk.crypto_algo < 1) || (out_uk.crypto_algo >= (uint16_t)CRYPTO_ALGO::ALGO_LIMIT_MARKER))
        {
            serr << "ERROR wrong algo in url info "  << out_uk.crypto_algo << std::endl;
            r = false;
            return r;
        }

		out_uk.url_size = temp.readUInt16(pos); pos+=2;
		if (out_uk.url_size  > URL_MAX_SIZE)
		{
            serr << "ERROR wrong url size in url info "  << out_uk.url_size  << std::endl;
            r = false;
            return r;
		}

		for( uint32_t j = 0; j< out_uk.url_size; j++) out_uk.url[j] = temp.getdata()[pos+j];
		if (out_uk.url_size < URL_MAX_SIZE) out_uk.url[out_uk.url_size] = 0; // rsa??
		else out_uk.url[URL_MAX_SIZE - 1] = 0;

        if (VERBOSE_DEBUG)
		{
            std::string s(out_uk.url);
            if ((s.size() >= 3) && (s[0]=='[') && (s[1]=='r') && (s[2]==']'))
                std::cout << "url: [r]" << file_util::get_summary_hex(s.data()+3, (uint32_t) s.size()-3) << " "<< std::endl;
            else if ((s.size() >= 3) && (s[0]=='[') && (s[1]=='e') && (s[2]==']'))
                std::cout << "url: [r]" << file_util::get_summary_hex(s.data()+3, (uint32_t) s.size()-3) << " "<< std::endl;
            else
                std::cout << "url: " << s << " "<< std::endl;
        }

        for( uint32_t j = out_uk.url_size; j< URL_MAX_SIZE; j++) out_uk.url[j] = 0; // padding
        pos += URL_MAX_SIZE;

        for( uint32_t j = 0; j< 4; j++)
        {
            out_uk.magic[j] = temp.getdata()[pos+j];
        }
        if ((out_uk.magic[0]!= 'a') ||(out_uk.magic[1]!= 'b') ||(out_uk.magic[2]!= 'c') ||(out_uk.magic[3]!= 'd') )
        {
            serr << "ERROR wrong magic number in url info" << std::endl;
            r = false;
            return r;
        }
        pos += 4;

		out_uk.key_fromH = temp.readUInt16(pos); pos+=2;
		out_uk.key_fromL = temp.readUInt16(pos); pos+=2;
		out_uk.key_size  = temp.readUInt32(pos); pos+=4;

		int32_t v = out_uk.key_fromH * BASE + out_uk.key_fromL;

		if (VERBOSE_DEBUG)
		{
            std::cout << "key from: " << v << " ";
            std::cout << "key size: " << out_uk.key_size << std::endl;
        }

        // zero
        bool is_rsa =  false;
        bool is_ecc =  false;
        if (out_uk.url[0]=='[')
        {
            if (out_uk.url[1]=='r')
            {
                is_rsa = true;
            }
            else if (out_uk.url[1]=='e')
            {
                is_ecc = true;
            }
        }

        if ((is_rsa == false) && (is_ecc == false))
        {
            for( uint32_t j = 0; j< MIN_KEY_SIZE; j++) out_uk.key[j] = 0;
        }
        else
        {
            // NOT USE...
            for( uint32_t j = 0; j< MIN_KEY_SIZE; j++) out_uk.key[j] = temp.getdata()[pos+j];
            out_uk.key[MIN_KEY_SIZE - 1] = 0;
        }
        pos += MIN_KEY_SIZE;

		for( uint32_t j = 0; j< CHKSUM_SIZE; j++)
		{
            out_uk.checksum[j] = temp.getdata()[pos+j];
        }
        pos += CHKSUM_SIZE;

		for( uint32_t j = 0; j< CHKSUM_SIZE; j++)
		{
            out_uk.checksum_data[j] = temp.getdata()[pos+j];
        }
        pos += CHKSUM_SIZE;

		if ((is_rsa == true) || (is_ecc == true))
		{
			out_uk.rsa_ecc_encoded_data_pad = temp.readUInt32(pos); pos+=4;
			out_uk.rsa_ecc_encoded_data_len = temp.readUInt32(pos); pos+=4;
			out_uk.rsa_ecc_encoded_data_pos = temp.readUInt32(pos); pos+=4;
		}
		else
		{
			out_uk.rsa_ecc_encoded_data_pad = 0; pos+=4;
			out_uk.rsa_ecc_encoded_data_len = 0; pos+=4;
			out_uk.rsa_ecc_encoded_data_pos = 0; pos+=4;
		}

		out_uk.crypto_flags = temp.readUInt32(pos); pos+=4;
		out_uk.shuffle_perc = temp.readUInt32(pos); pos+=4;

		return r;
	}

	bool get_key(std::stringstream& serr, urlkey& uk)
	{
		bool r = true;

        if(std::filesystem::is_directory(staging)==false)
        {
            serr << "ERROR staging is not a folder " << staging << std::endl;
            return false;
        }

        std::string file = staging + "decode_staging_url_file_" + std::to_string(staging_cnt) + ".dat";
        staging_cnt++;

        if (file_util::fileexists(file))
		    std::remove(file.data());

        if ( (uk.url_size < URL_MIN_SIZE) || (uk.url_size > URL_MAX_SIZE))
        {
            serr << "ERROR " << "invalid web url size " << uk.url_size << std::endl;
            r = false;
        }

		// DOWNLOAD URL FILE
		cryptodata dataout_local;
        cryptodata dataout_other;
        cryptodata rsa_key_data;
        cryptodata ecc_key_data;
        cryptodata histo_key_data;

        std::string embedded_rsa_key;
        std::string embedded_ecc_key;

		history_key history_key_out;
        std::string shisto_key; // 3 SHA
		uint32_t histo_keyseq = 0;

		char u[URL_MAX_SIZE] = {0};

        bool is_video =  false;
        bool is_ftp   =  false;
        bool is_local =  false;
        bool is_rsa   =  false;
        bool is_ecc   =  false;
        bool is_histo =  false;
		bool is_web	  =  false;
		bool is_wbaes512 = false;
		bool is_wbaes1024 = false;
		bool is_wbaes2048 = false;
		bool is_wbaes4096 = false;
		bool is_wbaes8192 = false;
		bool is_wbaes16384 = false;
		bool is_wbaes32768 = false;

		if (r)
		{
            for( uint32_t j = 0; j< URL_MAX_SIZE; j++) u[j] = uk.url[j];

            if (u[0]=='[')
            {
                if (u[1]=='v')
                {
                    is_video = true;
                }
                else if (u[1]=='f')
                {
                    is_ftp = true;
                }
                else if (u[1]=='l')
                {
                    is_local = true;
                }
                else if (u[1]=='r')
                {
                    is_rsa = true;
                }
                else if (u[1]=='e')
                {
                    is_ecc = true;
                }
                else if (u[1]=='h')
                {
                    is_histo = true;
                }
				else if (u[1]=='w')
				{
					is_web = true;
				}
				else if (strutil::has_token(token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes512) ,  std::string(u), 0)) is_wbaes512 = true;
				else if (strutil::has_token(token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes1024),  std::string(u), 0)) is_wbaes1024 = true;
				else if (strutil::has_token(token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes2048),  std::string(u), 0)) is_wbaes2048 = true;
				else if (strutil::has_token(token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes4096),  std::string(u), 0)) is_wbaes4096 = true;
				else if (strutil::has_token(token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes8192),  std::string(u), 0)) is_wbaes8192 = true;
				else if (strutil::has_token(token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes16384),  std::string(u), 0)) is_wbaes16384 = true;
				else if (strutil::has_token(token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes32768),  std::string(u), 0)) is_wbaes32768 = true;
			}

            size_t pos_url = 0;
            if      (is_video)   pos_url = 3;
            else if (is_ftp)     pos_url = 3;
            else if (is_local)   pos_url = 3;
            else if (is_rsa)     pos_url = 3;
            else if (is_ecc)     pos_url = 3;
            else if (is_histo)   pos_url = 3;
			else if (is_web)   	 pos_url = 3;
			else if (is_wbaes512)     pos_url = token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes512).size()+2;
			else if (is_wbaes1024)    pos_url = token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes1024).size()+2;
			else if (is_wbaes2048)    pos_url = token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes2048).size()+2;
			else if (is_wbaes4096)    pos_url = token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes4096).size()+2;
			else if (is_wbaes8192)    pos_url = token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes8192).size()+2;
			else if (is_wbaes16384)   pos_url = token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes16384).size()+2;
			else if (is_wbaes32768)   pos_url = token_wbaes_algo(CRYPTO_ALGO::ALGO_wbaes32768).size()+2;
            int rc = 0;

            if (is_video)
            {
                std::string s(&u[pos_url]);
                serr << "video URL: " << s << std::endl;

                rc = key_file::getvideo(s, file.data(), "", verbose);
            }
            else if (is_local)
            {
                std::string s(&u[pos_url]);
                std::string local_url = folder_local + s;

                rc = key_file::getlocal(local_url.data(), dataout_local, "", verbose);

                if (rc!= 0)
                {
                    serr << "ERROR with get local file, error code: " << rc << " url: " << local_url <<  " file: " << file << std::endl;
                    r = false;
                }
            }
            else if (is_ftp)
            {
                std::string s(&u[pos_url]);
                rc = key_file::getftp(s.data(), file.data(),
                            encryped_ftp_user,
                            encryped_ftp_pwd,
                            known_ftp_server,
                            "", verbose);
                if (rc!= 0)
                {
                    serr << "ERROR with getftp, error code: " << rc << " url: " << s <<  " file: " << file << std::endl;
                    r = false;
                }
            }
			else if ((is_wbaes512) || (is_wbaes1024) || (is_wbaes2048) || (is_wbaes4096) || (is_wbaes8192) || (is_wbaes16384) || (is_wbaes32768))
			{
			}
            else if (is_histo)
            {
                std::string local_histo_db = folder_my_private_hh + HHKEY_MY_PRIVATE_DECODE_DB;

                std::string s(&u[pos_url]);
                std::vector<std::string> v = parsing::split(s, ";");
                if (v.size() < 1)
                {
                    serr << "ERROR histo url bad format - missing histo key name: " << s << std::endl;
                    r = false;
                }
                else
                {
                    if (VERBOSE_DEBUG)
                    {
                        if (v.size() == 1)
                            std::cout << "unique histo key name in URL: " << v[0] << std::endl;
                        else
                            std::cout << "multiple histo key in URL: " << v[0] << " " << v[1] << " ..." << std::endl;
                    }
                }
                if (r)
                {
                    r = cryptoAL::hhkey_util::find_history_key_by_sha(v[0], local_histo_db, history_key_out, histo_keyseq, dbmgr, true);
                    if (r)
                    {
                        shisto_key = history_key_out.data_sha[0]+history_key_out.data_sha[1]+history_key_out.data_sha[2];
                        if (VERBOSE_DEBUG)
                        {
                            std::cout << "histo key: " << shisto_key << " size:" << shisto_key.size() << std::endl;
                            std::cout << "histo key: " << file_util::get_summary_hex(shisto_key.data(), (uint32_t)shisto_key.size()) << " size:" << shisto_key.size() << std::endl;
                        }
                    }
                    else
                    {
                        serr << "ERROR no histo key: " << v[0] << std::endl;
                    }
                }
            }
            else if (is_rsa)
            {
				std::string local_rsa_db = folder_my_private_rsa + RSA_MY_PRIVATE_DB; // decoding

				uk.url[URL_MAX_SIZE-1] = 0;
				//std::string rsa_key = uk.without_header_token(); // ???

				if (uk.rsa_ecc_encoded_data_pad + uk.rsa_ecc_encoded_data_pos + uk.rsa_ecc_encoded_data_len > data_temp.buffer.size())
				{
                    serr << "ERROR invalid data file (too small): " << file << std::endl;
					r = false;
				}
				else
				{
					char c;
					for(size_t j=0;j<uk.rsa_ecc_encoded_data_len;j++)
					{
						c = data_temp.buffer.getdata()[uk.rsa_ecc_encoded_data_pos + uk.rsa_ecc_encoded_data_pad + j];
						uk.sRSA_ECC_ENCODED_DATA += c;
					}

					if(uk.rsa_ecc_encoded_data_len != uk.sRSA_ECC_ENCODED_DATA.size())
					{
                        serr << "ERROR inconsistency reading rsa data: " << uk.sRSA_ECC_ENCODED_DATA.size() << std::endl;
						r = false;
					}
				}

				if (r)
				{
					int pos_url = 3;
        			std::string sURL(&uk.url[pos_url]);

				 	std::vector<std::string> v ;
				 	std::vector<uint32_t> v_encoded_size;

				 	std::vector<std::string> vv = parsing::split(sURL, ";");
					if (vv.size() < 1)
					{
                        serr << "ERROR rsa url bad format - missing rsa key name: " << sURL << std::endl;
						r = false;
					}
					else if (vv.size() == 1)
					{
                        v = vv;
					}
					else
					{
                        if (vv.size() % 2 != 0)
                        {
                            serr << "ERROR parsing url with muiltiple rsa - uneven " << sURL << " " << sURL.size()<< std::endl;
                            r = false;
                        }

                        if (r)
                        {
                            long long N = (long long) vv.size() / 2;
                            for (long long riter = 0; riter< N; riter++)
                            {
                                std::string vt0 = vv[2*riter];
                                std::string vt1 = vv[2*riter + 1];

                                {
                                    v.push_back(vt0);
                                    long long n = parsing::str_to_ll(vt1);
                                    if (n >= 0)
                                    {
                                        v_encoded_size.push_back((uint32_t)n);
                                    }
                                    else
                                    {
                                        serr << "ERROR parsing url with muiltiple rsa -  encoded data len invalid " << vt1 << std::endl;
                                        r = false;
                                        break;
                                    }
                                }
                            }
                        }
					}

					if (r)
					{
						if (VERBOSE_DEBUG)
						{
							if (v.size() == 1)
								std::cout << "unique rsa key name in URL: " << v[0] << std::endl;
							else if (v.size() > 1)
								std::cout << "multiple rsa key in URL: " << v[0] << " " << v[1] << " ..." << std::endl;
						}
					}

					// ITER
					long long N = (long long)v.size();
					for (long long riter = N - 1; riter >= 0; riter--)
					{
                        std::string rsa_key_at_iter = v[riter];
						cryptoAL::rsa::rsa_key krsaout;
						bool r = rsa_util::get_rsa_key(rsa_key_at_iter, local_rsa_db, krsaout);
						if (r)
						{
							dbmgr.add_to_usage_count_rsa(rsa_key_at_iter, local_rsa_db);

							if (riter != 0)
							{
								uint32_t msg_size_produced;
								std::string d = uk.sRSA_ECC_ENCODED_DATA.substr(0, v_encoded_size[riter]);
								//std::string t = rsa_util::rsa_decode_string(d, krsaout, (uint32_t)d.size(), msg_size_produced, use_gmp);
								std::string t = rsa_util::rsa_decode_full_string(d, krsaout, msg_size_produced, use_gmp, false, &serr);

								// may reduce size
								uk.sRSA_ECC_ENCODED_DATA = t + uk.sRSA_ECC_ENCODED_DATA.substr(d.size());

								if (VERBOSE_DEBUG)
								    std::cout << "RSA ITER: " << riter << " " << rsa_key_at_iter << " from " << d.size() << " to " << t.size() << " total left " << uk.sRSA_ECC_ENCODED_DATA.size() << std::endl;
							}
							else
							{
								uint32_t msg_size_produced;
								//embedded_rsa_key = rsa_util::rsa_decode_string(uk.sRSA_ECC_ENCODED_DATA, krsaout, (uint32_t)uk.sRSA_ECC_ENCODED_DATA.size(), msg_size_produced, use_gmp);
								embedded_rsa_key = rsa_util::rsa_decode_full_string(uk.sRSA_ECC_ENCODED_DATA, krsaout, msg_size_produced, use_gmp, false, &serr);
							}
						}
						else
						{
                            serr << "ERROR rsa_key not found: [" << rsa_key_at_iter << "], in: " << local_rsa_db << std::endl;
						}
					}
				}
            }
            else if (is_ecc)
            {
                std::string local_private_ecc_db = folder_my_private_ecc + ECCKEY_MY_PRIVATE_DB; // decoding

				uk.url[URL_MAX_SIZE-1] = 0;
				//std::string ecc_key_in_url = uk.without_header_token(); // ???

				if (uk.rsa_ecc_encoded_data_pad + uk.rsa_ecc_encoded_data_pos + uk.rsa_ecc_encoded_data_len > data_temp.buffer.size())
				{
                    serr << "ERROR invalid data file (too small): " << file << std::endl;
					r = false;
				}
				else
				{
					char c;
					for(size_t j=0;j<uk.rsa_ecc_encoded_data_len;j++)
					{
						c = data_temp.buffer.getdata()[uk.rsa_ecc_encoded_data_pos + uk.rsa_ecc_encoded_data_pad + j];
						uk.sRSA_ECC_ENCODED_DATA += c;
					}

					if(uk.rsa_ecc_encoded_data_len != uk.sRSA_ECC_ENCODED_DATA.size())
					{
                        serr << "ERROR inconsistency reading rsa data: " << uk.sRSA_ECC_ENCODED_DATA.size() << std::endl;
						r = false;
					}
				}

				if (r)
				{
					int pos_url = 3;
        			std::string sURL(&uk.url[pos_url]);

				 	std::vector<std::string> v ;
				 	std::vector<uint32_t> v_encoded_size;

				 	std::vector<std::string> vv = parsing::split(sURL, ";");
					if (vv.size() < 1)
					{
                        serr << "ERROR ecc url bad format - missing ecc key name: " << sURL << std::endl;
						r = false;
					}
					else if (vv.size() == 1)
					{
                        v = vv;
					}
					else
					{
                        if (vv.size() % 2 != 0)
                        {
                            serr << "ERROR parsing url with muiltiple ecc - uneven " << sURL << " " << sURL.size()<< std::endl;
                            r = false;
                        }

                        if (r)
                        {
                            long long N = (long long) vv.size() / 2;
                            for (long long riter = 0; riter< N; riter++)
                            {
                                std::string vt0 = vv[2*riter];
                                std::string vt1 = vv[2*riter + 1];

                                {
                                    v.push_back(vt0);
                                    long long n = parsing::str_to_ll(vt1);
                                    if (n >= 0)
                                    {
                                        v_encoded_size.push_back((uint32_t)n);
                                    }
                                    else
                                    {
                                        serr << "ERROR parsing url with muiltiple ecc -  encoded data len invalid " << vt1 << std::endl;
                                        r = false;
                                        break;
                                    }
                                }
                            }
                        }
					}

					if (r)
					{
						if (VERBOSE_DEBUG)
						{
							if (v.size() == 1)	std::cout << "unique ecc key name in URL: " << v[0] << std::endl;
							else				std::cout << "multiple ecc key in URL: " << v[0] << " " << v[1] << " ..." << std::endl;
						}
					}

					// ITER
					long long N = (long long)v.size();
					for (long long riter = N - 1; riter >= 0; riter--)
					{
                        std::string ecc_key_at_iter = v[riter];
						ecc_key ek_mine;

						bool r = ecc_util::get_ecc_key(ecc_key_at_iter, local_private_ecc_db, ek_mine);
						if (r)
						{
							dbmgr.add_to_usage_count_ecc(ecc_key_at_iter, local_private_ecc_db);

                            if (VERBOSE_DEBUG)
                            {
                                serr << "ecc private key found: " << ecc_key_at_iter << std::endl;
                                serr << "ecc domain: " << ek_mine.dom.name() << std::endl;
                            }

							bool DECODE_FULL=false;
							if (riter != 0)
							{
								std::string d = uk.sRSA_ECC_ENCODED_DATA.substr(0, v_encoded_size[riter]);
                                if (VERBOSE_DEBUG)
                                {
                                    serr << "ecc data to decode: " << d << " size: " << d.size() << std::endl;
                                }

                                uint32_t msg_size_produced;
								std::string t;
								if (DECODE_FULL)
									t = ecc::ecc_decode_full_string(d, ek_mine, msg_size_produced, verbose);
								else
									t = ecc::ecc_decode_string(d, ek_mine, (uint32_t)d.size(), msg_size_produced, verbose);

								if (VERBOSE_DEBUG)
                                {
                                    std::cerr << "ecc data decoded: " << t << " size: " << t.size() << std::endl;
                                }

								uk.sRSA_ECC_ENCODED_DATA = t + uk.sRSA_ECC_ENCODED_DATA.substr(d.size()); // may reduce size
							}
							else
							{
								uint32_t msg_size_produced;
								if (DECODE_FULL)
									embedded_ecc_key = ecc::ecc_decode_full_string(uk.sRSA_ECC_ENCODED_DATA, ek_mine, msg_size_produced, verbose);
								else
									embedded_ecc_key = ecc::ecc_decode_string(uk.sRSA_ECC_ENCODED_DATA, ek_mine, (uint32_t)uk.sRSA_ECC_ENCODED_DATA.size(), msg_size_produced, verbose);

								if (VERBOSE_DEBUG)
                                {
                                    std::cout << "ecc encoded data:        " << uk.sRSA_ECC_ENCODED_DATA << " size: " << uk.sRSA_ECC_ENCODED_DATA.size() << std::endl;
                                    std::cout << "ecc encoded data:        " << file_util::get_summary_hex(uk.sRSA_ECC_ENCODED_DATA.data(), (uint32_t)uk.sRSA_ECC_ENCODED_DATA.size()) << " size:" << uk.sRSA_ECC_ENCODED_DATA.size() << std::endl;
                                    std::cout << "ecc embedded random key: " << embedded_ecc_key << " size: " << embedded_ecc_key.size() << std::endl;
                                    std::cout << "ecc embedded random key: " << file_util::get_summary_hex(embedded_ecc_key.data(), (uint32_t)embedded_ecc_key.size()) << " size:" << embedded_ecc_key.size() << std::endl;
                                    std::cout << "ecc msg_size_produced:   " << msg_size_produced << std::endl;
                                }
							}
						}
						else
						{
                            serr << "ERROR ecc_key not found: " << ecc_key_at_iter << std::endl;
						}
					}
				}
            }
            else if (is_web)
            {
				int pos_url = 3;
				std::string s(&u[pos_url]);
				rc = key_file::wget(s.data(), file.data(), verbose);
				if (rc != 0)
				{
					// TODO - If detach ask local copy of web file...
                    serr << "ERROR " << "unable to read web url contents " << "URL " << s << std::endl;
					r = false;
				}
            }
		}

		if (r)
		{
			cryptodata no_key;
			cryptodata* pointer_datafile;
			if (is_rsa)
            {
                pointer_datafile = &rsa_key_data;
            }
            else if (is_ecc)
            {
                pointer_datafile = &ecc_key_data;
            }
			else if ((is_wbaes512) || (is_wbaes1024) || (is_wbaes2048) || (is_wbaes4096)   || (is_wbaes8192) || (is_wbaes16384) || (is_wbaes32768))
			{
				pointer_datafile = &no_key;
			}
            else if (is_histo)
            {
                pointer_datafile = &histo_key_data;
            }
			else if (is_local == false)
			{
                r = dataout_other.read_from_file(file);
                pointer_datafile = &dataout_other;
            }
            else
            {
                pointer_datafile = &dataout_local;
            }
            cryptodata& d = *pointer_datafile;

			if (r)
			{
				if ((is_wbaes512) || (is_wbaes1024) || (is_wbaes2048) || (is_wbaes4096)  || (is_wbaes8192) || (is_wbaes16384) || (is_wbaes32768))
				{
				}
				else
				{
					if (is_rsa)
					{
						d.buffer.write(embedded_rsa_key.data(), (uint32_t)embedded_rsa_key.size());
					}
					else if (is_ecc)
					{
						d.buffer.write(embedded_ecc_key.data(), (uint32_t)embedded_ecc_key.size());
					}
					else if (is_histo)
					{
						d.buffer.write(shisto_key.data(), (uint32_t)shisto_key.size());
						dbmgr.add_to_usage_count_hh_decode(histo_keyseq, folder_my_private_hh + HHKEY_MY_PRIVATE_DECODE_DB);
					}

					uint32_t pos = (uk.key_fromH * BASE) + uk.key_fromL ;
					int32_t  key_size = uk.key_size;
					if (VERBOSE_DEBUG)
					{
						std::cout << "key pos: " << pos << ", key size: " << uk.key_size << ", databuffer containing key - size: " << d.buffer.size() << std::endl;

                        // crash
                        //key pos : 0, key size : 2816, databuffer containing key - size : 0
                        //rotating(padding) key : 2816
					}

					if (pos >= d.buffer.size() - key_size)
					{
						std::string su(u);
                        serr << "ERROR " << "invalid url file key position: " << pos << " url: " << su << std::endl;
						r = false;
					}

					if (r)
					{
						Buffer* b = uk.get_buffer(); // allocate
						b->increase_size(key_size);

						int32_t databuffer_size = (int32_t)d.buffer.size();
						if (databuffer_size < key_size)
						{
                            if (databuffer_size > 0)
							    b->write(&d.buffer.getdata()[0], databuffer_size, 0);

							// PADDING...
							if (VERBOSE_DEBUG)
							{
								std::cout << "rotating (padding) key: " << key_size -  databuffer_size << std::endl;
							}

							char c[1]; uint32_t rotate_pos;
							for( int32_t j = databuffer_size; j< key_size; j++)
							{
                                if (databuffer_size > 0)
                                {
                                    rotate_pos = j % databuffer_size;
                                    c[0] = d.buffer.getdata()[rotate_pos];
                                    b->write(&c[0], 1, -1);
                                }
                                else
                                {
                                    // ???
                                    c[0] = 'A';
                                    b->write(&c[0], 1, -1);
                                }
							}
						}
						else
						{
							b->write(&d.buffer.getdata()[pos], key_size, 0);
						}

						if (VERBOSE_DEBUG)
						{
							std::cout << "key: ";
							file_util::show_summary(b->getdata(), key_size, serr);
						}

						//if (is_rsa == false)
						{
							std::string checksum;
							{
								SHA256 sha;
								sha.update(reinterpret_cast<const uint8_t*> (d.buffer.getdata()), d.buffer.size() );
								uint8_t* digest = sha.digest();
								checksum = SHA256::toString(digest);
								if (VERBOSE_DEBUG)
								{
									std::cout << "decryption key checksum: " << checksum << " " << d.buffer.size() << std::endl;
								}
								delete[] digest;
							}

							char c;
							for( size_t j = 0; j< CHKSUM_SIZE; j++)
							{
								c = checksum.at(j);
								if (c != uk.checksum[j])
								{
                                    serr << "ERROR " << "invalid key checksum at " << j << std::endl;
									r = false;
									break;
								}
							}
						}
					}
				}
			}
            else
            {
                serr << "ERROR " << "unable to read downloaded url contents " << file <<std::endl;
                r = false;
            }
		}

		// TODO no staging file
		if (keeping == false)
		{
            if (file_util::fileexists(file))
                std::remove(file.data());
        }
		return r;
	}

	bool decode_binDES(cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptodata& data_decrypted)
	{
        bool r = true;
		char c;

        if (key_size == 0)
		{
            std::cerr << "ERROR decode_binDES - key_size = 0 " <<  "" << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() == 0)
		{
            std::cerr << "ERROR decode_binDES - data file is empty " << std::endl;
            return false;
        }
        if (key_size % 4 != 0)
		{
            std::cerr << "ERROR decode_binDES - key_size must be 4x " <<  key_size << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() % 8 != 0)
		{
            std::cerr << "ERROR decode_binDES - data size must be 8x " <<  data_encrypted.buffer.size() << std::endl;
            return false;
        }

        // BINARY DES (double file size on encryption, divide in 2 on decryption)
		uint32_t nblock = data_encrypted.buffer.size() / 8;
		uint32_t nkeys  = key_size / 4;

		if (verbose)
		{
			std::string message = "Decoding binary DES";
            size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
            std::string message_space(sz, ' ');
            std::cout <<    message << message_space <<
                            "number of blocks (8 bytes): " << nblock <<
                            ", number of keys (4 bytes): " << nkeys  << std::endl;
        }

		char KEY[4];
		std::string DATA;
        char data_decr[4];

		uint32_t key_idx = 0;
		for(size_t blocki = 0; blocki < nblock; blocki++)
		{
            DATA.clear();
            for(size_t j = 0; j < 8; j++)
            {
                c = data_encrypted.buffer.getdata()[8*blocki + j];
                DATA += c;
            }

            for(size_t j = 0; j < 4; j++)
            {
                c = key[4*key_idx + j];
                KEY[j] = c;
            }
            key_idx++;
            if (key_idx >= nkeys) key_idx=0;

            DES des(KEY);
            des.decrypt_bin(DATA, data_decr, 4);
            data_decrypted.buffer.write(&data_decr[0], 4, -1); // 8 bytes to 4 bytes!
        }

        return r;
	}


	bool decode_idea(   cryptodata& data_encrypted,
                        const char* key, uint32_t key_size,
                        cryptodata& data_decrypted)
	{
        bool r = true;
		char c;

		if (key_size % 16 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "decode_sidea key must be multiple of 16 bytes " <<  key_size << std::endl;
            return r;
		}
		if (data_encrypted.buffer.size() % 8 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "decode_idea data must be multiple of 8 bytes " <<  data_encrypted.buffer.size() << std::endl;
            return r;
		}
        if (key_size == 0)
		{
            std::cerr << "ERROR decode_sidea - key_size = 0 " <<  "" << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() == 0)
		{
            std::cerr << "ERROR decode_sidea - data file is empty " << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_encrypted.buffer.size() / 8;
		uint32_t nkeys  = key_size / 16;


		if (data_encrypted.buffer.size() > 0)
		{
            if (key_size > data_encrypted.buffer.size() )
            {
                nround = key_size / data_encrypted.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
			std::string message = "Decoding idea";
            size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
            std::string message_space(sz, ' ');
            std::cout <<    message << message_space <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (8 bytes): " << nblock <<
                            ", number of keys (16 bytes): "  << nkeys  << std::endl;
        }

		uint8_t KEY[16+1];
		uint8_t DATA[8+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) *  nblock) % nkeys;
            }
            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            if (r == false)
                break;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 8; j++)
                    {
                        c = data_encrypted.buffer.getdata()[8*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8]=0;
                }
                else
                {
                    for(size_t j = 0; j < 8; j++)
                    {
                        c = data_decrypted.buffer.getdata()[8*blocki + j];
                        DATA[j] = c;
                    }
                    DATA[8]=0;
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16]=0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                idea algo;
                algo.IDEA(DATA, KEY, false);

                data_decrypted.buffer.write((char*)&DATA[0], 8, -1);
            }
        }

        return r;
	}


	bool decode_salsa20(    cryptodata& data_encrypted,
                            const char* key, uint32_t key_size,
                            cryptodata& data_decrypted)
	{
        bool r = true;
		char c;

		if (key_size % 32 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "decode_salsa20 key must be multiple of 32 bytes " <<  key_size << std::endl;
            return r;
		}
		if (data_encrypted.buffer.size() % 64 != 0)
		{
            r = false;
            std::cerr << "ERROR " << "decode_salsa20 data must be multiple of 64 bytes " <<  data_encrypted.buffer.size() << std::endl;
            return r;
		}
        if (key_size == 0)
		{
            std::cerr << "ERROR decode_salsa20 - key_size = 0 " <<  "" << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() == 0)
		{
            std::cerr << "ERROR decode_salsa20 - data file is empty " << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_encrypted.buffer.size() / 64;
		uint32_t nkeys  = key_size / 32;

		uint8_t iv[8]  = {0x12, 0x01, 0x56, 0x78, 0x00, 0xbc, 0xde, 0xde};

		if (data_encrypted.buffer.size() > 0)
		{
            if (key_size > data_encrypted.buffer.size() )
            {
                nround = key_size / data_encrypted.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
			std::string message = "Decoding salsa20";
            size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
            std::string message_space(sz, ' ');
            std::cout <<    message << message_space <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (64 bytes): " << nblock <<
                            ", number of keys (32 bytes): "   << nkeys  << std::endl;
        }

		uint8_t KEY[32+1];
        uint8_t encrypted[64+1];
        uint8_t out[64+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) *  nblock) % nkeys;
            }

            if (r == false)
                break;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 64; j++)
                    {
                        c = data_encrypted.buffer.getdata()[64*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[64]=0;
                }
                else
                {
                    for(size_t j = 0; j < 64; j++)
                    {
                        c = data_decrypted.buffer.getdata()[64*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[64]=0;
                }

                for(size_t j = 0; j < 32; j++)
                {
                    c = key[32*key_idx + j];
                    KEY[j] = c;
                }
                KEY[32]=0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                ucstk::Salsa20 s20(KEY);
                s20.setIv(iv);
                s20.processBlocks(encrypted, out, 1);

                data_decrypted.buffer.write((char*)&out[0], 64, -1);
            }
        }

        return r;
	}

	std::string get_keyname_aes(char* url)
	{
		std::string r;
		std::string tok;
		CRYPTO_ALGO a;
		for(uint16_t i = (uint16_t)wbaes_algo_first(); i<= (uint16_t)wbaes_algo_last(); i++)
		{
			a = wbaes_algo_from_uint16(i);
			tok = token_wbaes_algo(a);
			if 	(strutil::has_token(tok , std::string(url), 0))
			{
				r = std::string(url).substr(tok.size());
				break;
			}
		}
		return r;
	}

    std::string format_wbaes_name(const std::string& aesname)
    {
        CRYPTO_ALGO t = wbaes_algo(aesname);
        if (t==CRYPTO_ALGO::ALGO_wbaes512) return "AES 512";
        else if (t==CRYPTO_ALGO::ALGO_wbaes1024) return "AES 1024";
        else if (t==CRYPTO_ALGO::ALGO_wbaes2048) return "AES 2048";
        else if (t==CRYPTO_ALGO::ALGO_wbaes4096) return "AES 4096";
        else if (t==CRYPTO_ALGO::ALGO_wbaes8192) return "AES 8192";
        else if (t==CRYPTO_ALGO::ALGO_wbaes16384) return "AES 16384";
        else if (t==CRYPTO_ALGO::ALGO_wbaes32768) return "AES 32768";
        return "";
    }

	bool decode_wbaes(cryptodata& data_encrypted, const std::string& easname, const std::string& keyname, const std::string& folder, cryptodata& data_decrypted)
	{
		bool r = true;

        if (data_encrypted.buffer.size() == 0)
		{
            std::cerr << "ERROR decode_aes - data file is empty " << easname << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = 1;

		if (verbose)
		{
		    std::string message = "Decoding Whitebox " + format_wbaes_name(easname) + " CFB";
            size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
            std::string message_space(sz, ' ');
            std::cout <<    message << message_space <<
                            ", number of rounds : " << nround <<
							", block size : " << data_encrypted.buffer.size()  <<
                            ", number of blocks: " << nblock << std::endl;
        }

		WBAES::wbaes_vbase* paes = aes_pool.get_aes_instance(easname, keyname, folder, verbose);
		if (paes == nullptr)
		{
			std::cerr << "ERROR aes tables not found in " << easname << " " << keyname << " " << folder << std::endl;
			return false;
		}

		size_t n = data_encrypted.buffer.size();
		uint8_t* DATAOUT = new uint8_t[n];
        const unsigned char iv[16] = {0x60, 0x61, 0x82, 0x93, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

		if (VERBOSE_DEBUG) std::cout << "AES in message: ";
		if (VERBOSE_DEBUG) for(size_t i=0;i<16;i++) std::cout << (int)(uint8_t)data_encrypted.buffer.getdata()[i];
		if (VERBOSE_DEBUG) std::cout << "...";
		if (VERBOSE_DEBUG) std::cout <<std::endl;

		paes->aes_whitebox_decrypt_cfb(iv, (uint8_t*)&data_encrypted.buffer.getdata()[0], n, DATAOUT);
        data_decrypted.buffer.write((char*)&DATAOUT[0], (uint32_t)n, -1);

		if (VERBOSE_DEBUG) std::cout << "AES decrypt: ";
		if (VERBOSE_DEBUG) for(size_t i=0;i<16;i++) std::cout << (int)(uint8_t)DATAOUT[i];
		if (VERBOSE_DEBUG) std::cout << "...";
		if (VERBOSE_DEBUG) std::cout <<std::endl;

		delete []DATAOUT;
		return r;
	}

	bool decode_twofish(cryptodata& data_encrypted,
                            const char* key, uint32_t key_size,
                            cryptodata& data_decrypted)
	{
        bool r = true;
		char c;

		if (key_size == 0)
		{
            std::cerr << "ERROR decode_twofish - key_size = 0 " <<  "" << std::endl;
            return false;
        }
        if (key_size % 16 != 0)
		{
            std::cerr << "ERROR decode_twofish - key_size must be 16x " <<  key_size << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() % 16 != 0)
		{
            std::cerr << "ERROR decode_twofish - data size must be 16x " <<  data_encrypted.buffer.size() << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() == 0)
		{
            std::cerr << "ERROR decode_twofish - data file is empty " << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_encrypted.buffer.size() / 16;
		uint32_t nkeys  = key_size / 16;

		if (data_encrypted.buffer.size() > 0)
		{
            if (key_size > data_encrypted.buffer.size() )
            {
                nround = key_size / data_encrypted.buffer.size();
                nround++;
            }
		}

        int rr = 0;
		if (s_Twofish_initialise == false)
		{
            rr = Twofish_initialise();
            if (rr < 0)
            {
                std::cout << "Error with Twofish_initialise " << rr << std::endl;
                r = false;
                return r;
            }
            s_Twofish_initialise = true;
        }

		if (verbose)
		{
			std::string message = "Decoding twofish";
            size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
            std::string message_space(sz, ' ');
            std::cout <<    message << message_space <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (16 bytes): " << nblock <<
                            ", number of keys (16 bytes): "   << nkeys  << std::endl;
        }

		Twofish_Byte KEY[16+1];
        Twofish_Byte encrypted[16+1];
        Twofish_Byte out[16+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) *  nblock) % nkeys;
            }
            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            if (r == false)
                break;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_encrypted.buffer.getdata()[16*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[16]=0;
                }
                else
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_decrypted.buffer.getdata()[16*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[16]=0;
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16]=0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                Twofish_key xkey;
                rr = Twofish_prepare_key( KEY, 16, &xkey );
                if (rr < 0)
                {
                    std::cerr << "ERROR Twofish_prepare_key " << rr << std::endl;
                    r = false;
                    break;
                }
                Twofish_decrypt(&xkey, encrypted, out);
                data_decrypted.buffer.write((char*)&out[0], 16, -1);
            }
        }

        return r;
	}

	bool decode_binaes128(cryptodata& data_encrypted,
                            const char* key, uint32_t key_size,
                            cryptodata& data_decrypted,
                            CRYPTO_ALGO_AES aes_type)
	{
        bool r = true;
		char c;

        if (key_size == 0)
		{
            std::cerr << "ERROR decode_binaes128 - key_size = 0 " <<  "" << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() == 0)
		{
            std::cerr << "ERROR decode_binaes128 - data file is empty " << std::endl;
            return false;
        }

        if (key_size % 16 != 0)
		{
            std::cerr << "ERROR decode_binaes128 - key_size must be 16x " <<  key_size << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() % 16 != 0)
		{
            std::cerr << "ERROR decode_binaes128 - data size must be 16x " <<  data_encrypted.buffer.size() << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_encrypted.buffer.size() / 16;
		uint32_t nkeys  = key_size / 16;

		if (data_encrypted.buffer.size() > 0)
		{
            if (key_size > data_encrypted.buffer.size() )
            {
                nround = key_size / data_encrypted.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
			std::string message = "Decoding AES 128 " + aes_subtype((uint16_t)aes_type);
            size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
            std::string message_space(sz, ' ');
            std::cout <<    message << message_space <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (16 bytes): " << nblock <<
                            ", number of keys (16 bytes): "   << nkeys  << std::endl;
        }

		unsigned char KEY[16+1];
        unsigned char encrypted[16+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) *  nblock) % nkeys;
            }
            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            if (r == false)
                break;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_encrypted.buffer.getdata()[16*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[16]=0;
                }
                else
                {
                    for(size_t j = 0; j < 16; j++)
                    {
                        c = data_decrypted.buffer.getdata()[16*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[16]=0;
                }

                for(size_t j = 0; j < 16; j++)
                {
                    c = key[16*key_idx + j];
                    KEY[j] = c;
                }
                KEY[16]=0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext

                if (aes_type == CRYPTO_ALGO_AES::ECB)
                {
                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto p = aes.DecryptECB(encrypted, plainLen, KEY);

                    data_decrypted.buffer.write((char*)&p[0], 16, -1);
                    delete []p;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CBC)
                {
                    const unsigned char iv[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto p = aes.DecryptCBC(encrypted, plainLen, KEY, iv);

                    data_decrypted.buffer.write((char*)&p[0], 16, -1);
                    delete []p;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CFB)
                {
                    const unsigned char iv[16] = {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};

                    binAES aes(AESKeyLength::AES_128);  //128 - key length, can be 128, 192 or 256
                    auto p = aes.DecryptCFB(encrypted, plainLen, KEY, iv);

                    data_decrypted.buffer.write((char*)&p[0], 16, -1);
                    delete []p;
                }
                else
                {
                    std::cerr << "ERROR unsupportes AES type " << (int)aes_type << std::endl;
                    r = false;
                    break;
                }
            }
        }

        return r;
	}

	bool decode_binaes256(cryptodata& data_encrypted,
                            const char* key, uint32_t key_size,
                            cryptodata& data_decrypted,
                            CRYPTO_ALGO_AES aes_type)
	{
        bool r = true;
		char c;

        if (key_size == 0)
		{
            std::cerr << "ERROR decode_binaes256 - key_size = 0 " <<  "" << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() == 0)
		{
            std::cerr << "ERROR decode_binaes256 - data file is empty " << std::endl;
            return false;
        }

        if (key_size % 32 != 0)
		{
            std::cerr << "ERROR decode_binaes256 - key_size must be 32x " <<  key_size << std::endl;
            return false;
        }
        if (data_encrypted.buffer.size() % 32 != 0)
		{
            std::cerr << "ERROR decode_binaes256 - data size must be 32x " <<  data_encrypted.buffer.size() << std::endl;
            return false;
        }

		uint32_t nround = 1;
		uint32_t nblock = data_encrypted.buffer.size() / 32;
		uint32_t nkeys  = key_size / 32;

		if (data_encrypted.buffer.size() > 0)
		{
            if (key_size > data_encrypted.buffer.size() )
            {
                nround = key_size / data_encrypted.buffer.size();
                nround++;
            }
		}

		if (verbose)
		{
			std::string message = "Decoding AES 256 " + aes_subtype((uint16_t)aes_type);
            size_t sz = 0; if (NDISPLAY > message.size()) sz = NDISPLAY - message.size();
            std::string message_space(sz, ' ');
            std::cout <<    message << message_space <<
                            ", number of rounds : " << nround <<
                            ", number of blocks (32 bytes): " << nblock <<
                            ", number of keys (32 bytes): "   << nkeys  << std::endl;
        }

		unsigned char KEY[32+1];
        unsigned char encrypted[32+1];
		uint32_t key_idx = 0;

		for(size_t roundi = 0; roundi < nround; roundi++)
		{
            if (roundi > 0)
            {
                data_decrypted.buffer.seek_begin();
            }

            if (nround > 0)
            {
                key_idx = ((nround - roundi - 1) *  nblock) % nkeys;
            }
            //std::cout << "roundi " << roundi << " key_idx " << key_idx << std::endl;

            if (r == false)
                break;

            for(size_t blocki = 0; blocki < nblock; blocki++)
            {
                if (roundi == 0)
                {
                    for(size_t j = 0; j < 32; j++)
                    {
                        c = data_encrypted.buffer.getdata()[32*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[32]=0;
                }
                else
                {
                    for(size_t j = 0; j < 32; j++)
                    {
                        c = data_decrypted.buffer.getdata()[32*blocki + j];
                        encrypted[j] = c;
                    }
                    encrypted[32]=0;
                }

                for(size_t j = 0; j < 32; j++)
                {
                    c = key[32*key_idx + j];
                    KEY[j] = c;
                }
                KEY[32]=0;

                key_idx++;
                if (key_idx >= nkeys) key_idx=0;

                unsigned int plainLen = 32 * sizeof(unsigned char);  //bytes in plaintext

                if (aes_type == CRYPTO_ALGO_AES::ECB)
                {
                    binAES aes(AESKeyLength::AES_256);  //key length, can be 128, 192 or 256
                    auto p = aes.DecryptECB(encrypted, plainLen, KEY);

                    data_decrypted.buffer.write((char*)&p[0], 32, -1);
                    delete []p;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CBC)
                {
                    const unsigned char iv[32] = {
                        0x30, 0x31, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
						0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,};

                    binAES aes(AESKeyLength::AES_256);  // key length, can be 128, 192 or 256
                    auto p = aes.DecryptCBC(encrypted, plainLen, KEY, iv);

                    data_decrypted.buffer.write((char*)&p[0], 32, -1);
                    delete []p;
                }
                else if (aes_type == CRYPTO_ALGO_AES::CFB)
                {
                    const unsigned char iv[32] = {
                        0x40, 0x41, 0x42, 0x43, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
						0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x16, 0x17,0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,};

                    binAES aes(AESKeyLength::AES_256);  //key length, can be 128, 192 or 256
                    auto p = aes.DecryptCFB(encrypted, plainLen, KEY, iv);

                    data_decrypted.buffer.write((char*)&p[0], 32, -1);
                    delete []p;
                }
                else
                {
                    std::cerr << "ERROR unsupportes AES type " << (int)aes_type << std::endl;
                    r = false;
                    break;
                }
            }
        }

        return r;
	}


	bool decode(std::stringstream& serr,
                size_t iter, size_t NITER, uint16_t crypto_algo, uint32_t crypto_flags, uint32_t shuffle_perc,
                cryptodata& data_encrypted, const char* key, uint32_t key_size, cryptodata& data_decrypted,
				std::string keyname = "")
	{
	   	if (VERBOSE_DEBUG)
	   	{
            std::cout << "decode crypto_flags " <<  crypto_flags <<  std::endl;
			std::cout << "decode shuffle_perc " <<  shuffle_perc <<  std::endl;
		}

		bool r = true;
		CRYPTO_ALGO aesalgo = wbaes_algo_from_uint16(crypto_algo);
		std::string wbaes_algo_name = algo_wbaes_name(aesalgo);

        if ((iter==0) || (iter==NITER-1))
        {
			r = decode_salsa20(data_encrypted, key, key_size, data_decrypted);
        }
		else if (wbaes_algo_name.size() > 0)
		{
			std::string keyfolder = wbaes_my_private_path;
            r = decode_wbaes(data_encrypted, wbaes_algo_name,  keyname, keyfolder, data_decrypted);
		}
        else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_TWOFISH)
        {
            r = decode_twofish(data_encrypted, key, key_size, data_decrypted);
        }
        else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_IDEA)
        {
            r = decode_idea(data_encrypted, key, key_size, data_decrypted);
        }
        else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_Salsa20)
        {
            r = decode_salsa20(data_encrypted, key, key_size, data_decrypted);
        }
		else
		{
			bool bin16=true;
            CRYPTO_ALGO_AES aes_type = CRYPTO_ALGO_AES::ECB;
            if      (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_128_ecb) aes_type = CRYPTO_ALGO_AES::ECB;
            else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_128_cfb) aes_type = CRYPTO_ALGO_AES::CFB;
			else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_128_cbc) aes_type = CRYPTO_ALGO_AES::CBC;
            else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_256_ecb) {aes_type = CRYPTO_ALGO_AES::ECB;bin16=false;}
            else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_256_cfb) {aes_type = CRYPTO_ALGO_AES::CFB;bin16=false;}
			else if (crypto_algo == (uint16_t) CRYPTO_ALGO::ALGO_BIN_AES_256_cbc) {aes_type = CRYPTO_ALGO_AES::CBC;bin16=false;}

			if (bin16)  r = decode_binaes128(data_encrypted, key, key_size, data_decrypted, aes_type);
			else		r = decode_binaes256(data_encrypted, key, key_size, data_decrypted, aes_type);
        }

		if (r)
		{
            if (crypto_flags & 1)
            {
                cryptoshuffle sh(verbose);
                r = sh.shuffle(data_decrypted.buffer, key, key_size, shuffle_perc);
            }
		}
		else
		{
            serr << "decode error?" <<  std::endl;
		}

		return r;
	}


    bool decrypt(std::stringstream& serr)
	{
        bool empty_puzzle = false;

        if (filename_puzzle.size() ==  0)
        {
            if (VERBOSE_DEBUG)
                std::cout << "WARNING empty puzzle filename (using default puzzle)" <<  std::endl;
            empty_puzzle = true;
        }
        if (filename_encrypted_data.size() ==  0)
        {
            serr << "ERROR empty encrypted data filename " <<  std::endl;
            return false;
        }

        if (empty_puzzle == false)
        {
            if (file_util::fileexists(filename_puzzle) == false)
            {
                serr << "ERROR missing puzzle file " << filename_puzzle <<  std::endl;
                return false;
            }
        }
        if (file_util::fileexists(filename_encrypted_data) == false)
        {
            serr << "ERROR missing encrypted_data file " << filename_encrypted_data <<  std::endl;
            return false;
        }

		bool r = true;
		Buffer puz_key(10000);

		if (r)
		{
            if (empty_puzzle == false)
            {
                if (puz.read_from_file(filename_puzzle, true) == false)
                {
                    serr << "ERROR " << "reading puzzle file " << filename_puzzle << std::endl;
                    r = false;
                }
			}
			else
			{
                if (puz.read_from_empty_puzzle(true) == false)
                {
                    serr << "ERROR " << "reading default puzzle" << std::endl;
                    r = false;
                }
			}
		}

		if (r)
		{
            if (empty_puzzle == false)
            {
                if (puz.is_all_answered() == false)
                {
                    serr << "ERROR " << "puzzle not fully answered" << std::endl;
                    r = false;
                }
			}
		}

		if (r)
		{
            if (empty_puzzle == false)
            {
                if (puz.is_valid_checksum() == false)
                {
                    serr << "ERROR " << "invalid puzzle answers or checksum" << std::endl;
                    serr << "puzzle size: " << puz.puz_data.buffer.size() << std::endl;
                    r = false;
                }
			}
			else if (false) // TODO no need here - puzzle crc is saved when encoding
			{
                // Make qa puzzle from default puzzle
                bool rr = true;
                puzzle p;
                p.verbose = false;
                std::string e = p.empty_puzzle();

                cryptodata temp;
                temp.buffer.write(e.data(), (uint32_t)e.size(), -1);
                bool rs = temp.save_to_file(staging + "staging_temp_preqa.txt");
                if (rs==false)
                {
                    serr << "ERROR " << "temp.save_to_file(staging + staging_temp_preqa.txt" << std::endl;
                    throw std::runtime_error("Failed temp.save_to_file(staging + staging_temp_preqa.txt");
                }

                rr = p.read_from_file(staging + "staging_temp_preqa.txt" , true);  // parse_puzzle
                if (rr == false) {r = false;}

                if (r)
                {
                    rr = p.save_to_file(staging + "staging_temp_qa.txt");          // CHKSUM_TOKEN
                    if (rr == false) {r = false;}
                }

                if (r)
                {
                    rr = puz.read_from_file(staging + "staging_temp_qa.txt", true);
                    if (rr == false) {r = false;}
                }

                if (r)
                {
                    if (puz.is_valid_checksum() == false)
                    {
                        serr << "ERROR " << "invalid puzzle answers or checksum" << std::endl;
                        serr << "puzzle size: " << puz.puz_data.buffer.size() << std::endl;
                        r = false;
                    }
                }

                if (file_util::fileexists(staging + "staging_temp_preqa.txt"))
                    std::remove(std::string(staging + "staging_temp_preqa.txt").data());
                if (file_util::fileexists(staging + "staging_temp_qa.txt"))
                    std::remove(std::string(staging + "staging_temp_qa.txt").data());
			}
		}

		if (r)
		{
			puz.make_key(puz_key);
			if (puz_key.size() == 0)
			{
                serr << "ERROR " << "puzzle empty" << std::endl;
				r = false;
			}
		}

		// pre_decode
		if (r)
		{
			if (check_converter == true)
			{
				bool is_png = converter::pgn_converter::is_file_ext_png(filename_encrypted_data);
				if (is_png)
				{
					if (VERBOSE_DEBUG)
					{
						std::cout << "pre decode - reading png... " << filename_encrypted_data <<  std::endl;
					}

					std::string new_filename_encrypted_data;
					bool r = pre_decode(serr, 1, filename_encrypted_data, encrypted_data, new_filename_encrypted_data);
					if (r == false)
					{
                        serr << "ERROR converting png to file: "  << new_filename_encrypted_data << std::endl;
					}
					else
					{
						if (VERBOSE_DEBUG)
						{
							std::cout << "saved to "  << new_filename_encrypted_data << std::endl;
						}
						if (filename_encrypted_data != new_filename_encrypted_data)
						{
							// new_filename_encrypted_data file not use anymore, data in memory
							if (file_util::fileexists(new_filename_encrypted_data))
								std::remove(new_filename_encrypted_data.data());
						}
						filename_encrypted_data = new_filename_encrypted_data; // override
					}
				}
			}
			else
			{
				if (encrypted_data.read_from_file(filename_encrypted_data) == false)
				{
                    serr << "ERROR " << "reading encrypted file " << filename_encrypted_data <<  std::endl;
					r = false;
				}
			}
		}

		//remove_padding();

		auto file_size = encrypted_data.buffer.size();
		if (file_size < 4)
		{
            serr << "ERROR " << "encrypted file too small " << file_size <<  std::endl;
            r = false;
		}

		history_key hkey;
		bool hkey_ok = true;
		uint32_t hist_out_seq = 0;

		if(r)
		{
			if (folder_my_private_hh.size() > 0)
			{
				std::string local_histo_db = folder_my_private_hh + HHKEY_MY_PRIVATE_DECODE_DB;
				cryptoAL::hhkey_util::make_from_file(hkey, encrypted_data, local_histo_db, hkey_ok, dbmgr, true);

                hkey_ok = cryptoAL::hhkey_util::get_next_seq_histo(hist_out_seq, local_histo_db, dbmgr, true);
                if (hkey_ok)
                {
                    hkey.update_seq(hist_out_seq);
                }
			}
		}

		//-------------------------
		// TODO some simple identification of origin
		//-------------------------
		char c[256+1] = {0};
		int cnt=0;
		for(size_t i=file_size-256;i<file_size;i++)
		{
			c[cnt] = encrypted_data.buffer.getdata()[i];
			cnt++;
		}
		std::string remote_hwinfo(c);
		strutil::trim(remote_hwinfo);

		std::string current_hwinfo;
		System::Properties pr;
		current_hwinfo = pr.CPUModel() + " " + pr.GPUName();
		strutil::trim(current_hwinfo);

		encrypted_data.buffer.remove_last_n_char(256);
		if (VERBOSE_DEBUG) std::cout << "remote hwinfo: " << remote_hwinfo << std::endl;

		bool auto_save = auto_flag;
		if (current_hwinfo == remote_hwinfo)
		{
			if (auto_flag)
			{
				//bool okTESTING = false;
				//if (	(cfg_parse_result) &&
				//		(cfg.cmdparam.allow_auto_update_on_same_machine_for_testing.size()>0)
				//	)
				//{
				//	// all_auto_update_on_same_machine_for_testing = 1
				//	long long n = parsing::str_to_ll(cfg.cmdparam.allow_auto_update_on_same_machine_for_testing);
				//	if (n > 0)
				//	{
				//		okTESTING = true;
				//	}
				//}

				//if (okTESTING == false)
				//{
				//	std::cout << std::endl;
				//	std::cout << "WARNING - It appears that your are decoding a file you made and auto update is on." << std::endl;
				//	std::cout << "Normally the auto update flag is to update the public keys received from the sender of the encrypted file." << std::endl;
				//	std::cout << "The auto option will update the public keys of the sender with your own public keys!" << std::endl;
				//	std::cout << "Do you really want to do this? n=no (normal, just do the decoding), y=yes (I'm only testing)" << std::endl;
				//	std::cout << "==> ";
				//	std::string q = ns_menu::get_input_string();
				//	if      ((q=="n") || (q=="N") || (q=="no") || (q== "NO")) {auto_save = false;}
				//	else if ((q=="y") || (q=="Y") || (q=="yes")|| (q=="YES")) {}
				//	else
				//	{
				//		std::cout << "invalid response, only the decoding will be done, no update of public keys" << std::endl;
				//		auto_save = false;
				//	}
				//}
				//else
				//{
				//}
			}
		}

		//-------------------------
		// PLAIN crc_full_puz_key
		//-------------------------
		file_size = encrypted_data.buffer.size();
		uint32_t crc_read_full_puz_key;
		uint32_t crc_full_puz_key;
		if (r)
		{
            crc_read_full_puz_key = encrypted_data.buffer.readUInt32(file_size - 4);

            {
                CRC32 crc;
                crc.update(&puz_key.getdata()[0], puz_key.size());
                crc_full_puz_key = crc.get_hash();
            }

            if (crc_read_full_puz_key != crc_full_puz_key)
            {
                serr << "ERROR " << "the provided puzzle dont match the initial one." << std::endl;
                r = false;
            }
        }
        if (r)
		{
            encrypted_data.buffer.remove_last_n_char(4);
		}

		// decode(DataFinal, puz_key) => DataN+urlkeyN+NITER  urlkeyN=>keyN
        if (r)
		{
            data_temp_next.clear_data();
            if (decode( serr, 0, 1, (uint16_t)CRYPTO_ALGO::ALGO_Salsa20, 0, 0,
                        encrypted_data, puz_key.getdata(), puz_key.size(), data_temp_next) == false)
            {
                serr << "ERROR " << "decoding with next key" << std::endl;
                r = false;
            }
        }

		// N(urls keys)+1(puzzle key) = Number of iterations in the last 2 byte! + PADDING + PADDING_MULTIPLE-2
		int16_t NITER = 0;
        int16_t PADDING = 0;

        if (r)
		{
            uint32_t file_size = (uint32_t)data_temp_next.buffer.size();
            if (file_size >= PADDING_MULTIPLE)
            {
                if (PADDING_LEN_ENCODESIZE == 2) // will skip padding
                {
                    PADDING = data_temp_next.buffer.readUInt16(file_size - 4);
                }
                else if (PADDING_LEN_ENCODESIZE > 2)
                {
                    serr << "WARNING " << "unmanaged padding encoding size " << PADDING_LEN_ENCODESIZE  <<std::endl;
                }

                NITER = data_temp_next.buffer.readUInt16(file_size - 2);
                NITER = NITER - 1;

                if (NITER < 0)
                {
                    serr << "ERROR " << "encrypted_data can not be decoded - iteration value less than zero " << NITER << std::endl;
                    r = false;
                }
                else if (NITER > NITER_LIM)
                {
                    serr << "ERROR " << "encrypted_data can not be decoded - iteration value bigger than limit " << NITER << std::endl;
                    r = false;
                }
            }
            else
            {
                serr << "ERROR " << "encrypted_data can not be decoded - invalid file size" << std::endl;
                r = false;
            }
		}

		if (NITER == 0)
        {
            data_temp_next.buffer.remove_last_n_char(PADDING_MULTIPLE);

            data_temp.buffer.swap_with(data_temp_next.buffer);
            data_temp_next.erase();
        }
        else
        {
            urlkey uk;
            if (r)
            {
                if (NITER > 0)
                {
                    size_t buffer_size = data_temp_next.buffer.size();

                    // Get urlkeyN
                    if (buffer_size >= URLINFO_SIZE + PADDING_MULTIPLE) // last PADDING_MULTIPLE is NITER+1
                    {
                        // Inverse of data_temp.append(&vurlkey[vurlkey.size()-1].urlinfo_with_padding[0], URLINFO_SIZE);
                        Buffer temp(URLINFO_SIZE + PADDING_MULTIPLE);
                        data_temp_next.get_last(URLINFO_SIZE + PADDING_MULTIPLE, temp);

                        if (read_urlinfo(serr, temp, uk) == false)
                        {
                            serr << "ERROR " << "encrypted_data can not be decoded  - invalid urlinfo" << std::endl;
                            r = false;
                        }

                        if (r)
                        {
                            data_temp_next.buffer.remove_last_n_char(URLINFO_SIZE + PADDING_MULTIPLE);
                        }
                    }
                    else
                    {
                        serr << "ERROR " << "encrypted_data can not be decoded  - invalid urlinfo size" << std::endl;
                        r = false;
                    }
                }
            }

            if (r)
            {
                data_temp.buffer.swap_with(data_temp_next.buffer);
                data_temp_next.erase();

                // decode(DataFinal, pwd0) => DataN+urlkeyN         urlkeyN=>keyN
                // decode(DataN,     keyN) => DataN-1+urlkeyN-1     urlkeyN-1=>keyN-1
                // ...
                // decode(Data2, key2) => Data1+urlkey1             urlkey1=>key1
                // decode(Data1, key1) => Data

                for(int16_t iter=0; iter<NITER; iter++)
                {
                    // Get KeyN from uk info read from URL
                    uk.clear_dynamic_data();

                    r = get_key(serr, uk);
                    if (r == false)
                    {
                        break;
                    }

					if (uk.rsa_ecc_encoded_data_len > 0)
					{
						if (data_temp.buffer.size() < uk.rsa_ecc_encoded_data_len)
						{
                            serr << "ERROR " << "encrypted_data can not be decoded  - invalid data size" << std::endl;
							r = false;
						}
						else
						{
							data_temp.buffer.remove_last_n_char(uk.rsa_ecc_encoded_data_len);
						}

						if (r)
						{
							if (uk.rsa_ecc_encoded_data_pad > 0)
							{
								if (data_temp.buffer.size() < uk.rsa_ecc_encoded_data_pad)
								{
									serr << "ERROR " << "encrypted_data can not be decoded pad - invalid data size" << std::endl;
									r = false;
								}
								else
								{
									data_temp.buffer.remove_last_n_char(uk.rsa_ecc_encoded_data_pad);
								}
							}

							// all extra removed from data
						}
					}

					// VERIFY_CHKSUM_DATA
					char compute_checksum_data[CHKSUM_SIZE+1] = {0};
					if (r)
					{
						SHA256 sha;
						sha.update(reinterpret_cast<const uint8_t*> (data_temp.buffer.getdata()), data_temp.buffer.size() );
						uint8_t* digest = sha.digest();
						auto s = SHA256::toString(digest);
						delete[]digest;
						for( size_t j = 0; j< CHKSUM_SIZE; j++)
							compute_checksum_data[j] = s[j];
						compute_checksum_data[CHKSUM_SIZE] = 0;

						char c;
						for( size_t j = 0; j< CHKSUM_SIZE; j++)
						{
							c = compute_checksum_data[j];
							if (c != uk.checksum_data[j])
							{
								char display_checksum_data[CHKSUM_SIZE+1] = {0};
								for( size_t j = 0; j< CHKSUM_SIZE; j++)
									display_checksum_data[j] = uk.checksum_data[j];

                                serr << "ERROR " << "invalid data checksum at " << j << " " << std::string(display_checksum_data) <<  std::endl;
								r = false;
								break;
							}
						}
					}

					if ((uk.crypto_algo < 1) || (uk.crypto_algo >= (uint16_t)CRYPTO_ALGO::ALGO_LIMIT_MARKER))
                    {
                        serr << "WARNING mismatch algo at url iter: " <<  iter << std::endl;
                    }

					std::string keyname;
					if 		(uk.crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_wbaes512)  {keyname = get_keyname_aes(uk.url);}
					else if (uk.crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_wbaes1024) {keyname = get_keyname_aes(uk.url);}
					else if (uk.crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_wbaes2048) {keyname = get_keyname_aes(uk.url);}
					else if (uk.crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_wbaes4096) {keyname = get_keyname_aes(uk.url);}
					else if (uk.crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_wbaes8192) {keyname = get_keyname_aes(uk.url);}
					else if (uk.crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_wbaes16384) {keyname = get_keyname_aes(uk.url);}
					else if (uk.crypto_algo == (uint16_t)CRYPTO_ALGO::ALGO_wbaes32768) {keyname = get_keyname_aes(uk.url);}

                    // decode(DataN, keyN) => DataN-1+urlkeyN-1     urlkeyN-1=>keyN-1
                    if (decode( serr, iter+1, NITER+1, uk.crypto_algo,
								uk.crypto_flags, uk.shuffle_perc,
                                data_temp,
                                &uk.get_buffer()->getdata()[0], uk.key_size,
                                data_temp_next, keyname) == false)
                    {
                        r = false;
                        serr << "ERROR " << "encrypted_data can not be decoded" << std::endl;
                        break;
                    }

                    size_t buffer_size = data_temp_next.buffer.size();

                    // Get urlkeyN
                    if (iter < NITER - 1)
                    {
                        if (buffer_size >= URLINFO_SIZE)
                        {
                            // Inverse of data_temp.append(&vurlkey[vurlkey.size()-1].urlinfo_with_padding[0], URLINFO_SIZE);
                            Buffer temp(URLINFO_SIZE);
                            data_temp_next.get_last(URLINFO_SIZE, temp);

                            if (VERBOSE_DEBUG) std::cout << std::endl;
                            if (read_urlinfo(serr, temp, uk) == false)
                            {
                                r = false;
                                serr << "ERROR " << "encrypted_data can not be decoded - can not read urlinfo" << std::endl;
                                break;
                            }

                            if (r)
                            {
                                data_temp_next.buffer.remove_last_n_char(URLINFO_SIZE);
                            }
                        }
                        else
                        {
                            r = false;
                            serr << "ERROR " << "encrypted_data can not be decoded - invalid urlinfo size" << std::endl;
                            break;
                        }
                    }

                    data_temp.buffer.swap_with(data_temp_next.buffer);
                    data_temp_next.erase();

                } //for(int16_t iter=0; iter<NITER; iter++)
            }
		}

        // Unpadding
        if (r)
        {
            if (PADDING > 0)
            {
                //std::cerr << "WARNING Unpadding of " << PADDING << " " << data_temp.buffer.size() << std::endl;
                data_temp.buffer.remove_last_n_char(PADDING);
            }
        }

		if (r)
		{
            // data_temp => decrypted_data
            r = data_temp.copy_buffer_to(decrypted_data);
            if (r)
            {
                r = post_decode(serr, decrypted_data, filename_decrypted_data, auto_save);
                if(r==false)
                {
                    serr << "ERROR " << "saving " << filename_decrypted_data << std::endl;
                }
            }
            else
            {
                serr << "ERROR " << "copying " << filename_decrypted_data  <<std::endl;
            }
		}

		if(r)
		{
			if (hkey_ok)
			{
				std::string local_histo_db = folder_my_private_hh + HHKEY_MY_PRIVATE_DECODE_DB;
				if (file_util::fileexists(local_histo_db) == false)
				{
					std::map<uint32_t, history_key> map_histo;
					std::ofstream outstream;
					outstream.open(local_histo_db, std::ios_base::out);
					outstream << bits(map_histo);
					outstream.close();
				}

                cryptoAL::hhkey_util::save_histo_key(hkey, local_histo_db, dbmgr, true);
                if (verbose)
                    std::cout << "history sequence saved: "  << hist_out_seq << std::endl;

				dbmgr.flush();
			}
		}
		return r;
	}

	bool cfg_parse_result= true;
	crypto_cfg  cfg;
	puzzle      puz;
    cryptodata  encrypted_data;
    cryptodata  decrypted_data;

	std::string filename_cfg;
	std::string filename_puzzle;
    std::string filename_encrypted_data;
	std::string filename_decrypted_data;
	std::string staging;
	std::string folder_local;
    std::string folder_my_private_rsa;
	std::string folder_other_public_rsa;
    std::string folder_my_private_ecc;
    std::string folder_other_public_ecc;
	std::string folder_my_private_hh;
    std::string folder_other_public_hh;
    std::string wbaes_my_private_path;
	std::string wbaes_other_public_path;

    cryptodata  data_temp;
    cryptodata  data_temp_next;
    bool        verbose;
    bool        keeping;
    std::string encryped_ftp_user;
    std::string encryped_ftp_pwd;
    std::string known_ftp_server;
    int         staging_cnt=0;
    bool        use_gmp;
    bool        auto_flag = false;
	bool		check_converter = false;

    cryptodata_list datalist;
	WBAES::wbaes_pool aes_pool;

	bool has_cfg_algo = false;
	std::vector<CRYPTO_ALGO> vAlgo;

	cryptoAL::db::db_mgr dbmgr;

	bool pre_decode(std::stringstream& serr, uint32_t converterid, const std::string& filename_encrypted_data, cryptodata& output_encrypted_data, std::string& new_output_filename)
	{
		bool r = true;
		if (converterid == 1)
		{
			// or append suffix....
			new_output_filename = converter::pgn_converter::remove_ext_png(filename_encrypted_data);
			if (VERBOSE_DEBUG)
				std::cout << "filename without png extension: " << new_output_filename << std::endl;

			converter::pgn_converter converter(verbose);
			std::string filename_tmp_envelop = filename_encrypted_data +".pngtobin.temp";

			cryptodata dtemp_envelop;
			int rc = converter.pngToBinary(filename_encrypted_data.data(), filename_tmp_envelop.data());
			if (rc == 0)
			{
				if (dtemp_envelop.read_from_file(filename_tmp_envelop) == false)
				{
                    serr << "ERROR " << "reading pgn file " << filename_tmp_envelop <<  std::endl;
					r = false;
				}
			}
			else
			{
                serr << "ERROR " << "decoding png " << std::endl;
				r = false;
			}

			if (file_util::fileexists(filename_tmp_envelop))
				std::remove(filename_tmp_envelop.data());

			if (r)
			{
                // NEED to extract raw encrypted data from pgn envelop
				cryptodata_list newdatalist(&serr, verbose);
                newdatalist.set_converter(converterid); // PNG padding

				r = newdatalist.read_write_from(dtemp_envelop, new_output_filename,
												folder_other_public_rsa,
												folder_other_public_ecc,
												folder_other_public_hh,
												folder_my_private_rsa,
												folder_my_private_ecc,
												folder_my_private_hh,
												verbose);
				if (r==false)
                {
                    serr << "ERROR " << " pre_decode error with PGN envelop " << new_output_filename << std::endl;
                    return false;
                }

				if (output_encrypted_data.read_from_file(new_output_filename) == false)
				{
                    serr << "ERROR " << "reading encrypted file " << new_output_filename <<  std::endl;
					r = false;
				}
			}
		}
		else
        {
            if (output_encrypted_data.read_from_file(filename_encrypted_data) == false)
            {
                serr << "ERROR " << "reading encrypted file " << filename_encrypted_data <<  std::endl;
                r = false;
            }
        }
		return r;
	}

	bool post_decode(std::stringstream& serr, cryptodata& decrypted_data, const std::string& filename_decrypted_data, bool auto_save = true)
	{
        datalist.verbose = verbose;
        bool r = true;

		if (!auto_flag)
        {
			if (verbose)
				std::cout << "!auto_flag" << std::endl;
        }

		// TODO move to dbmgr
		//	confirm_history_key() will re-read histo file
		//	kpriv.update_confirmed(true);
		//	map_histo[seq] = kpriv;
		dbmgr.flush();

        r = datalist.read_write_from(   decrypted_data, filename_decrypted_data,
                                        folder_other_public_rsa,
                                        folder_other_public_ecc,
                                        folder_other_public_hh,
                                        folder_my_private_rsa,
                                        folder_my_private_ecc,
                                        folder_my_private_hh,
                                        verbose,
										auto_save); // save if auto_flag==true

        if (r)
        {
            // Confirming:
			// 	Received HHKEY_OTHER_PUBLIC_DECODE_DB
			// 	Update HHKEY_MY_PRIVATE_ENCODE_DB
			std::string fileHistoPrivateEncodeDB = folder_my_private_hh + HHKEY_MY_PRIVATE_ENCODE_DB;
			std::string importfile = folder_other_public_hh + HHKEY_OTHER_PUBLIC_DECODE_DB;

			if (file_util::fileexists(fileHistoPrivateEncodeDB) == false)
			{
				std::map<uint32_t, history_key> map_histo;
				std::ofstream outstream;
				outstream.open(fileHistoPrivateEncodeDB, std::ios_base::out);
				outstream << bits(map_histo);
				outstream.close();
			}

			if (file_util::fileexists(fileHistoPrivateEncodeDB) == true)
			{
				if (file_util::fileexists(importfile) == true)
				{
					uint32_t cnt;
					uint32_t n;
					bool r = confirm_history_key(fileHistoPrivateEncodeDB, importfile, cnt, n);
					if (r==false)
					{
                        serr << "WARNING confirm of HH keys FAILED" << std:: endl;
						//r = false;
					}
					else
					{
						if (verbose)
							std::cout << "Number of new confirm: " << cnt << ", number of hashes: " << n << std:: endl;
					}
				}
				else
				{
                    serr << "WARNING no file to import HH keys confirmation: " << importfile << std:: endl;
				}
            }
			else
			{
				if (file_util::fileexists(importfile) == true)
				{
					// TODO
					if (verbose)
                        std::cerr << "WARNING no file to update HH keys confirmation: " << fileHistoPrivateEncodeDB << std:: endl;
				}
			}
        }

        if (r)
        {
            bool ok[4] = {true};
            bool key_updated[4] = {false};

            ok[0] = keymgr::status_confirm_or_delete(dbmgr, folder_my_private_rsa, CRYPTO_FILE_TYPE::RSA_KEY_STATUS , key_updated[0], verbose);
            if (ok[0]==false)
            {
                serr << "WARNING failed to update rsa keys status " << std:: endl;
            }

            ok[1] = keymgr::status_confirm_or_delete(dbmgr, folder_my_private_ecc, CRYPTO_FILE_TYPE::ECC_KEY_STATUS , key_updated[1], verbose);
            if (ok[1]==false)
            {
                serr << "WARNING failed to update ecc keys status " << std:: endl;
            }

            ok[2] = keymgr::status_confirm_or_delete(dbmgr, folder_my_private_hh,  CRYPTO_FILE_TYPE::HH_KEY_STATUS ,  key_updated[2], verbose);
            if (ok[2]==false)
            {
                serr << "WARNING failed to update hh keys status " << std:: endl;
            }

			ok[3] = keymgr::status_confirm_or_delete(dbmgr, folder_my_private_ecc,  CRYPTO_FILE_TYPE::ECC_DOM_STATUS ,  key_updated[3], verbose);
            if (ok[3]==false)
            {
                serr << "WARNING failed to update ecc domain keys status " << std:: endl;
            }
        }

		if (r)
        {
			bool key_merged = false;
			bool ok = keymgr::merge_other_ecc_domain(folder_my_private_ecc, folder_other_public_ecc, key_merged, verbose);
			if (ok == false)
			{
                serr << "WARNING failed to merge ecc domain keys status " << std:: endl;
			}
		}

		if (r)
        {
			// Nothing todo! - The next export will override other public keys anyway after being deleted at the source from delete confirmation status
			// WHEN to do it: was already marked as deleted and did not receive another deleted record this decode (encode sent a confimation before)
			// cleanup public other [k.deleted == true]
/*
			bool ok[3] = {true};
            bool key_deleted[3] = {false};
			ok[0] = keymgr::delete_public_keys_marked_for_deleting(folder_other_public_rsa, CRYPTO_FILE_TYPE::RSA_PUBLIC , key_deleted[0]);
			ok[1] = keymgr::delete_public_keys_marked_for_deleting(folder_other_public_ecc, CRYPTO_FILE_TYPE::ECC_PUBLIC , key_deleted[1]);
			ok[2] = keymgr::delete_public_keys_marked_for_deleting(folder_other_public_hh,  CRYPTO_FILE_TYPE::HH_PUBLIC , key_deleted[2]);
			//...
*/
		}

		dbmgr.flush();
        return r;
    }


};

}

#endif
