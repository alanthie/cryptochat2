/*
 * Author: Alain Lanthier
 */

#include "../include/client_term.hpp"
#include "../include/nc_key.hpp"

#include "../include/crypto_const.hpp"
#include "../include/terminal.h"
#include "../include/crypto_client.hpp"
#include "../include/data.hpp"
#include "../include/string_util.hpp"
#include "../include/file_util.hpp"
#include "../include/main_global.hpp"
#include <stdarg.h>

using Term::Terminal; // old constants
using Term::fg;
using Term::bg;
using Term::style;
using Term::Key;

// virtual
void ClientTerm1::process_FKey(char32_t k)
{
    if (k == NCKEY_F03) // toggle crypto
    {
        netw_client->cryto_on = !netw_client->cryto_on;
        netw_client->set_ui_dirty();
    }
    else if (k == NCKEY_F04) // chat with all
    {
        netw_client->chat_with_other_user_index = 0;
    }
}

// virtual
bool ClientTerm1::is_client_dirty()
{
    bool r = false;
    if      (_mode == 0) r = netw_client->get_ui_dirty();
    else if (_mode == 2) r = main_global::is_log_dirty();
    else if (_mode == 1) r = is_file_view_dirty;
    else if (_mode == 3) r = netw_client->get_user_view_dirty();

    return  r;
}

// virtual
void ClientTerm1::reset_is_dirty()
{
    if      (_mode == 0)    netw_client->set_ui_dirty(false);
    else if (_mode == 2)    main_global::set_log_dirty(false);
    else if (_mode == 1)    is_file_view_dirty = false;
    else if (_mode == 3)    netw_client->set_user_view_dirty(false);
}

// virtual
void ClientTerm1::process_enter()
{
    if (_mode == 3)
    {
        int row_cursor = first_row_usr_view + cursor_usr_y;
        if (row_cursor < vusrrows.size() && row_cursor >= 0)
        {
            if (row_cursor < netw_client->map_user_index_to_user.size() && row_cursor >= 0)
            {
                int cnt = 0;
                for (auto& e : netw_client->map_user_index_to_user)
                {
                    if (cnt == row_cursor)
                    {
                        if (e.first != netw_client->my_user_index)
                            netw_client->chat_with_other_user_index = e.first;
                        break;
                    }
                    cnt++;
                }
            }
        }
    }
    else if (_mode == 0)
    {
       // return a heap-allocated copy of the current (UTF-8) contents.
      char* content = ncreader_contents(nc_reader);

      process_prompt(content);

      ncreader_clear(nc_reader);
      if (content != NULL)
        free(content);
    }
}

// virtual
void ClientTerm1::process_tab_changes(const char* tname, struct nctab* t, struct ncplane* p)
{
    //_mode 0 = chat view, 1 = file view, 2 = log view, 3=User view
    int prev_mode = _mode;
    bool found = false;

    if (strcmp(tname, "Chat") == 0)
    {
        _mode = 0;
        found = true;
    }
    else if (strcmp(tname, "File") == 0)
    {
        _mode = 1;
        found = true;
    }
    else if (strcmp(tname, "User") == 0)
    {
        _mode = 3;
        found = true;
    }
    else if (strcmp(tname, "Log") == 0)
    {
        _mode = 2;
        found = true;
    }
    else if (strcmp(tname, "About") == 0)
    {
        _mode = 4;
        found = true;
    }
    else if (strcmp(tname, "Help") == 0)
    {
        _mode = 5;
        found = true;
    }
    else if (strcmp(tname, "Stats") == 0)
    {
        _mode = 6;
        found = true;
    }
    else
    {
        _mode = -1;
    }

    if (found == false)
    {
        if (p != nullptr)
        {
            unsigned rrows, rcols;
            ncplane_dim_yx(p, &rrows, &rcols);
            nrows = (int)rrows;
            ncols = (int)rcols;
        }

        if (p != nullptr)
        {
            notcurses_term_dim_yx(nc, &rows, &cols);

            ncplane_erase(p);
            ncplane_putstr_yx(p, 0, 0, "Future feature ...");
        }

        // status plane
        sstatus.clear();
        if (status_plane != nullptr)
        {
            ncplane_erase(status_plane);
        }
        return;
    }

    if (_mode == 4) // about
    {
        if (p != nullptr)
        {
            ncplane_erase(p);

            ncplane_putstr_yx(p, 0, 0, (std::string("Crypto Chat (version ") + version_to_string() + std::string(")")).c_str() );
            ncplane_putstr_yx(p, 2, 0, "Author : Alain Lanthier");
            ncplane_putstr_yx(p, 3, 0, "License: Free for personal use");
            ncplane_putstr_yx(p, 4, 0, "Open source: https://github.com/alanthie/CryptoChat");
            ncplane_putstr_yx(p, 5, 0, "Donate patreon : https://www.patreon.com/c/CryptoAL");
            ncplane_putstr_yx(p, 6, 0, "       gofundme: https://www.gofundme.com/f/survivre-au-nom");
            ncplane_putstr_yx(p, 7, 0, "Bugs or features suggestion: https://github.com/alanthie/CryptoChat/issues");
            ncplane_putstr_yx(p, 8, 0, "Copyright © 2024–2025 Alain Lanhier");
            ncplane_putstr_yx(p, 9, 0, "This program comes with absolutely no warranty");
        }
        return;
    }

    if (_mode == 6) // stats
    {
        if (p != nullptr)
        {
            ncplane_erase(p);
            size_t n = main_global::msg_stats.msg_in_count;
            if (n < 1) n = 1;
            ncplane_putstr_yx(p, 1, 0, "Base chat (symmetrical keys) encryption:" );
            ncplane_putstr_yx(p, 2, 0, (std::string("msg count:" )                       + std::to_string(main_global::stats().msg_in_count)).c_str() );
            ncplane_putstr_yx(p, 3, 0, (std::string("average msg len (bytes):  " )       + std::to_string(main_global::stats().msg_in_len / n)).c_str() );
            ncplane_putstr_yx(p, 4, 0, (std::string("average vigenere_key_len (bytes):  " ) + std::to_string(main_global::stats().vigenere_key_len/ n)).c_str() );
            ncplane_putstr_yx(p, 5, 0, (std::string("average idea_key_len (bytes):  " )     + std::to_string(main_global::stats().idea_key_len/ n)).c_str() );
            ncplane_putstr_yx(p, 6, 0, (std::string("average salsa20_key_len (bytes):  " )  + std::to_string(main_global::stats().salsa20_key_len/ n)).c_str() );
            //
            size_t n2 = main_global::msg_stats.msg2_in_count;
            if (n2 < 1) n2 = 1;
            ncplane_putstr_yx(p, 8, 0, "Extra crypto (RSA, ECC, ... ) encryption:" );
            ncplane_putstr_yx(p, 9, 0, (std::string("msg count:" )                        + std::to_string(main_global::stats().msg2_in_count)).c_str() );
            ncplane_putstr_yx(p, 10, 0, (std::string("average msg_in_len (bytes):  " )       + std::to_string(main_global::stats().msg2_in_len / n2)).c_str() );
            ncplane_putstr_yx(p, 11, 0, (std::string("average msg_out_len (bytes): " )       + std::to_string(main_global::stats().msg2_out_len / n2)).c_str() );
            //
            size_t n3 = main_global::msg_stats.rsa_ecc_key_count;
            if (n3 < 1) n3 = 1;
            ncplane_putstr_yx(p, 12, 0, (std::string("rsa_ecc_key_count:" )                  + std::to_string(main_global::stats().rsa_ecc_key_count)).c_str() );
            ncplane_putstr_yx(p, 13, 0, (std::string("average embedded_random rsa_ecc_key_len (bytes):  " )  + std::to_string(main_global::stats().embedded_rsa_ecc_key_len / n3)).c_str() );
            ncplane_putstr_yx(p, 14, 0, (std::string("average envelopped      rsa_ecc_key_len (bytes):  " )  + std::to_string(main_global::stats().rsa_ecc_key_len / n3)).c_str() );

            size_t n4 = main_global::msg_stats.other_key_count;
            if (n4 < 1) n4 = 1;
            ncplane_putstr_yx(p, 15, 0, (std::string("other_key_count:" )                  + std::to_string(main_global::stats().other_key_count)).c_str() );
            ncplane_putstr_yx(p, 16, 0, (std::string("average other_key_len (bytes):  " )  + std::to_string(main_global::stats().other_key_len / n4)).c_str() );

            ncplane_putstr_yx(p, 17, 0, (std::string("ALGO_BIN_DES count:  " )      + std::to_string(main_global::stats().ALGO_BIN_DES)).c_str() );
            ncplane_putstr_yx(p, 18, 0, (std::string("ALGO_BIN_AES256 count:  " )   + std::to_string(main_global::stats().ALGO_BIN_AES256)).c_str() );
            ncplane_putstr_yx(p, 19, 0, (std::string("ALGO_TWOFISH count:  " )      + std::to_string(main_global::stats().ALGO_TWOFISH)).c_str() );
            ncplane_putstr_yx(p, 20, 0, (std::string("ALGO_Salsa20 count:  " )      + std::to_string(main_global::stats().ALGO_Salsa20)).c_str() );
            ncplane_putstr_yx(p, 21, 0, (std::string("ALGO_IDEA count:  " )         + std::to_string(main_global::stats().ALGO_IDEA)).c_str() );
            ncplane_putstr_yx(p, 22, 0, (std::string("ALGO_wbaes count:  " )        + std::to_string(main_global::stats().ALGO_wbaes)).c_str() );
            //
            ncplane_putstr_yx(p, 24, 0, "You can search the web about vigenere, idea, salsa20 encryption algorithms");
            ncplane_putstr_yx(p, 25, 0, "You can search the web about rsa, ecc, ...  encryption algorithms");
            ncplane_putstr_yx(p, 26, 0, "ALL encryption keys are RANDOM and regenerate at EVERY message");
        }
        return;
    }

    if (_mode == 5) // help
    {
        if (p != nullptr)
        {
            ncplane_erase(p);

            ncplane_putstr_yx(p, 0, 0, "Tab keys: TAB, SHIFT-TAB, F1, F2");
            ncplane_putstr_yx(p, 1, 0, "Pannel keys: SHIFT-UP, SHIFT-DOWN, SHIFT-PAGEUP, SHIFT-PAGEDOWN");
            ncplane_putstr_yx(p, 2, 0, "Input keys: ENTER, UP, DOWN, LEFT, RIGHT, Backspace, text");
            ncplane_putstr_yx(p, 3, 0, "Send a text file: <<filename>>");
            ncplane_putstr_yx(p, 4, 0, "Send a binary file: [[filename]]");
            ncplane_putstr_yx(p, 5, 0, "Send pre configured text file <<*>>");
            ncplane_putstr_yx(p, 6, 0, "Send pre configured binary file [[*]]");
            ncplane_putstr_yx(p, 7, 0, "Quit key: CTRL-X");
        }
        return;
    }

    if      (_mode == 0)    refresh_screen(p, netw_client->get_ui_dirty());
    else if (_mode == 2)    refresh_screen(p, main_global::is_log_dirty());
    else if (_mode == 1)    refresh_screen(p, is_file_view_dirty);
    else if (_mode == 3)    refresh_screen(p, netw_client->get_user_view_dirty());

    if      (_mode == 0)    netw_client->set_ui_dirty(false);
    else if (_mode == 2)    main_global::set_log_dirty(false);
    else if (_mode == 1)    is_file_view_dirty = false;
    else if (_mode == 3)    netw_client->set_user_view_dirty(false);
}


ClientTerm1::ClientTerm1() : nc_terminal()
{
    // term is not init
    tbegin = std::chrono::steady_clock::now();
}

bool ClientTerm1::is_file_command(const std::string& m)
{
    if (m.size() < 5) return false;
    if ((m[0]=='<') && (m[1]=='<') && (m[m.size()-1]=='>') && (m[m.size()-2]=='>'))
        return true;
    return false;
}

bool ClientTerm1::is_binfile_command(const std::string& m)
{
    if (m.size() < 5) return false;
    if ((m[0] == '[') && (m[1] == '[') && (m[m.size() - 1] == ']') && (m[m.size() - 2] == ']'))
        return true;
    return false;
}

std::string ClientTerm1::file_from_command(const std::string& m)
{
    return m.substr(2, m.size()-4);
}

std::string ClientTerm1::read_file(const std::string& fname, std::stringstream* serr)
{
    cryptoAL::cryptodata file;
    if (file.read_from_file(fname, true, serr))
    {
        return std::string(file.buffer.getdata(), file.buffer.size());
    }
    return {};
}

void ClientTerm1::add_to_history(bool is_receive, bool crypto, uint32_t from_user, uint32_t to_user, uint8_t msg_type, std::string& msg,
                  std::string filename, std::string filename_key, bool is_for_display)
{
    netw_client->add_to_history(is_receive, crypto, from_user, to_user, msg_type, msg, filename, filename_key, is_for_display);
}

std::string ClientTerm1::get_printable_string(const std::string& line)
{
    std::string s(line.size(), ' ');
    char c;
    for (size_t i=0;i<line.size();i++)
    {
        c = line[i];
        if ((c >= 32) && (c < 127)) s[i] = c;
        else s[i] = '_';
    }
    return s;
}

// virtual
void ClientTerm1::process_move_keys_in_tab_plane(const char32_t c)
{
    if (c == NCKey::PgUp || c == NCKey::PgDown || c == NCKey::Up || c == NCKey::Down)
    {
        ncplane* t = nctabbed_content_plane(nct);

        if (_mode == 0)
        {
            if (vallrows.size() > (nrows - 0))
            {
                if (c == NCKey::PgUp)
                {
                    first_row = first_row - (nrows - 0);
                    if (first_row < 0) first_row = 0;
                    refresh_screen(t,false);
                }
                else if (c == NCKey::PgDown)
                {
                    first_row = first_row + (nrows - 0);
                    if (first_row > vallrows.size() - (nrows - 0))
                        first_row = vallrows.size() - (nrows - 0);
                    refresh_screen(t,false);
                }
            }

            if (c == NCKey::Up)
            {
                if (cursor_y == 0)
                {
                    first_row = first_row - 1;
                    if (first_row < 0) first_row = 0;
                }
                else
                {
                    cursor_y--;
                }
                refresh_screen(t,false);
            }
            else if (c == NCKey::Down)
            {
                if (cursor_y == (nrows - 0) - 1)
                {
                    if (vallrows.size() > (nrows - 0))
                    {
                        first_row = first_row + 1;
                        if (first_row > vallrows.size() - (nrows - 0))
                            first_row = vallrows.size() - (nrows - 0);
                    }
                }
                else
                {
                    cursor_y++;
                }
                refresh_screen(t,false);
            }
        }
        else if (_mode == 2)
        {
            if (vlogrows.size() > (nrows - 0))
            {
                if (c == NCKey::PgUp)
                {
                    first_row_log_view = first_row_log_view - (nrows - 0);
                    if (first_row_log_view < 0) first_row_log_view = 0;
                    refresh_screen(t,false);
                }
                else if (c == NCKey::PgDown)
                {
                    first_row_log_view = first_row_log_view + (nrows - 0);
                    if (first_row_log_view > vlogrows.size() - (nrows - 0))
                        first_row_log_view = vlogrows.size() - (nrows - 0);
                    refresh_screen(t,false);
                }
                else if (c == NCKey::Up)
                {
                    first_row_log_view = first_row_log_view - 1;
                    if (first_row_log_view < 0) first_row_log_view = 0;
                    refresh_screen(t,false);
                }
                else if (c == NCKey::Down)
                {
                    first_row_log_view = first_row_log_view + 1;
                    if (first_row_log_view > vlogrows.size() - (nrows - 0))
                        first_row_log_view = vlogrows.size() - (nrows - 0);
                    refresh_screen(t,false);
                }
            }
        }
        else if (_mode == 1)
        {
            if (vfilerows.size() > (nrows - 0))
            {
                if (c == NCKey::PgUp)
                {
                    first_row_fileview = first_row_fileview - (nrows - 0);
                    if (first_row_fileview < 0) first_row_fileview = 0;
                    refresh_screen(t,false);
                }
                else if (c == NCKey::PgDown)
                {
                    first_row_fileview = first_row_fileview + (nrows - 0);
                    if (first_row_fileview > vfilerows.size() - (nrows - 0))
                        first_row_fileview = vfilerows.size() - (nrows - 0);
                    refresh_screen(t,false);
                }
                else if (c == NCKey::Up)
                {
                    first_row_fileview = first_row_fileview - 1;
                    if (first_row_fileview < 0) first_row_fileview = 0;
                    refresh_screen(t,false);
                }
                else if (c == NCKey::Down)
                {
                    first_row_fileview = first_row_fileview + 1;
                    if (first_row_fileview > vfilerows.size() - (nrows - 0))
                        first_row_fileview = vfilerows.size() - (nrows - 0);
                    refresh_screen(t,false);
                }
            }
        }
        else if (_mode == 3)
        {
            if (vusrrows.size() > (nrows - 0))
            {
                if (c == NCKey::PgUp)
                {
                    first_row_usr_view = first_row_usr_view - (nrows - 0);
                    if (first_row_usr_view < 0) first_row_usr_view = 0;
                    refresh_screen(t,false);
                }
                else if (c == NCKey::PgDown)
                {
                    first_row_usr_view = first_row_usr_view + (nrows - 0);
                    if (first_row_usr_view > vusrrows.size() - (nrows - 0))
                        first_row_usr_view = vusrrows.size() - (nrows - 0);
                    refresh_screen(t,false);
                }
            }

            if (c == NCKey::Up)
            {
                if (cursor_usr_y == 0)
                {
                    first_row_usr_view = first_row_usr_view - 1;
                    if (first_row_usr_view < 0) first_row_usr_view = 0;
                }
                else
                {
                    cursor_usr_y--;
                }
                refresh_screen(t,false);
            }
            else if (c == NCKey::Down)
            {
                if (cursor_usr_y == (nrows - 0) - 1)
                {
                    if (vallrows.size() > (nrows - 0))
                    {
                        first_row_usr_view = first_row_usr_view + 1;
                        if (first_row_usr_view > vusrrows.size() - (nrows - 0))
                            first_row_usr_view = vusrrows.size() - (nrows - 0);
                    }
                }
                else
                {
                    cursor_usr_y++;
                }
                refresh_screen(t,false);
            }
        }
    }
}

void ClientTerm1::draw_history(struct ncplane* p, std::string& ab, std::vector<std::vector<row_segment>>& abrows, bool is_dirty)
{
    uint64_t panel_color = ncplane_channels(p);
    uint64_t text_color;

    // File view
    if (_mode==1)
    {
        if (is_dirty)
        {
            vfilerows.clear();
            file_view_filename_key = {};

            bool is_msgfile = false;
            int row_cursor = first_row + cursor_y;
            if (row_cursor < vallrows_is_file.size() && row_cursor >= 0)
            {
                if (vallrows_is_file[row_cursor] == 1)
                {
                    is_msgfile = true;
                }
            }

            if (is_msgfile)
            {
                std::string filename_key = vallrows_filename_key[row_cursor];
                size_t byte_processed;
                size_t total_size = 1;
                bool is_done;

                file_view_filename_key = filename_key;

                if (filename_key.size() > 0)
                {
                    bool r;
                    if (vallrows_is_send[row_cursor])
                        r = netw_client->get_info_file_to_send(filename_key, byte_processed, total_size, is_done);
                    else
                        r = netw_client->get_info_file_to_recv(filename_key, byte_processed, total_size, is_done);

                    if (r)
                    {
                        if (is_done)
                        {
                            std::string s;
                            if (vallrows_is_send[row_cursor])
                                s = netw_client->get_file_to_send(filename_key);
                            else
                                s = netw_client->get_file_to_recv(filename_key);

                            if (s.size() > 0)
                            {
                                vfilerows = NETW_MSG::split(s, "\n");
                            }
                        }
                    }
                }
            }
        }

        if (vfilerows.size() == 0)
        {
            first_row_fileview = 0;
            ab.append("No file to show (move cursor to a file send or recv)");
            ab.append(Term::erase_to_eol());
            ab.append("\r\n");

            for (int i = 1; i < nrows - 0; i++)
            {
                ab.append(" ");
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");
            }
            return;
        }

        {
            // shows nrows - 0 at most
            // first row is at n_rows - nrows + 0
            int cnt = 0;
            int n_total_rows = vfilerows.size();

            if (is_dirty)
            {
                first_row_fileview = n_total_rows - (nrows - 0);
                if (first_row_fileview < 0) first_row_fileview = 0;
            }

            for (int i = first_row_fileview; i < (int)vfilerows.size(); i++)
            {
                ab.append("[" + std::to_string(i) + "]: ");
                ab.append(get_printable_string(vfilerows[i]));
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");
                cnt++;

                if (cnt >= nrows - 0)
                    break;
            }

            for (int i = cnt; i < nrows - 0; i++)
            {
                ab.append(" ");
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");
            }
        }
        return;
    }

    // Log view
    else if (_mode==2)
    {
        if (is_dirty)
        {
            vlogrows.clear();
            std::string log_str = main_global::get_log_string();
            vlogrows = NETW_MSG::split(log_str, "\n");

            if (vlogrows.size() == 0)
            {
                first_row_log_view = 0;
                ab.append("Log is empty");
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");

                for (int i = 1; i < nrows - 0; i++)
                {
                    ab.append(" ");
                    ab.append(Term::erase_to_eol());
                    ab.append("\r\n");
                }
                return;
            }
        }

        {
            // shows nrows - 0 at most
            // first row is at n_rows - nrows + 0
            int cnt = 0;
            int n_total_rows = vlogrows.size();

            if (is_dirty)
            {
                first_row_log_view = n_total_rows - (nrows - 0);
                if (first_row_log_view < 0) first_row_log_view = 0;
            }

            for (int i = first_row_log_view; i < (int)vlogrows.size(); i++)
            {
                ab.append("[" + std::to_string(i) + "]: ");
                ab.append(get_printable_string(vlogrows[i]));
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");
                cnt++;

                if (cnt >= nrows - 0)
                    break;
            }

            for (int i = cnt; i < nrows - 0; i++)
            {
                ab.append(" ");
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");
            }
        }

        return;
    }

    // User view
    else if (_mode==3)
    {
        if (is_dirty)
        {
            vusrrows.clear();
            auto vh = netw_client->map_user_index_to_user;

            // fill vh[i].vmsg_extra
            for (auto& e : vh)
            {
                std::string s;
                s = " index: " + std::to_string(e.first) +
                    ", username: " + e.second.usr +
                    ", hostname: " + e.second.host ;
                vusrrows.push_back(s);
            }

            if (vusrrows.size() == 0)
            {
                first_row_usr_view = 0;
                ab.append("User list is empty");
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");

                for (int i = 1; i < nrows - 0; i++)
                {
                    ab.append(" ");
                    ab.append(Term::erase_to_eol());
                    ab.append("\r\n");
                }
                return;
            }
        }

        {
            // shows nrows - 0 at most
            // first row is at n_rows - nrows + 0
            int cnt = 0;
            int n_total_rows = vusrrows.size();

            if (is_dirty)
            {
                first_row_usr_view = n_total_rows - (nrows - 0);
                if (first_row_usr_view < 0) first_row_usr_view = 0;
            }

            for (int i = first_row_usr_view; i < (int)vusrrows.size(); i++)
            {
                if (cursor_usr_y == cnt)
                    ab.append("*[" + std::to_string(i) + "]: ");
                else
                    ab.append(" [" + std::to_string(i) + "]: ");

                ab.append(get_printable_string(vusrrows[i]));
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");
                cnt++;

                if (cnt >= nrows - 0)
                    break;
            }

            for (int i = cnt; i < nrows - 0; i++)
            {
                if (cursor_usr_y == cnt)
                    ab.append("*");
                else
                    ab.append(" ");
                ab.append(Term::erase_to_eol());
                ab.append("\r\n");
                cnt++;
            }
        }

        return;
    }

    // Chat view
    else if (_mode == 0)
    {
        if (is_dirty)
        {
            size_t histo_cnt;
            auto vh = netw_client->get_vhistory(histo_cnt); // get a copy since multi thread ressource

            // fill vh[i].vmsg_extra
            for (int i = 0; i < (int)vh.size(); i++)
            {
                if (vh[i].msg_type == NETW_MSG::MSG_FILE)
                {
                    if (vh[i].is_for_display && vh[i].vmsg_extra.size() == 0)
                    {
                        size_t byte_processed;
                        size_t total_size = 1;
                        bool is_done;

                        if (vh[i].is_receive == false)
                        {
                            bool r = netw_client->get_info_file_to_send(vh[i].filename_key, byte_processed, total_size, is_done);
                            if (r)
                            {
                                if (is_done && vh[i].vmsg_extra.size() == 0)
                                {
                                    std::string s = netw_client->get_file_to_send(vh[i].filename_key);
                                    if (s.size() > 0)
                                    {
                                        vh[i].vmsg_extra = NETW_MSG::split(s, "\n");
                                    }
                                }
                            }
                        }
                        else
                        {
                            bool r = netw_client->get_info_file_to_recv(vh[i].filename_key, byte_processed, total_size, is_done);
                            if (r)
                            {
                                if (is_done && vh[i].vmsg_extra.size() == 0)
                                {
                                    std::string s = netw_client->get_file_to_recv(vh[i].filename_key);
                                    if (s.size() > 0)
                                    {
                                        vh[i].vmsg_extra = NETW_MSG::split(s, "\n");
                                    }
                                }
                            }
                        }
                    }
                }
            }

            //int row_cursor = first_row + cursor_y;
            vallrows.clear();
            vrows.clear();
            vallrows_is_file.clear();
            vallrows_is_send.clear();
            vallrows_filename_key.clear();

            char is_file_line;
            bool is_file_send;
            std::string filename_key;

            for (int i = 0; i < (int)vh.size(); i++)
            {
                std::string work;
                {
                    std::vector<std::string> vlines = NETW_MSG::split(vh[i].msg, "\r\n");

                    // only consider first line...
                    for (size_t j = 0; j < 1; j++)
                    {
                        work.append(std::to_string(histo_cnt - vh.size() + i + 1));
                        work.append(" ");

                        if (vh[i].is_receive)
                        {
                            std::string user;
                            std::string fromuser_nonzero;
                            fromuser_nonzero = std::to_string(vh[i].from_user);
                            if (vh[i].from_user == 0) fromuser_nonzero = "srv";

                            if (netw_client->map_user_index_to_user.contains(vh[i].from_user))
                                user = netw_client->map_user_index_to_user[vh[i].from_user].usr;

                            if (user.empty())
                                work.append("recv (from: " + fromuser_nonzero + ")" + "      ");
                            else
                                work.append("recv (from: " + fromuser_nonzero + ")[" + user + "]      ");
                        }
                        else
                        {
                            std::string user;
                            std::string to_user_nonzero;
                            to_user_nonzero = std::to_string(vh[i].to_user);
                            if (vh[i].to_user == 0) to_user_nonzero = "all";

                            if (netw_client->map_user_index_to_user.contains(vh[i].to_user))
                                user = netw_client->map_user_index_to_user[vh[i].to_user].usr;

                            if (user.empty())
                                work.append("send (to: " + to_user_nonzero + ")");
                            else
                               work.append("send (to: " + to_user_nonzero + ")[" + user + "]");
                        }
                        work.append(": ");

                        std::string sl;
                        if (vh[i].msg_type != NETW_MSG::MSG_FILE)
                        {
                            is_file_line = false;
                            sl = get_printable_string(vlines[j]);
                            filename_key = {};
                            is_file_send = !vh[i].is_receive;
                        }
                        else
                        {
                            sl = get_printable_string(vh[i].filename);
                            is_file_line = true;
                            is_file_send = !vh[i].is_receive;
                            filename_key = vh[i].filename_key;
                        }

                        if (vh[i].msg_type == NETW_MSG::MSG_FILE)
                        {
                            size_t byte_processed;
                            size_t total_size = 1;
                            bool is_done;
                            float percent = 0;
                            float fbyte_processed;
                            float ftotal_size;

                            if (vh[i].is_receive == false)
                            {
                                bool r = netw_client->get_info_file_to_send(vh[i].filename_key, byte_processed, total_size, is_done);
                                if (r)
                                {
                                    fbyte_processed = byte_processed;
                                    ftotal_size = total_size;

                                    if (total_size > 0)
                                        if (byte_processed <= total_size)
                                            percent = fbyte_processed / ftotal_size;
                                }
                            }
                            else
                            {
                                bool r = netw_client->get_info_file_to_recv(vh[i].filename_key, byte_processed, total_size, is_done);
                                if (r)
                                {
                                    fbyte_processed = byte_processed;
                                    ftotal_size = total_size;

                                    if (total_size > 0)
                                        if (byte_processed <= total_size)
                                            percent = fbyte_processed / ftotal_size;
                                }
                            }

                            if (vh[i].is_receive == true)
                                text_color = (uint64_t)to_uint32_t(enumcolor::yellow) << 32u | ncchannels_fchannel(panel_color);
                            else
                                text_color = (uint64_t)to_uint32_t(enumcolor::white) << 32u | ncchannels_fchannel(panel_color);

                            std::string ss;
                            int ipercent = (int)(100 * percent);

                            if (vh[i].is_for_display) ss += "<<" + sl + ">>";
                            else ss += "[[" + sl + "]]";

                            ss += "[" + std::to_string(ipercent) + "%] size=" + std::to_string(total_size) + "";

                            if (vh[i].is_for_display) ss += " Lines=" + std::to_string(vh[i].vmsg_extra.size());
                            else ss += " ";
                            
                            if (vh[i].filename_mediaviewer.empty() == false)
                            {
								ss += ", mediaviewer_file=[" + vh[i].filename_mediaviewer + "]";
							}

                            work.append(ss); // ncols ...
                        }
                        else
                        {
                            if (vh[i].is_receive == true)
                                text_color = (uint64_t)to_uint32_t(enumcolor::yellow) << 32u | ncchannels_fchannel(panel_color);
                            else
                                text_color = (uint64_t)to_uint32_t(enumcolor::white) << 32u | ncchannels_fchannel(panel_color);

                            work.append(sl); // ncols ...
                        }
                    }

                    vallrows.push_back(work);
                    {
                        std::vector<row_segment> arow  = { row_segment{text_color, work} };
                        vrows.push_back(arow);
                    }
                    vallrows_is_file.push_back(is_file_line);
                    vallrows_filename_key.push_back(filename_key);
                    vallrows_is_send.push_back(is_file_send);

                    for (size_t j = 0; j < vh[i].vmsg_extra.size(); j++)
                    {
                        work.clear();
                        is_file_line = true;
                        is_file_send = !vh[i].is_receive;
                        filename_key = vh[i].filename_key;

                        if (j < MAX_EXTRA_LINE_TO_DISPLAY_FOR_FILE - 1)
                        {
                            {
                                work.append(std::to_string(histo_cnt - vh.size() + i + 1));
                                work.append(" ");

                                if (vh[i].is_receive == true)
                                    text_color = (uint64_t)to_uint32_t(enumcolor::yellow) << 32u | ncchannels_fchannel(panel_color);
                                else
                                    text_color = (uint64_t)to_uint32_t(enumcolor::white) << 32u | ncchannels_fchannel(panel_color);

                                work.append(vh[i].is_receive ? "< " : "> ");
                                work.append(": ");
                                std::string sl = get_printable_string(vh[i].vmsg_extra[j]);
                                work.append(sl); // ncols ...

                                vallrows.push_back(work);
                                {
                                    std::vector<row_segment> arow  = { row_segment{text_color, work} };
                                    vrows.push_back(arow);
                                }
                                vallrows_is_file.push_back(is_file_line);
                                vallrows_is_send.push_back(is_file_send);
                                vallrows_filename_key.push_back(filename_key);
                            }
                        }
                        else if (j == MAX_EXTRA_LINE_TO_DISPLAY_FOR_FILE - 1)
                        {
                            {
                                work.append(std::to_string(histo_cnt - vh.size() + i + 1));
                                work.append(" ");

                                if (vh[i].is_receive == true)
                                    text_color = (uint64_t)to_uint32_t(enumcolor::yellow) << 32u | ncchannels_fchannel(panel_color);
                                else
                                    text_color = (uint64_t)to_uint32_t(enumcolor::white) << 32u | ncchannels_fchannel(panel_color);

                                work.append(vh[i].is_receive ? "< " : "> ");
                                work.append(": ");
                                std::string sl = "..................";
                                work.append(sl); // ncols ...

                                vallrows.push_back(work);
                                {
                                    std::vector<row_segment> arow  = { row_segment{text_color, work} };
                                    vrows.push_back(arow);
                                }
                                vallrows_is_file.push_back(is_file_line);
                                vallrows_is_send.push_back(is_file_send);
                                vallrows_filename_key.push_back(filename_key);
                            }
                        }
                    }
                }
            }
        }

        // shows nrows - 0 at most
        // first row is at n_rows - nrows + 0
        int cnt = 0;
        int n_total_rows = vallrows.size();

        if (is_dirty)
        {
            first_row = n_total_rows - (nrows - 0);
            if (first_row < 0) first_row = 0;
        }

        // check is_file_view_dirty
        {
            int row_cursor = first_row + cursor_y;
            if (row_cursor >= 0 && row_cursor < vallrows_filename_key.size())
            {
                if (vallrows_is_file[row_cursor] == false)
                {
                    is_file_view_dirty = true;
                }
                else if (vallrows_filename_key[row_cursor] != file_view_filename_key)
                {
                    is_file_view_dirty = true;
                }
            }
        }

        for (int i = first_row; i < (int)vallrows.size(); i++)
        {
            ab.append(vallrows[i]);
            abrows.push_back(vrows[i]);

            ab.append(Term::erase_to_eol());
            ab.append("\r\n");
            cnt++;

            if (cnt >= nrows - 0)
                break;
        }

        for (int i = cnt; i < nrows - 0; i++)
        {
            ab.append(" ");
            ab.append(Term::erase_to_eol());
            ab.append("\r\n");
            {
                std::vector<row_segment> arow  = { row_segment{panel_color, " "} };
                abrows.push_back(arow);
            }
            cnt++;
        }
    }
}

void ClientTerm1::draw_status_msg(std::string& ab)
{
    ab.append(Term::erase_to_eol());
    ab.append("Status: ");

    ab.append(status_msg);
    ab.append("\r\n");
}

void ClientTerm1::refresh_screen(struct ncplane* p, bool is_dirty)
{
    if (p != nullptr)
    {
      unsigned rrows, rcols;
      ncplane_dim_yx(p, &rrows, &rcols);
      nrows = (int)rrows;
      ncols = (int)rcols;
    }

    std::string ab;
    std::vector<std::vector<row_segment>> abrows;
    if (nrows*ncols > 8*1024)
    {
        ab.reserve(nrows*ncols*2);
    }
    else
        ab.reserve(16 * 1024);

    // ...
    status_msg.clear();

    if (_mode==0)
    {
        if (netw_client->cryto_on)
            status_msg += "[Extra Cryto ON (F3)]" ;
        else
            status_msg += "[Extra Cryto OFF (F3)]";

        if (netw_client->chat_with_other_user_index == 0)
            status_msg += "[Chatting with ALL]";
        else
        {
            status_msg += "[Chatting with index: " + std::to_string(netw_client->chat_with_other_user_index) + " (F4)]";
            for (auto&e : netw_client->map_user_index_to_user)
            {
                if (e.first == netw_client->chat_with_other_user_index)
                {
                    status_msg += "[username= " + e.second.usr  + "]";
                    break;
                }
            }
        }
        status_msg += " - ";
        status_msg += "[my index= " + std::to_string(netw_client->my_user_index) + "]";
        status_msg += "[my username= " + netw_client->username + "]";
    }
    else
    {
        if (netw_client->chat_with_other_user_index == 0)
            status_msg += "[Chatting with ALL]";
        else
            status_msg += "[Chatting with index: " + std::to_string(netw_client->chat_with_other_user_index) + " (F4)]";
        status_msg += " - ";
        status_msg += "[my index= " + std::to_string(netw_client->my_user_index) + "]";
        status_msg += "[my username= " + netw_client->username + "]";
    }

    draw_history(p, ab, abrows, is_dirty);

    // tab plane
    if (p != nullptr)
    {
        ncplane_erase(p);

        if (_mode != 0)
        {
            std::vector<std::string> vlines = NETW_MSG::split(ab, "\r\n");
            for(size_t i=0;i<vlines.size();i++)
            {
                ncplane_putstr_yx(p, 0+i, 0, vlines[i].c_str());
            }
        }

        else if (_mode == 0)
        {
            uint64_t panel_color = ncplane_channels(p);
            int cnt=0;
            std::string s;
            for(size_t i=0;i<abrows.size();i++)
            {
                ncplane_set_channels(p, abrows[i].at(0).channels);

                if (cnt == cursor_y)
                {
                    s = "*" + abrows[i].at(0).s;
                }
                else
                    s = " " + abrows[i].at(0).s;

                ncplane_putstr_yx(p, 0+i, 0, s.c_str());
                cnt++;
            }
            ncplane_set_channels(p, panel_color);
        }
    }

    // status plane
    sstatus.clear();
    sstatus.append("Status: ");
    sstatus.append(status_msg);

    if (status_plane != nullptr)
    {
        ncplane_erase(status_plane);
        ncplane_puttext(status_plane, 0, NCALIGN_LEFT, sstatus.c_str(), NULL);
    }

    // input plane
    // ...
}

void ClientTerm1::process_prompt(char* e, bool auto_ui)
{
    ClientTerm1& ct = *this;
    if (e != NULL && _mode==0)
    {
        bool is_txtfile_send_cmd = false;
        bool is_binfile_send_cmd = false;
        std::string message = std::string(e, strlen(e));

        std::string filename;
        std::string filename_key;

        if (ct.is_file_command(message))
        {
            filename = ct.file_from_command(message);
            if (filename == "*")
            {
                filename = ct.netw_client->_cfg_cli.default_txt_filename;
            }

            try
            {
                // TEST
                //filename = "/home/allaptop/dev/CryptoChat/lnx_chatcli/bin/Debug/f.txt";

                if (!filename.empty() && file_util::fileexists(filename))
                {
                    filename_key = filename + std::to_string(ct.netw_client->file_counter);
                    ct.netw_client->file_counter++;
                    bool r = ct.netw_client->add_file_to_send(filename, filename_key);
                    if (r)
                    {
                        is_txtfile_send_cmd = true;
                        message = "[" + filename + "," + filename_key + ",1]";
                    }
                }
                else
                {
                    std::stringstream ss;
                    ss << "WARNING - File do not exist: " << filename << std::endl;
                    main_global::log(ss.str());
                    ss.str({});
                }
            }
            catch (...)
            {
                std::stringstream ss;
                ss << "WARNING - Invalid file: " << filename << std::endl;
                main_global::log(ss.str());
                ss.str({});
            }
        }
        else if (ct.is_binfile_command(message))
        {
            filename = ct.file_from_command(message);
            if (filename == "*")
            {
                filename = ct.netw_client->_cfg_cli.default_bin_filename;
            }

            try
            {
                if (!filename.empty() && file_util::fileexists(filename))
                {
                    filename_key = filename + std::to_string(ct.netw_client->file_counter);
                    ct.netw_client->file_counter++;
                    bool r = ct.netw_client->add_file_to_send(filename, filename_key);
                    if (r)
                    {
                        is_binfile_send_cmd = true;
                        message = "[" + filename + "," + filename_key + ",0]";
                    }
                }
                else
                {
                    std::stringstream ss;
                    ss << "WARNING - File do not exist: " << filename << std::endl;
                    main_global::log(ss.str());
                    ss.str({});
                }
            }
            catch (...)
            {
                std::stringstream ss;
                ss << "WARNING - Invalid file: " << filename << std::endl;
                main_global::log(ss.str());
                ss.str({});
            }
        }

        if (is_binfile_send_cmd || is_txtfile_send_cmd)
        {
            if (message.size() > 0)
            {
                std::string key;
                key = ct.netw_client->get_key();

                NETW_MSG::MSG m;
                m.make_msg(NETW_MSG::MSG_FILE, message, key);

                uint8_t crypto_flag = (ct.netw_client->cryto_on == true) ? 1 : 0;
                if (ct.netw_client->chat_with_other_user_index == 0) crypto_flag = 0;

                std::stringstream ss;
                ss << "send MSG_FILE : " << filename << std::endl;
                main_global::log(ss.str());ss.str({});
                int ret = ct.netw_client->send_message_buffer(  ct.netw_client->get_socket(), m, key,
                                                                crypto_flag,
                                                                ct.netw_client->my_user_index,
                                                                ct.netw_client->chat_with_other_user_index);

                if (ret != -1)
                {
                    ct.netw_client->add_to_history(false, crypto_flag, ct.netw_client->my_user_index, ct.netw_client->chat_with_other_user_index,
                                                    NETW_MSG::MSG_FILE, message, filename, filename_key, is_txtfile_send_cmd);
                    ct.netw_client->set_ui_dirty();
                }
                else
                {
                    ss << "WARNING - send MSG_FILE Failed : " << filename << std::endl;
                }
                main_global::log(ss.str());ss.str({});
            }
        }
        else
        {
            if (message.size() > 0)
            {
                std::string key;
                key = ct.netw_client->get_key();

                NETW_MSG::MSG m;
                m.make_msg(NETW_MSG::MSG_TEXT, message, key);

                uint8_t crypto_flag = (ct.netw_client->cryto_on == true) ? 1 : 0;
                if (ct.netw_client->chat_with_other_user_index == 0) crypto_flag = 0;

                std::stringstream ss;
                ss << "send MSG_TEXT : " << "..." << std::endl;
                main_global::log(ss.str());ss.str({});
                int ret = ct.netw_client->send_message_buffer(  ct.netw_client->get_socket(), m, key,
                                                                crypto_flag,
                                                                ct.netw_client->my_user_index,
                                                                ct.netw_client->chat_with_other_user_index);
                if (ret != -1)
                {
                    ct.netw_client->add_to_history( false, crypto_flag, ct.netw_client->my_user_index, ct.netw_client->chat_with_other_user_index,
                                                    NETW_MSG::MSG_TEXT, message);
                    ct.netw_client->set_ui_dirty();
                }
                else
                {
                    ss << "WARNING - send MSG_TEXT Failed : " << filename << std::endl;
                }
                main_global::log(ss.str());
                ss.str({});
            }
        }
    }
}


int main_client_ui1(crypto_socket::crypto_client* netwclient, bool auto_ui = false)
{
    // No re-entry
    static int count_entry = 0;
    count_entry++;
    if (count_entry > 1) return -1;

    int ret_loop_iter = 0;
    try
    {
        //-------------------------------------
        // TERMINAL interface
        //-------------------------------------
        ClientTerm1 _ct;
        _ct.netw_client = netwclient;

        {
            if(setlocale(LC_ALL, "") == nullptr)
            {
              std::cerr << "error setlocale(LC_ALL)" << std::endl;
              return -1;
            }

            int r = _ct.term_init();
            if (r < 0)
            {
                std::cerr << "error terminal init " << std::endl;
                return -1;
            }
            _ct.get_term_size_tabbed_plane(_ct.nrows, _ct.ncols);
        }

        bool on = true;
        while (on)
        {
            if (netwclient->is_got_chat_cli_signal())
            {
                std::stringstream ss;
                ss << "Terminating thread client_UI" << std::endl;
                main_global::log(ss.str(), true);
                ss.str({});

                //delete ct;
                on = false;
                break;
            }

            //------------------------------
            // loop_iter
            // process_xyz() are being fired
            //------------------------------
            ret_loop_iter = _ct.loop_iter(false);

            if (ret_loop_iter < 0)
            {
                on = false;

                // user exit
                _ct.destroy();
                if(notcurses_stop(_ct.nc) < 0)
                {
                  std::cerr << "notcurses_stop failed" << std::endl;
                }
                _ct.nc = nullptr;
                break;
            }
        }
    }
    catch(const std::runtime_error& re)
    {
        std::stringstream ss;
        ss << "Runtime error main_client_ui: " << re.what() << std::endl;
        main_global::log(ss.str(),true);
        ss.str({});
        return 2;
    }
    catch(...)
    {
        std::stringstream ss;
        ss << "Unknown error exception main_client_ui" << std::endl;
        main_global::log(ss.str(),true);
        ss.str({});
        return 1;
    }
    return 0;
}
