/*
 * Author: Alain Lanthier
 */
#ifndef CLIENT_TERM_HPP_INCLUDED
#define CLIENT_TERM_HPP_INCLUDED

#include "../include/nc_terminal.hpp"

#include "../include/crypto_const.hpp"
#include "../include/terminal.h"
#include "../include/crypto_client.hpp"
#include "../include/data.hpp"
#include "../include/string_util.hpp"
#include "../include/file_util.hpp"
#include "../include/main_global.hpp"
#include <stdarg.h>

using Term::Terminal;
using Term::fg;
using Term::bg;
using Term::style;
using Term::Key;

class ClientTerm1 : public nc_terminal
{
public:
    const int MAX_EXTRA_LINE_TO_DISPLAY_FOR_FILE = 10;
    crypto_socket::crypto_client* netw_client = nullptr;

    // tab plane size
    int nrows;
    int ncols;

    int first_row = 0;              // first row to display for vallrows
    int first_row_fileview = 0;     // first row to display for vfilerows
    int first_row_log_view = 0;     // first row to display for vlogrows
    int first_row_usr_view = 0;
    std::vector<std::string> vallrows;      // chat view
    std::vector<std::string> vfilerows;     // file view
    std::vector<std::string> vlogrows;      // log view
    std::vector<std::string> vusrrows;      // usr view

    std::vector<std::vector<row_segment>> vrows;

    std::vector<char> vallrows_is_file;
    std::vector<char> vallrows_is_send;
    std::vector<std::string> vallrows_filename_key;

    bool is_file_view_dirty = true;
    std::string file_view_filename_key;

    std::string status_msg;

    int _mode = 0; // 0 = chat view, 1 = file view, 2 = log view, 3=User view

    // chat view cursor position in screen
    int cursor_x=0;
    int cursor_y=0;

    // user view cursor position in screen
    int cursor_usr_x = 0;
    int cursor_usr_y = 0;

    std::chrono::steady_clock::time_point tbegin;

    ClientTerm1();
    ~ClientTerm1() {}

    bool is_file_command(const std::string& m);
    bool is_binfile_command(const std::string& m);

    std::string file_from_command(const std::string& m);
    std::string read_file(const std::string& fname, std::stringstream* serr = nullptr);

    void add_to_history(bool is_receive, bool crypto, uint32_t from_user, uint32_t to_user, uint8_t msg_type, std::string& msg,
                        std::string filename, std::string filename_key, bool is_for_display);

    std::string get_printable_string(const std::string& line);

    void draw_history(struct ncplane* p, std::string& ab, std::vector<std::vector<row_segment>>& abrows, bool is_dirty = true);
    void draw_status_msg(std::string& ab);

    void refresh_screen(struct ncplane* p, bool is_dirty = true);

    void process_prompt(char* e, bool auto_ui = false);

    // virtual
    bool is_client_dirty() override ;
    void reset_is_dirty()  override ;

    void process_FKey(char32_t k) override;
	void process_enter() override;
	void process_tab_changes(const char* tname, struct nctab* t, struct ncplane* p) override;
	void process_move_keys_in_tab_plane(const char32_t c) override;
};


#endif // CLIENT_TERM_HPP_INCLUDED
