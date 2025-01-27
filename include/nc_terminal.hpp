/*
 * Author: Alain Lanthier
 */

#ifndef _nc_terminal_hpp_
#define _nc_terminal_hpp_

#include <memory>
#include <unistd.h>
#include <cstdlib>
#include <clocale>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <mutex>
#include <vector>
#include "../include/nc_key.hpp"
#include "../../notcurses/include/notcurses/notcurses.h"

static void tabcbfn(struct nctab* t, struct ncplane* p, void* curry);


 enum class enumcolor {
    black = 30,
    red = 31,
    green = 32,
    yellow = 33,
    blue = 34,
    magenta = 35,
    cyan = 36,
    gray = 37,
    white = 38
};

static void enumcolor_to_rgb(enumcolor f, uint8_t&r, uint8_t&g, uint8_t&b)
{
    if (f == enumcolor::black)       {r=0;g=0;b=0;}
    else if (f == enumcolor::red)    {r=255;g=0;b=0;}
    else if (f == enumcolor::green)  {r=0;g=255;b=0;}
    else if (f == enumcolor::yellow) {r=255;g=255;b=0;}
    else if (f == enumcolor::blue)   {r=0;g=0;b=255;}
    else if (f == enumcolor::magenta){r=255;g=0;b=255;}
    else if (f == enumcolor::cyan)   {r=0;g=255;b=255;}
    else if (f == enumcolor::gray)   {r=128;g=128;b=128;}
    else if (f == enumcolor::white)  {r=255;g=255;b=255;}
}
static uint64_t fg_bg(enumcolor f, enumcolor b)
{
    uint8_t fr, fg, fb, br, bg, bb;
    enumcolor_to_rgb(f, fr, fg, fb);
    enumcolor_to_rgb(b, br, bg, bb);
    return NCCHANNELS_INITIALIZER(fr, fg, fb, br, bg, bb);
}
static uint32_t to_uint32_t(enumcolor f)
{
    uint8_t fr, fg, fb;
    enumcolor_to_rgb(f, fr, fg, fb);
    return NCCHANNEL_INITIALIZER(fr, fg, fb);
}

struct row_segment
{
    uint64_t channels;
    std::string s;
};
// a row is std::vector<row_segment> vseg;

class nc_terminal
{
public:
	std::string sinput;
	std::mutex mtx;
	static unsigned dimy, dimx;
	bool nomice = false;

	struct notcurses* nc  = nullptr;
	bool bottom = false;

	unsigned rows, cols;
	struct ncplane* stdp = nullptr;	// standard main plane
	struct ncplane_options popts;

	struct ncplane* ncp = nullptr;	// tabbed plane
	struct nctabbed_options topts;
	struct nctabbed* nct = nullptr;	// tabs info linked list

	struct ncplane* input_plane = nullptr;// input plane
	struct ncplane* input_plane_inner = nullptr;// input plane inner
	struct ncplane_options iopts;

	struct ncplane* reader_plane = nullptr;
	struct ncreader* nc_reader = nullptr;

	struct ncplane* status_plane = nullptr; // status plane
	struct ncplane_options sopts;
	std::string sstatus = "status";

	bool is_notcurses_stopped();

	nc_terminal();
	virtual ~nc_terminal();

	void destroy();

    void get_term_size_tabbed_plane(unsigned* r, unsigned* c);
    void get_term_size_tabbed_plane(int& r, int& c);
    void tabcb(struct nctab* t, struct ncplane* p);

    void status_redraw();
    void input_redraw();

    int reset_main_plane();
    int reset_input_plane();
    int reset_status_plane();
    int reset_tabbed();

    void create_resize(bool is_resize);

    int term_init();

	char evtype_to_char(ncinput* ni);
	char32_t printutf8(char32_t kp);

	// virtual
	virtual bool is_client_dirty() {return false;}
	virtual void reset_is_dirty() {}

	virtual void process_FKey(char32_t k) {}
	virtual void process_enter() {}
	virtual void process_tab_changes(const char* tname, struct nctab* t, struct ncplane* p) {}
	virtual void process_move_keys_in_tab_plane(const char32_t c) {}

	void show_char(char32_t r, ncinput& ni);

	int loop();
	int loop_iter(bool blocking_ui = false);
};

int test_main(int , char** );

// the callback draws the tab contents
void tabcbfn(struct nctab* t, struct ncplane* p, void* curry);

#endif

