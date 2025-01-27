/*
 * Author: Alain Lanthier
 */

#include "../include/nc_terminal.hpp"
#include "../../notcurses/include/notcurses/notcurses.h"

bool nc_terminal::is_notcurses_stopped()
{
  return nc == nullptr;
}

nc_terminal::nc_terminal() {}
nc_terminal::~nc_terminal()
{
    destroy();
}

void nc_terminal::destroy()
{
  if (is_notcurses_stopped ())
    return;

  if (input_plane!=nullptr)
  {
	  ncplane_destroy(input_plane);
	  input_plane = nullptr;
  }
  if (input_plane_inner!=nullptr)
  {
	  ncplane_destroy(input_plane_inner);
	  input_plane_inner = nullptr;
  }
  if (status_plane != nullptr)
  {
	  ncplane_destroy(status_plane);
	  status_plane = nullptr;
  }
  if (nct!=nullptr)
  {
	   nctabbed_destroy(nct);
	   nct = nullptr;
  }
  if (nc_reader!=nullptr)
  {
	   ncreader_destroy(nc_reader, nullptr);
	   nc_reader = nullptr;
  }
}

void nc_terminal::get_term_size_tabbed_plane(unsigned* r, unsigned* c)
{
    ncplane* t = nctabbed_content_plane(nct);
    if (t != nullptr)
        ncplane_dim_yx(t, r, c);
}

void nc_terminal::get_term_size_tabbed_plane(int& r, int& c)
{
    ncplane* t = nctabbed_content_plane(nct);

    if (t != nullptr)
    {
      unsigned rrows, rcols;
      ncplane_dim_yx(t, &rrows, &rcols);
      r = (int)rrows;
      c = (int)rcols;
    }
}

// tab redraw callback
void nc_terminal::tabcb(struct nctab* t, struct ncplane* p)
{
  const char* tname = nctab_name(t);
  process_tab_changes(tname, t, p);
}

void nc_terminal::status_redraw()
{
  if (status_plane == nullptr) return;
  ncplane_erase(status_plane);

  ncplane_puttext(status_plane, 0, NCALIGN_CENTER, sstatus.c_str(), NULL);
  sstatus.clear();
}

void nc_terminal::input_redraw()
{
  // ncreader is over input_plane_inner
  if (input_plane_inner == nullptr) return;
  ncplane_erase(input_plane_inner);
}

int nc_terminal::reset_main_plane()
{
    // How to resize...
    ncplane_erase(stdp);
    //ncplane_puttext(stdp, 0, NCALIGN_CENTER,"Crypto Chat by Alain Lanthier (version 0.001)", NULL);
    return 0;
}

int nc_terminal::reset_input_plane()
{
  if (input_plane!=nullptr)
  {
    ncplane_destroy(input_plane);
    input_plane = nullptr;
  }
  if (input_plane_inner!=nullptr)
  {
    ncplane_destroy(input_plane_inner);
    input_plane_inner = nullptr;
  }
  if (nc_reader!=nullptr)
  {
     ncreader_destroy(nc_reader, nullptr);
     nc_reader = nullptr;
  }

  iopts =
  {
    .y = (((int)rows) >=14) ? 1 + 0 + ((int)rows) - 8 : 7,
    .x = 0,
    .rows = 6,
    .cols = (cols>=40) ? cols : 40
  };
  input_plane = ncplane_create(stdp, &iopts);

  struct ncplane_options sopts_inner =
  {
    .y = (((int)rows) >=14) ? 2 + 0 + ((int)rows)  - 8 : 8,
    .x = 1,
    .rows = 4,
    .cols = (cols>=41) ? cols - 2 : 38
  };
  input_plane_inner = ncplane_create(stdp, &sopts_inner);

  {
    unsigned irows, icols;
    ncplane_dim_yx(input_plane, &irows, &icols);

    nccell c = NCCELL_TRIVIAL_INITIALIZER;
    nccell_set_bg_rgb8(&c, 0x20, 0x20, 0x20);
    ncplane_set_base_cell(input_plane, &c);
    nccell ul = NCCELL_TRIVIAL_INITIALIZER, ur = NCCELL_TRIVIAL_INITIALIZER;
    nccell ll = NCCELL_TRIVIAL_INITIALIZER, lr = NCCELL_TRIVIAL_INITIALIZER;
    nccell hl = NCCELL_TRIVIAL_INITIALIZER, vl = NCCELL_TRIVIAL_INITIALIZER;
    if(nccells_rounded_box(input_plane, NCSTYLE_BOLD, 0, &ul, &ur, &ll, &lr, &hl, &vl))
    {
      std::cerr << "reset_input_plane nccells_rounded_box failed" << std::endl;
      return -1;
    }

    nccell_set_fg_rgb(&ul, 0xff0000); nccell_set_bg_rgb(&ul, 0x002000);
    nccell_set_fg_rgb(&ur, 0x00ff00); nccell_set_bg_rgb(&ur, 0x002000);
    nccell_set_fg_rgb(&ll, 0x0000ff); nccell_set_bg_rgb(&ll, 0x002000);
    nccell_set_fg_rgb(&lr, 0xffffff); nccell_set_bg_rgb(&lr, 0x002000);
    if(ncplane_box_sized(input_plane, &ul, &ur, &ll, &lr, &hl, &vl, irows - 0, icols,
					     NCBOXGRAD_TOP | NCBOXGRAD_BOTTOM | NCBOXGRAD_RIGHT | NCBOXGRAD_LEFT))
    {
        std::cerr << "reset_input_planencplane_box_sized failed" << std::endl;
        return -1;
    }
  }

  ncreader_options reader_opts{};
  bool horscroll = false;
  reader_opts.flags = NCREADER_OPTION_CURSOR | (horscroll ? NCREADER_OPTION_HORSCROLL : 0);

  // can't use Plane until we have move constructor for Reader
  struct ncplane_options nopts = {
	  .y = 0,
	  .x = 0,
	  .rows = 4,
	  .cols = (cols>=41) ? cols - 2 : (unsigned int)38,
	  .userptr = nullptr,
	  .name = "read",
	  .resizecb = nullptr,
	  .flags = 0,
	  .margin_b = 0, .margin_r = 0,
  };
  reader_plane = ncplane_create(input_plane_inner, &nopts);
  ncplane_set_base(reader_plane, "░", 0, 0);
  nc_reader = ncreader_create(reader_plane, &reader_opts);
  if(nc_reader == nullptr)
  {
	  //return EXIT_FAILURE;
  }
  return 0;
}

int nc_terminal::reset_status_plane()
{
  if (status_plane!=nullptr)
  {
	  ncplane_destroy(status_plane);
	  status_plane = nullptr;
  }

  sopts =
  {
	  .y = (((int)rows) >=15) ? 1 + 6 + ((int)rows)  - 8 : 14,
	  .x = 0,
	  .rows = 1,
	  .cols = (cols>=41) ? cols: 40
  };
  status_plane = ncplane_create(stdp, &sopts);
  return 0;
}

int nc_terminal::reset_tabbed()
{
  if (nct!=nullptr)
  {
	   nctabbed_destroy(nct);
	   nct = nullptr;
  }

  popts =
  {
	  .y = 0,
	  .x = 0,
	  .rows = (rows>=14) ? 1 + rows - 8 : (unsigned int)6,
	  .cols = (cols>=40) ? cols  : (unsigned int)40
  };
  ncp = ncplane_create(stdp, &popts);

  topts = {
	  .selchan = NCCHANNELS_INITIALIZER(0, 255, 0, 0, 0, 0),
	  .hdrchan = NCCHANNELS_INITIALIZER(255, 0, 0, 60, 60, 60),
	  .sepchan = NCCHANNELS_INITIALIZER(255, 255, 255, 100, 100, 100),
	  .separator = "][",
	  .flags = bottom ? NCTABBED_OPTION_BOTTOM : 0
  };
  nct = nctabbed_create(ncp, &topts);

  ncplane_set_base(nctabbed_content_plane(nct), " ", 0, NCCHANNELS_INITIALIZER(255, 255, 255, 0, 0, 0));
  if(     nctabbed_add(nct, NULL, NULL, tabcbfn, "Chat", 	(void*)this) == NULL
       || nctabbed_add(nct, NULL, NULL, tabcbfn, "About", 	(void*)this) == NULL
       || nctabbed_add(nct, NULL, NULL, tabcbfn, "Help", 	(void*)this) == NULL
       || nctabbed_add(nct, NULL, NULL, tabcbfn, "Stats", 	(void*)this) == NULL
       //|| nctabbed_add(nct, NULL, NULL, tabcbfn, "Email", 	(void*)this) == NULL
	   //|| nctabbed_add(nct, NULL, NULL, tabcbfn, "Key", 	(void*)this) == NULL
	   || nctabbed_add(nct, NULL, NULL, tabcbfn, "Log", 	(void*)this) == NULL
	   //|| nctabbed_add(nct, NULL, NULL, tabcbfn, "Config",  (void*)this) == NULL
	   || nctabbed_add(nct, NULL, NULL, tabcbfn, "User", 	(void*)this) == NULL
	   || nctabbed_add(nct, NULL, NULL, tabcbfn, "File", 	(void*)this) == NULL)
  {
	  std::cerr << "nctabbed_add failed" << std::endl;
	  return -1;
  }

  return 0;
}

void nc_terminal::create_resize(bool is_resize)
{
    notcurses_term_dim_yx(nc, &rows, &cols);

    //if (is_resize == false)
    {
      reset_main_plane();
      reset_tabbed();
      reset_input_plane();
      reset_status_plane();
      return;
    }
}

int nc_terminal::term_init()
{
  notcurses_options nopts = {0};
  nopts.flags = NCOPTION_INHIBIT_SETLOCALE;

  nc = notcurses_core_init(&nopts, NULL);
  if(!nc)
  {
	  std::cerr << "notcurses_core_init failed" << std::endl;
	  return -2;
  }

  if(!nomice)
  {
	  notcurses_mice_enable (nc, NCMICE_ALL_EVENTS);
  }

  stdp = notcurses_stddim_yx(nc, &rows, &cols);
  create_resize(false);

  nctabbed_redraw(nct);
  input_redraw();
  status_redraw();

  if(notcurses_render(nc) < 0)
  {
	  std::cerr << "notcurses_render failed" << std::endl;
	  return -1;
  }

  return 0;
}

char nc_terminal::evtype_to_char(ncinput* ni)
{
  switch(ni->evtype){
	case EvType::Unknown:
	  return 'u';
	case EvType::Press:
	  return 'P';
	case EvType::Repeat:
	  return 'R';
	case EvType::Release:
	  return 'L';
  }
  return 'X';
}

// Print the utf8 Control Pictures for otherwise unprintable ASCII
char32_t nc_terminal::printutf8(char32_t kp)
{
  if(kp <= NCKEY_ESC){
	return 0x2400 + kp;
  }
  return kp;
}

void nc_terminal::show_char(char32_t r, ncinput& ni)
{
  char buffer[100] = {0};
  char buffer2[100] = {0};
  //char buffer_in[100] = {0};

  if (r == (char32_t)-1)
  {
	  int e = errno;
	  if(e)
	  {
		  std::cerr << "Error reading from terminal (" << strerror(e) << "?)\n";
	  }
	  return;
  }

  //if (r == 0) return; // interrupted by signal

  if (r == NCKEY_ENTER)
  {
	  process_enter();
  }

  sprintf(buffer, "%c%c%c%c%c%c%c%c%c ",
		    ncinput_shift_p(&ni) ? 'S' : 's',
		    ncinput_alt_p(&ni) ? 'A' : 'a',
		    ncinput_ctrl_p(&ni) ? 'C' : 'c',
		    ncinput_super_p(&ni) ? 'U' : 'u',
		    ncinput_hyper_p(&ni) ? 'H' : 'h',
		    ncinput_meta_p(&ni) ? 'M' : 'm',
		    ncinput_capslock_p(&ni) ? 'X' : 'x',
		    ncinput_numlock_p(&ni) ? '#' : '.',
		    evtype_to_char(&ni));

  if(r < 0x80)
  {
    sprintf(buffer2, "ASCII: [0x%02x (%03d)] '%lc'", r, r, (wint_t)(iswprint(r) ? r : printutf8(r))) ;
    strcat(buffer, buffer2);

    // INPUT TEXT
    //sprintf(buffer_in, "%lc", (wint_t)(iswprint(r) ? r : printutf8(r)));
    //sinput.append(buffer_in);
  }
  else
  {
    if (nckey_synthesized_p(r))
    {
	  sprintf(buffer2, "Special: [0x%02x (%02d)] '%s'", r, r, nc_keystr(r));
	  strcat(buffer, buffer2);

	  if(NCKey::IsMouse(r))
	  {
	    sprintf(buffer2, "IsMouse %d/%d", ni.x, ni.y);
	    strcat(buffer, buffer2);
	  }
    }
    else
    {
	  sprintf(buffer2, "Unicode: [0x%08x] '%s'", r, ni.utf8);
	  strcat(buffer, buffer2);
    }
  }

  if(ni.eff_text[0] != ni.id || ni.eff_text[1] != 0)
  {
    sprintf(buffer2, " effective text '");
    strcat(buffer, buffer2);

    for (int c=0; ni.eff_text[c]!=0; c++)
    {
	  unsigned char egc[5]={0};
	  if (notcurses_ucs32_to_utf8(&ni.eff_text[c], 1, egc, 4)>=0)
	  {
	    sprintf(buffer2, "%s", egc);
	    strcat(buffer, buffer2);

	    // INPUT TEXT
	    //sprintf(buffer_in, "%s", egc);
	    //sinput.append(buffer_in);
	  }
    }
    sprintf(buffer2, "'");
    strcat(buffer, buffer2);
  }

  sstatus.append(buffer);
}

int nc_terminal::loop()
{
  bool done = false;
  int ret;

  while(done == false)
  {
    ret = loop_iter(true);
    if (ret < 0)
    {
      destroy();
      if(notcurses_stop(nc) < 0)
      {
          std::cerr << "notcurses_stop failed" << std::endl;
          nc = nullptr;
          return -1;
      }

      nc = nullptr;
      return 0;
    }
  }
  return 0;
}

int nc_terminal::loop_iter(bool blocking_ui)
{
    uint32_t c;
    ncinput ni;

    if (blocking_ui == false)
        c = notcurses_get_nblock(nc, &ni);
    else
        c = notcurses_get_blocking(nc, &ni);

    if (c == 'X' && ncinput_ctrl_p(&ni))
    {
        return -1;
    }

    if (nckey_synthesized_p(c))
    {
        if (c== NCKEY_RESIZE)
        {
            mtx.lock();
            notcurses_refresh (nc, &rows, &cols);
            mtx.unlock();

            create_resize(true);
        }
    }

    if (c != 0)
    {
        if(ni.evtype == NCTYPE_RELEASE)
        {
            return 0;
        }
        if (c == NCKEY_TAB && !ncinput_shift_p(&ni) && !ncinput_ctrl_p(&ni) && !ncinput_alt_p(&ni) )
        {
            nctabbed_next(nct);
        }
        else if (c == NCKEY_TAB && ncinput_shift_p(&ni) )
        {
            nctabbed_prev(nct);
        }
        else if (c == NCKEY_F02)
        {
            nctabbed_next(nct); // tabcbfn() fired
        }
        else if (c == NCKEY_F01)
        {
            nctabbed_prev(nct); // tabcbfn() fired
        }
        else if (c == NCKEY_F03) // toggle crypto
        {
            process_FKey(NCKEY_F03);
        }
        else if (c == NCKEY_F04) // chat with all
        {
            process_FKey(NCKEY_F04);
        }
        else if (c == NCKEY_ENTER)
        {
            process_enter();
        }
        else if (ncinput_shift_p(&ni))
        {
            if (c == NCKey::PgUp || c == NCKey::PgDown || c == NCKey::Up || c == NCKey::Down)
            {
                process_move_keys_in_tab_plane(c);
            }
            else
            {
                // dropped ....
            }
        }
        else if (ncreader_offer_input(nc_reader, &ni))
        {
        }
        else
        {
            // dropped ....
        }
        //show_char(c, ni);
    }

    bool is_dirty = false;
    if (c==0)
    {
        // do we have receibved other suff
        is_dirty = is_client_dirty();
    }

    if ((c != 0) || is_dirty)
    {
        nctabbed_ensure_selected_header_visible(nct);
        nctabbed_redraw(nct);
        input_redraw();
        status_redraw();

        if(notcurses_render(nc) < 0)
        {
          std::cerr << "notcurses_render failed" << std::endl;
          return -1;
        }

        reset_is_dirty();

    }
    else if (blocking_ui == false)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return 0;
}

int test_main(int , char** )
{
  if(setlocale(LC_ALL, "") == nullptr)
  {
	  std::cerr << "error setlocale(LC_ALL)" << std::endl;
	  return EXIT_FAILURE;
  }

  nc_terminal nc_term;

  int r = nc_term.term_init();
  if (r < 0)
  {
	  std::cerr << "error init terminal" << std::endl;
	  return r;
  }
  return nc_term.loop();
}

void tabcbfn(struct nctab* t, struct ncplane* p, void* curry)
{
  nc_terminal* term = reinterpret_cast<nc_terminal*>(curry);
  if (term == nullptr) return;
  term->tabcb(t, p);
}


