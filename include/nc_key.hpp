#ifndef _NCKey_H_
#define _NCKey_H_

#include <memory>
#include <unistd.h>
#include <cstdlib>
#include <clocale>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <thread>
#include <mutex>
#include "../notcurses/include/notcurses/notcurses.h"

struct NCKey
{
	static constexpr char32_t Invalid   = NCKEY_INVALID;
	static constexpr char32_t Resize    = NCKEY_RESIZE;
	static constexpr char32_t Up        = NCKEY_UP;
	static constexpr char32_t Right     = NCKEY_RIGHT;
	static constexpr char32_t Down      = NCKEY_DOWN;
	static constexpr char32_t Left      = NCKEY_LEFT;
	static constexpr char32_t Ins       = NCKEY_INS;
	static constexpr char32_t Del       = NCKEY_DEL;
	static constexpr char32_t Backspace = NCKEY_BACKSPACE;
	static constexpr char32_t PgDown    = NCKEY_PGDOWN;
	static constexpr char32_t PgUp      = NCKEY_PGUP;
	static constexpr char32_t Home      = NCKEY_HOME;
	static constexpr char32_t End       = NCKEY_END;
	static constexpr char32_t F00       = NCKEY_F00;
	static constexpr char32_t F01       = NCKEY_F01;
	static constexpr char32_t F02       = NCKEY_F02;
	static constexpr char32_t F03       = NCKEY_F03;
	static constexpr char32_t F04       = NCKEY_F04;
	static constexpr char32_t F05       = NCKEY_F05;
	static constexpr char32_t F06       = NCKEY_F06;
	static constexpr char32_t F07       = NCKEY_F07;
	static constexpr char32_t F08       = NCKEY_F08;
	static constexpr char32_t F09       = NCKEY_F09;
	static constexpr char32_t F10       = NCKEY_F10;
	static constexpr char32_t F11       = NCKEY_F11;
	static constexpr char32_t F12       = NCKEY_F12;
	static constexpr char32_t F13       = NCKEY_F13;
	static constexpr char32_t F14       = NCKEY_F14;
	static constexpr char32_t F15       = NCKEY_F15;
	static constexpr char32_t F16       = NCKEY_F16;
	static constexpr char32_t F17       = NCKEY_F17;
	static constexpr char32_t F18       = NCKEY_F18;
	static constexpr char32_t F19       = NCKEY_F19;
	static constexpr char32_t F20       = NCKEY_F20;
	static constexpr char32_t F21       = NCKEY_F21;
	static constexpr char32_t F22       = NCKEY_F22;
	static constexpr char32_t F23       = NCKEY_F23;
	static constexpr char32_t F24       = NCKEY_F24;
	static constexpr char32_t F25       = NCKEY_F25;
	static constexpr char32_t F26       = NCKEY_F26;
	static constexpr char32_t F27       = NCKEY_F27;
	static constexpr char32_t F28       = NCKEY_F28;
	static constexpr char32_t F29       = NCKEY_F29;
	static constexpr char32_t F30       = NCKEY_F30;
	static constexpr char32_t F31       = NCKEY_F31;
	static constexpr char32_t F32       = NCKEY_F32;
	static constexpr char32_t F33       = NCKEY_F33;
	static constexpr char32_t F34       = NCKEY_F34;
	static constexpr char32_t F35       = NCKEY_F35;
	static constexpr char32_t F36       = NCKEY_F36;
	static constexpr char32_t F37       = NCKEY_F37;
	static constexpr char32_t F38       = NCKEY_F38;
	static constexpr char32_t F39       = NCKEY_F39;
	static constexpr char32_t F40       = NCKEY_F40;
	static constexpr char32_t F41       = NCKEY_F41;
	static constexpr char32_t F42       = NCKEY_F42;
	static constexpr char32_t F43       = NCKEY_F43;
	static constexpr char32_t F44       = NCKEY_F44;
	static constexpr char32_t F45       = NCKEY_F45;
	static constexpr char32_t F46       = NCKEY_F46;
	static constexpr char32_t F47       = NCKEY_F47;
	static constexpr char32_t F48       = NCKEY_F48;
	static constexpr char32_t F49       = NCKEY_F49;
	static constexpr char32_t F50       = NCKEY_F50;
	static constexpr char32_t F51       = NCKEY_F51;
	static constexpr char32_t F52       = NCKEY_F52;
	static constexpr char32_t F53       = NCKEY_F53;
	static constexpr char32_t F54       = NCKEY_F54;
	static constexpr char32_t F55       = NCKEY_F55;
	static constexpr char32_t F56       = NCKEY_F56;
	static constexpr char32_t F57       = NCKEY_F57;
	static constexpr char32_t F58       = NCKEY_F58;
	static constexpr char32_t F59       = NCKEY_F59;
	static constexpr char32_t F60       = NCKEY_F60;
	static constexpr char32_t Enter     = NCKEY_ENTER;
	static constexpr char32_t CLS       = NCKEY_CLS;
	static constexpr char32_t DLeft     = NCKEY_DLEFT;
	static constexpr char32_t DRight    = NCKEY_DRIGHT;
	static constexpr char32_t ULeft     = NCKEY_ULEFT;
	static constexpr char32_t URight    = NCKEY_URIGHT;
	static constexpr char32_t Center    = NCKEY_CENTER;
	static constexpr char32_t Begin     = NCKEY_BEGIN;
	static constexpr char32_t Cancel    = NCKEY_CANCEL;
	static constexpr char32_t Close     = NCKEY_CLOSE;
	static constexpr char32_t Command   = NCKEY_COMMAND;
	static constexpr char32_t Copy      = NCKEY_COPY;
	static constexpr char32_t Exit      = NCKEY_EXIT;
	static constexpr char32_t Print     = NCKEY_PRINT;
	static constexpr char32_t CapsLock  = NCKEY_CAPS_LOCK;
	static constexpr char32_t ScrollLock= NCKEY_SCROLL_LOCK;
	static constexpr char32_t NumLock   = NCKEY_NUM_LOCK;
	static constexpr char32_t PrintScreen= NCKEY_PRINT_SCREEN;
	static constexpr char32_t Pause     = NCKEY_PAUSE;
	static constexpr char32_t Menu      = NCKEY_MENU;
	static constexpr char32_t Refresh   = NCKEY_REFRESH;
	static constexpr char32_t Button1   = NCKEY_BUTTON1;
	static constexpr char32_t Button2   = NCKEY_BUTTON2;
	static constexpr char32_t Button3   = NCKEY_BUTTON3;
	static constexpr char32_t Button4   = NCKEY_BUTTON4;
	static constexpr char32_t Button5   = NCKEY_BUTTON5;
	static constexpr char32_t Button6   = NCKEY_BUTTON6;
	static constexpr char32_t Button7   = NCKEY_BUTTON7;
	static constexpr char32_t Button8   = NCKEY_BUTTON8;
	static constexpr char32_t Button9   = NCKEY_BUTTON9;
	static constexpr char32_t Button10  = NCKEY_BUTTON10;
	static constexpr char32_t Button11  = NCKEY_BUTTON11;
	static constexpr char32_t ScrollUp  = NCKEY_SCROLL_UP;
	static constexpr char32_t ScrollDown = NCKEY_SCROLL_DOWN;
	static constexpr char32_t Return    = NCKEY_RETURN;

	static bool IsMouse (char32_t ch) noexcept
	{
		return nckey_mouse_p (ch);
	}

	static bool IsSupPUAa (char32_t ch) noexcept
	{
		return nckey_supppuaa_p (ch);
	}

	static bool IsSupPUAb (char32_t ch) noexcept
	{
		return nckey_supppuab_p (ch);
	}
};

struct EvType
{
	static constexpr ncintype_e Unknown = NCTYPE_UNKNOWN;
	static constexpr ncintype_e Press = NCTYPE_PRESS;
	static constexpr ncintype_e Repeat = NCTYPE_REPEAT;
	static constexpr ncintype_e Release = NCTYPE_RELEASE;
};

// return the string version of a special composed key
static const char* nc_keystr(char32_t spkey)
{
  switch(spkey)
  {
    // FIXME
    case NCKEY_RESIZE:  return "resize event";
    case NCKEY_INVALID: return "invalid";
    case NCKEY_LEFT:    return "left";
    case NCKEY_UP:      return "up";
    case NCKEY_RIGHT:   return "right";
    case NCKEY_DOWN:    return "down";
    case NCKEY_INS:     return "insert";
    case NCKEY_DEL:     return "delete";
    case NCKEY_PGDOWN:  return "pgdown";
    case NCKEY_PGUP:    return "pgup";
    case NCKEY_HOME:    return "home";
    case NCKEY_END:     return "end";
    case NCKEY_F00:     return "F0";
    case NCKEY_F01:     return "F1";
    case NCKEY_F02:     return "F2";
    case NCKEY_F03:     return "F3";
    case NCKEY_F04:     return "F4";
    case NCKEY_F05:     return "F5";
    case NCKEY_F06:     return "F6";
    case NCKEY_F07:     return "F7";
    case NCKEY_F08:     return "F8";
    case NCKEY_F09:     return "F9";
    case NCKEY_F10:     return "F10";
    case NCKEY_F11:     return "F11";
    case NCKEY_F12:     return "F12";
    case NCKEY_F13:     return "F13";
    case NCKEY_F14:     return "F14";
    case NCKEY_F15:     return "F15";
    case NCKEY_F16:     return "F16";
    case NCKEY_F17:     return "F17";
    case NCKEY_F18:     return "F18";
    case NCKEY_F19:     return "F19";
    case NCKEY_F20:     return "F20";
    case NCKEY_F21:     return "F21";
    case NCKEY_F22:     return "F22";
    case NCKEY_F23:     return "F23";
    case NCKEY_F24:     return "F24";
    case NCKEY_F25:     return "F25";
    case NCKEY_F26:     return "F26";
    case NCKEY_F27:     return "F27";
    case NCKEY_F28:     return "F28";
    case NCKEY_F29:     return "F29";
    case NCKEY_F30:     return "F30";
    case NCKEY_F31:     return "F31";
    case NCKEY_F32:     return "F32";
    case NCKEY_F33:     return "F33";
    case NCKEY_F34:     return "F34";
    case NCKEY_F35:     return "F35";
    case NCKEY_F36:     return "F36";
    case NCKEY_F37:     return "F37";
    case NCKEY_F38:     return "F38";
    case NCKEY_F39:     return "F39";
    case NCKEY_F40:     return "F40";
    case NCKEY_F41:     return "F41";
    case NCKEY_F42:     return "F42";
    case NCKEY_F43:     return "F43";
    case NCKEY_F44:     return "F44";
    case NCKEY_F45:     return "F45";
    case NCKEY_F46:     return "F46";
    case NCKEY_F47:     return "F47";
    case NCKEY_F48:     return "F48";
    case NCKEY_F49:     return "F49";
    case NCKEY_F50:     return "F50";
    case NCKEY_F51:     return "F51";
    case NCKEY_F52:     return "F52";
    case NCKEY_F53:     return "F53";
    case NCKEY_F54:     return "F54";
    case NCKEY_F55:     return "F55";
    case NCKEY_F56:     return "F56";
    case NCKEY_F57:     return "F57";
    case NCKEY_F58:     return "F58";
    case NCKEY_F59:     return "F59";
    case NCKEY_BACKSPACE: return "backspace";
    case NCKEY_CENTER:  return "center";
    case NCKEY_ENTER:   return "enter";
    case NCKEY_CLS:     return "clear";
    case NCKEY_DLEFT:   return "down+left";
    case NCKEY_DRIGHT:  return "down+right";
    case NCKEY_ULEFT:   return "up+left";
    case NCKEY_URIGHT:  return "up+right";
    case NCKEY_BEGIN:   return "begin";
    case NCKEY_CANCEL:  return "cancel";
    case NCKEY_CLOSE:   return "close";
    case NCKEY_COMMAND: return "command";
    case NCKEY_COPY:    return "copy";
    case NCKEY_EXIT:    return "exit";
    case NCKEY_PRINT:   return "print";
    case NCKEY_REFRESH: return "refresh";
    case NCKEY_SEPARATOR: return "separator";
    case NCKEY_CAPS_LOCK: return "caps lock";
    case NCKEY_SCROLL_LOCK: return "scroll lock";
    case NCKEY_NUM_LOCK: return "num lock";
    case NCKEY_PRINT_SCREEN: return "print screen";
    case NCKEY_PAUSE: return "pause";
    case NCKEY_MENU: return "menu";
    // media keys, similarly only available through kitty's protocol
    case NCKEY_MEDIA_PLAY: return "play";
    case NCKEY_MEDIA_PAUSE: return "pause";
    case NCKEY_MEDIA_PPAUSE: return "play-pause";
    case NCKEY_MEDIA_REV: return "reverse";
    case NCKEY_MEDIA_STOP: return "stop";
    case NCKEY_MEDIA_FF: return "fast-forward";
    case NCKEY_MEDIA_REWIND: return "rewind";
    case NCKEY_MEDIA_NEXT: return "next track";
    case NCKEY_MEDIA_PREV: return "previous track";
    case NCKEY_MEDIA_RECORD: return "record";
    case NCKEY_MEDIA_LVOL: return "lower volume";
    case NCKEY_MEDIA_RVOL: return "raise volume";
    case NCKEY_MEDIA_MUTE: return "mute";
    case NCKEY_LSHIFT: return "left shift";
    case NCKEY_LCTRL: return "left ctrl";
    case NCKEY_LALT: return "left alt";
    case NCKEY_LSUPER: return "left super";
    case NCKEY_LHYPER: return "left hyper";
    case NCKEY_LMETA: return "left meta";
    case NCKEY_RSHIFT: return "right shift";
    case NCKEY_RCTRL: return "right ctrl";
    case NCKEY_RALT: return "right alt";
    case NCKEY_RSUPER: return "right super";
    case NCKEY_RHYPER: return "right hyper";
    case NCKEY_RMETA: return "right meta";
    case NCKEY_L3SHIFT: return "level 3 shift";
    case NCKEY_L5SHIFT: return "level 5 shift";
    case NCKEY_MOTION: return "mouse (no buttons pressed)";
    case NCKEY_BUTTON1: return "mouse (button 1)";
    case NCKEY_BUTTON2: return "mouse (button 2)";
    case NCKEY_BUTTON3: return "mouse (button 3)";
    case NCKEY_BUTTON4: return "mouse (button 4)";
    case NCKEY_BUTTON5: return "mouse (button 5)";
    case NCKEY_BUTTON6: return "mouse (button 6)";
    case NCKEY_BUTTON7: return "mouse (button 7)";
    case NCKEY_BUTTON8: return "mouse (button 8)";
    case NCKEY_BUTTON9: return "mouse (button 9)";
    case NCKEY_BUTTON10: return "mouse (button 10)";
    case NCKEY_BUTTON11: return "mouse (button 11)";
    default:            return "unknown";
  }
}


#endif

