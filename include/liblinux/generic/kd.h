/*
 * Copyright 2018 Mahdi Khanalizadeh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HEADER_LIBLINUX_GENERIC_KD_H_INCLUDED
#define HEADER_LIBLINUX_GENERIC_KD_H_INCLUDED

enum
{
	linux_GIO_FONT       = 0x4B60,
	linux_PIO_FONT       = 0x4B61,
	linux_GIO_FONTX      = 0x4B6B,
	linux_PIO_FONTX      = 0x4B6C,
	linux_PIO_FONTRESET  = 0x4B6D,
	linux_GIO_CMAP       = 0x4B70,
	linux_PIO_CMAP       = 0x4B71,
	linux_KIOCSOUND      = 0x4B2F,
	linux_KDMKTONE       = 0x4B30,
	linux_KDGETLED       = 0x4B31,
	linux_KDSETLED       = 0x4B32,
	linux_KDGKBTYPE      = 0x4B33,
	linux_KDADDIO        = 0x4B34,
	linux_KDDELIO        = 0x4B35,
	linux_KDENABIO       = 0x4B36,
	linux_KDDISABIO      = 0x4B37,
	linux_KDSETMODE      = 0x4B3A,
	linux_KDGETMODE      = 0x4B3B,
	linux_KDMAPDISP      = 0x4B3C,
	linux_KDUNMAPDISP    = 0x4B3D,
	linux_GIO_SCRNMAP    = 0x4B40,
	linux_PIO_SCRNMAP    = 0x4B41,
	linux_GIO_UNISCRNMAP = 0x4B69,
	linux_PIO_UNISCRNMAP = 0x4B6A,
	linux_GIO_UNIMAP     = 0x4B66,
	linux_PIO_UNIMAP     = 0x4B67,
	linux_PIO_UNIMAPCLR  = 0x4B68,
	linux_KDGKBMODE      = 0x4B44,
	linux_KDSKBMODE      = 0x4B45,
	linux_KDGKBMETA      = 0x4B62,
	linux_KDSKBMETA      = 0x4B63,
	linux_KDGKBLED       = 0x4B64,
	linux_KDSKBLED       = 0x4B65,
	linux_KDGKBENT       = 0x4B46,
	linux_KDSKBENT       = 0x4B47,
	linux_KDGKBSENT      = 0x4B48,
	linux_KDSKBSENT      = 0x4B49,
	linux_KDGKBDIACR     = 0x4B4A,
	linux_KDSKBDIACR     = 0x4B4B,
	linux_KDGKBDIACRUC   = 0x4BFA,
	linux_KDSKBDIACRUC   = 0x4BFB,
	linux_KDGETKEYCODE   = 0x4B4C,
	linux_KDSETKEYCODE   = 0x4B4D,
	linux_KDSIGACCEPT    = 0x4B4E,
	linux_KDKBDREP       = 0x4B52,
	linux_KDFONTOP       = 0x4B72,
};

struct linux_consolefontdesc_t
{
	unsigned short charcount;
	unsigned short charheight;
	char* chardata;
};

enum
{
	linux_LED_SCR = 0x01,
	linux_LED_NUM = 0x02,
	linux_LED_CAP = 0x04,
};

enum
{
	linux_KB_84    = 0x01, // unused
	linux_KB_101   = 0x02,
	linux_KB_OTHER = 0x03, // unused
};

enum
{
	linux_KD_TEXT     = 0x00,
	linux_KD_GRAPHICS = 0x01,
	linux_KD_TEXT0    = 0x02, // obsolete
	linux_KD_TEXT1    = 0x03, // obsolete
};

enum
{
	linux_E_TABSZ = 256,
};

typedef char linux_scrnmap_t; // unused

enum
{
	linux_UNI_DIRECT_BASE = 0xF000,
	linux_UNI_DIRECT_MASK = 0x01FF,
};

struct linux_unipair_t
{
	unsigned short unicode;
	unsigned short fontpos;
};

struct linux_unimapdesc_t
{
	unsigned short entry_ct;
	struct linux_unipair_t* entries;
};

struct linux_unimapinit_t // unused
{
	unsigned short advised_hashsize;
	unsigned short advised_hashstep;
	unsigned short advised_hashlevel;
};

enum
{
	linux_K_RAW       = 0x00,
	linux_K_XLATE     = 0x01,
	linux_K_MEDIUMRAW = 0x02,
	linux_K_UNICODE   = 0x03,
	linux_K_OFF       = 0x04,
};

enum
{
	linux_K_METABIT   = 0x03,
	linux_K_ESCPREFIX = 0x04,
};

enum // unused
{
	linux_K_SCROLLLOCK = 0x01,
	linux_K_NUMLOCK    = 0x02,
	linux_K_CAPSLOCK   = 0x04,
};

enum // unused
{
	linux_K_NORMTAB     = 0x00,
	linux_K_SHIFTTAB    = 0x01,
	linux_K_ALTTAB      = 0x02,
	linux_K_ALTSHIFTTAB = 0x03,
};

enum
{
	linux_KD_FONT_OP_SET         = 0,
	linux_KD_FONT_OP_GET         = 1,
	linux_KD_FONT_OP_SET_DEFAULT = 2,
	linux_KD_FONT_OP_COPY        = 3,
};

enum
{
	linux_KD_FONT_FLAG_DONT_RECALC = 1,
};

struct linux_kbentry_t
{
	unsigned char kb_table;
	unsigned char kb_index;
	unsigned short kb_value;
};

struct linux_kbsentry_t
{
	unsigned char kb_func;
	unsigned char kb_string[512];
};

struct linux_kbdiacr_t
{
	unsigned char diacr, base, result;
};

struct linux_kbdiacrs_t
{
	unsigned int kb_cnt;
	struct linux_kbdiacr_t kbdiacr[256];
};

struct linux_kbdiacruc_t
{
	unsigned int diacr, base, result;
};

struct linux_kbdiacrsuc_t
{
	unsigned int kb_cnt;
	struct linux_kbdiacruc_t kbdiacruc[256];
};

struct linux_kbkeycode_t
{
	unsigned int scancode, keycode;
};

struct linux_kbd_repeat_t
{
	int delay;
	int period;
};

struct linux_console_font_op_t
{
	unsigned int op;
	unsigned int flags;
	unsigned int width, height;
	unsigned int charcount;
	unsigned char* data;
};

struct linux_console_font_t
{
	unsigned int width, height;
	unsigned int charcount;
	unsigned char *data;
};

#endif // HEADER_LIBLINUX_KD_H_INCLUDED
