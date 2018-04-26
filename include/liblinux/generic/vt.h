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

#ifndef HEADER_LIBLINUX_VT_H_INCLUDED
#define HEADER_LIBLINUX_VT_H_INCLUDED

enum
{
	linux_MIN_NR_CONSOLES =  1,
	linux_MAX_NR_CONSOLES = 63,
};

enum
{
	linux_VT_OPENQRY       = 0x5600,
	linux_VT_GETMODE       = 0x5601,
	linux_VT_SETMODE       = 0x5602,
	linux_VT_GETSTATE      = 0x5603,
	// (unused) linux_VT_SENDSIG       = 0x5604,
	linux_VT_RELDISP       = 0x5605,
	linux_VT_ACTIVATE      = 0x5606,
	linux_VT_WAITACTIVE    = 0x5607,
	linux_VT_DISALLOCATE   = 0x5608,
	linux_VT_RESIZE        = 0x5609,
	linux_VT_RESIZEX       = 0x560A,
	linux_VT_LOCKSWITCH    = 0x560B,
	linux_VT_UNLOCKSWITCH  = 0x560C,
	linux_VT_GETHIFONTMASK = 0x560D,
	linux_VT_WAITEVENT     = 0x560E,
	linux_VT_SETACTIVATE   = 0x560F,
};

struct linux_vt_mode_t
{
	char mode;
	char waitv; // unused (set to 0)
	short relsig;
	short acqsig;
	short frsig; // unused (set to 0)
};

enum // vt mode
{
	linux_VT_AUTO    = 0x00,
	linux_VT_PROCESS = 0x01,

	linux_VT_ACKACQ  = 0x02,
};

struct linux_vt_stat_t
{
	unsigned short v_active;
	unsigned short v_signal;
	unsigned short v_state;
};

struct linux_vt_sizes_t
{
	unsigned short v_rows;
	unsigned short v_cols;
	unsigned short v_scrollsize; // unused (set to 0)
};

struct linux_vt_consize_t
{
	unsigned short v_rows;
	unsigned short v_cols;
	unsigned short v_vlin;
	unsigned short v_clin;
	unsigned short v_vcol;
	unsigned short v_ccol;
};

struct linux_vt_event_t
{
	unsigned int event;
	unsigned int oldev;
	unsigned int newev;
	unsigned int pad[4]; // reserved for future use (set to 0)
};

enum // event
{
	linux_VT_EVENT_SWITCH  = 0x0001,
	linux_VT_EVENT_BLANK   = 0x0002,
	linux_VT_EVENT_UNBLANK = 0x0004,
	linux_VT_EVENT_RESIZE  = 0x0008,
	linux_VT_MAX_EVENT     = 0x000F,
};

struct linux_vt_setactivate_t
{
	unsigned int console;
	struct linux_vt_mode_t mode;
};

#endif // HEADER_LIBLINUX_VT_H_INCLUDED
