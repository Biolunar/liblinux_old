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

#ifndef HEADER_LIBLINUX_GENERIC_TERMIOS_H_INCLUDED
#define HEADER_LIBLINUX_GENERIC_TERMIOS_H_INCLUDED

struct linux_winsize_t
{
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};

enum
{
	linux_NCC = 8,
};

struct linux_termio_t
{
	unsigned short c_iflag;
	unsigned short c_oflag;
	unsigned short c_cflag;
	unsigned short c_lflag;
	unsigned char c_line;
	unsigned char c_cc[linux_NCC];
};

enum
{
	linux_TIOCM_LE   = 0x001,
	linux_TIOCM_DTR  = 0x002,
	linux_TIOCM_RTS  = 0x004,
	linux_TIOCM_ST   = 0x008,
	linux_TIOCM_SR   = 0x010,
	linux_TIOCM_CTS  = 0x020,
	linux_TIOCM_CAR  = 0x040,
	linux_TIOCM_RNG  = 0x080,
	linux_TIOCM_DSR  = 0x100,
	linux_TIOCM_CD   = linux_TIOCM_CAR,
	linux_TIOCM_RI   = linux_TIOCM_RNG,
	linux_TIOCM_OUT1 = 0x2000,
	linux_TIOCM_OUT2 = 0x4000,
	linux_TIOCM_LOOP = 0x8000,
};

#endif // HEADER_LIBLINUX_GENERIC_TERMIOS_H_INCLUDED
