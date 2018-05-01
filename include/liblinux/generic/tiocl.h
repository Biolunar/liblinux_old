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

#ifndef HEADER_LIBLINUX_GENERIC_TIOCL_H_INCLUDED
#define HEADER_LIBLINUX_GENERIC_TIOCL_H_INCLUDED

enum
{
	linux_TIOCL_SETSEL            =  2,
	linux_TIOCL_PASTESEL          =  3,
	linux_TIOCL_UNBLANKSCREEN     =  4,
	linux_TIOCL_SELLOADLUT        =  5,
	linux_TIOCL_GETSHIFTSTATE     =  6,
	linux_TIOCL_GETMOUSEREPORTING =  7,
	linux_TIOCL_SETVESABLANK      = 10,
	linux_TIOCL_SETKMSGREDIRECT   = 11,
	linux_TIOCL_GETFGCONSOLE      = 12,
	linux_TIOCL_SCROLLCONSOLE     = 13,
	linux_TIOCL_BLANKSCREEN       = 14,
	linux_TIOCL_BLANKEDSCREEN     = 15,
	linux_TIOCL_GETKMSGREDIRECT   = 17,
};

enum
{
	linux_TIOCL_SELCHAR        =  0,
	linux_TIOCL_SELWORD        =  1,
	linux_TIOCL_SELLINE        =  2,
	linux_TIOCL_SELPOINTER     =  3,
	linux_TIOCL_SELCLEAR       =  4,
	linux_TIOCL_SELMOUSEREPORT = 16,
	linux_TIOCL_SELBUTTONMASK  = 15,
};

struct tiocl_selection
{
	unsigned short xs;
	unsigned short ys;
	unsigned short xe;
	unsigned short ye;
	unsigned short sel_mode;
};

#endif // HEADER_LIBLINUX_GENERIC_TIOCL_H_INCLUDED
