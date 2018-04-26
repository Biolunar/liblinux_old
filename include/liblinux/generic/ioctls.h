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

#ifndef HEADER_LIBLINUX_GENERIC_IOCTLS_H_INCLUDED
#define HEADER_LIBLINUX_GENERIC_IOCTLS_H_INCLUDED

#include "ioctl.h"
#include "termio.h"
#include "termiox.h"
#include "termbits.h"
#include "kd.h"
#include "vt.h"

enum
{
	linux_TCGETS          = 0x5401,
	linux_TCSETS          = 0x5402,
	linux_TCSETSW         = 0x5403,
	linux_TCSETSF         = 0x5404,
	linux_TCGETA          = 0x5405,
	linux_TCSETA          = 0x5406,
	linux_TCSETAW         = 0x5407,
	linux_TCSETAF         = 0x5408,
	linux_TCSBRK          = 0x5409,
	linux_TCXONC          = 0x540A,
	linux_TCFLSH          = 0x540B,
	linux_TIOCEXCL        = 0x540C,
	linux_TIOCNXCL        = 0x540D,
	linux_TIOCSCTTY       = 0x540E,
	linux_TIOCGPGRP       = 0x540F,
	linux_TIOCSPGRP       = 0x5410,
	linux_TIOCOUTQ        = 0x5411,
	linux_TIOCSTI         = 0x5412,
	linux_TIOCGWINSZ      = 0x5413,
	linux_TIOCSWINSZ      = 0x5414,
	linux_TIOCMGET        = 0x5415,
	linux_TIOCMBIS        = 0x5416,
	linux_TIOCMBIC        = 0x5417,
	linux_TIOCMSET        = 0x5418,
	linux_TIOCGSOFTCAR    = 0x5419,
	linux_TIOCSSOFTCAR    = 0x541A,
	linux_FIONREAD        = 0x541B,
	linux_TIOCINQ         = linux_FIONREAD,
	linux_TIOCLINUX       = 0x541C,
	linux_TIOCCONS        = 0x541D,
	linux_TIOCGSERIAL     = 0x541E,
	linux_TIOCSSERIAL     = 0x541F,
	linux_TIOCPKT         = 0x5420,
	linux_FIONBIO         = 0x5421,
	linux_TIOCNOTTY       = 0x5422,
	linux_TIOCSETD        = 0x5423,
	linux_TIOCGETD        = 0x5424,
	linux_TCSBRKP         = 0x5425,
	linux_TIOCSBRK        = 0x5427,
	linux_TIOCCBRK        = 0x5428,
	linux_TIOCGSID        = 0x5429,
	linux_TCGETS2         = (int)LINUX_IOR('T', 0x2A, struct linux_termios2_t),
	linux_TCSETS2         = (int)LINUX_IOW('T', 0x2B, struct linux_termios2_t),
	linux_TCSETSW2        = (int)LINUX_IOW('T', 0x2C, struct linux_termios2_t),
	linux_TCSETSF2        = (int)LINUX_IOW('T', 0x2D, struct linux_termios2_t),
	linux_TIOCGRS485      = 0x542E,
	linux_TIOCSRS485      = 0x542F,
	linux_TIOCGPTN        = (int)LINUX_IOR('T', 0x30, unsigned int),
	linux_TIOCSPTLCK      = (int)LINUX_IOW('T', 0x31, int),
	linux_TIOCGDEV        = (int)LINUX_IOR('T', 0x32, unsigned int),
	linux_TCGETX          = 0x5432,
	linux_TCSETX          = 0x5433,
	linux_TCSETXF         = 0x5434,
	linux_TCSETXW         = 0x5435,
	linux_TIOCSIG         = (int)LINUX_IOW('T', 0x36, int),
	linux_TIOCVHANGUP     = 0x5437,
	linux_TIOCGPKT        = (int)LINUX_IOR('T', 0x38, int),
	linux_TIOCGPTLCK      = (int)LINUX_IOR('T', 0x39, int),
	linux_TIOCGEXCL       = (int)LINUX_IOR('T', 0x40, int),
	linux_TIOCGPTPEER     = (int)LINUX_IO('T', 0x41),
	linux_FIONCLEX        = 0x5450,
	linux_FIOCLEX         = 0x5451,
	linux_FIOASYNC        = 0x5452,
	linux_TIOCSERCONFIG   = 0x5453,
	linux_TIOCSERGWILD    = 0x5454,
	linux_TIOCSERSWILD    = 0x5455,
	linux_TIOCGLCKTRMIOS  = 0x5456,
	linux_TIOCSLCKTRMIOS  = 0x5457,
	linux_TIOCSERGSTRUCT  = 0x5458,
	linux_TIOCSERGETLSR   = 0x5459,
	linux_TIOCSERGETMULTI = 0x545A,
	linux_TIOCSERSETMULTI = 0x545B,
	linux_TIOCMIWAIT      = 0x545C,
	linux_TIOCGICOUNT     = 0x545D,

#ifndef LINUX_FIOQSIZE
	linux_FIOQSIZE        = 0x5460,
#endif
#undef LINUX_FIOQSIZE
};

enum
{
	linux_TIOCPKT_DATA       =  0,
	linux_TIOCPKT_FLUSHREAD  =  1,
	linux_TIOCPKT_FLUSHWRITE =  2,
	linux_TIOCPKT_STOP       =  4,
	linux_TIOCPKT_START      =  8,
	linux_TIOCPKT_NOSTOP     = 16,
	linux_TIOCPKT_DOSTOP     = 32,
	linux_TIOCPKT_IOCTL      = 64,
};

enum
{
	linux_TIOCSER_TEMT = 0x01,
};

#endif // HEADER_LIBLINUX_GENERIC_IOCTLS_H_INCLUDED
