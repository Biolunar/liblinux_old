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

#ifndef HEADER_LIBLINUX_GENERIC_TERMBITS_H_INCLUDED
#define HEADER_LIBLINUX_GENERIC_TERMBITS_H_INCLUDED

typedef unsigned char linux_cc_t;
typedef unsigned int linux_speed_t;
typedef unsigned int linux_tcflag_t;

enum
{
	linux_NCCS = 19,
};

struct linux_termios_t
{
	linux_tcflag_t c_iflag;
	linux_tcflag_t c_oflag;
	linux_tcflag_t c_cflag;
	linux_tcflag_t c_lflag;
	linux_cc_t c_line;
	linux_cc_t c_cc[linux_NCCS];
};

struct linux_termios2_t
{
	linux_tcflag_t c_iflag;
	linux_tcflag_t c_oflag;
	linux_tcflag_t c_cflag;
	linux_tcflag_t c_lflag;
	linux_cc_t c_line;
	linux_cc_t c_cc[linux_NCCS];
	linux_speed_t c_ispeed;
	linux_speed_t c_ospeed;
};

struct linux_ktermios_t
{
	linux_tcflag_t c_iflag;
	linux_tcflag_t c_oflag;
	linux_tcflag_t c_cflag;
	linux_tcflag_t c_lflag;
	linux_cc_t c_line;
	linux_cc_t c_cc[linux_NCCS];
	linux_speed_t c_ispeed;
	linux_speed_t c_ospeed;
};

enum // c_cc
{
	linux_VINTR    =  0,
	linux_VQUIT    =  1,
	linux_VERASE   =  2,
	linux_VKILL    =  3,
	linux_VEOF     =  4,
	linux_VTIME    =  5,
	linux_VMIN     =  6,
	linux_VSWTC    =  7,
	linux_VSTART   =  8,
	linux_VSTOP    =  9,
	linux_VSUSP    = 10,
	linux_VEOL     = 11,
	linux_VREPRINT = 12,
	linux_VDISCARD = 13,
	linux_VWERASE  = 14,
	linux_VLNEXT   = 15,
	linux_VEOL2    = 16,
};

enum // c_iflag
{
	linux_IGNBRK  = 0000001,
	linux_BRKINT  = 0000002,
	linux_IGNPAR  = 0000004,
	linux_PARMRK  = 0000010,
	linux_INPCK   = 0000020,
	linux_ISTRIP  = 0000040,
	linux_INLCR   = 0000100,
	linux_IGNCR   = 0000200,
	linux_ICRNL   = 0000400,
	linux_IUCLC   = 0001000,
	linux_IXON    = 0002000,
	linux_IXANY   = 0004000,
	linux_IXOFF   = 0010000,
	linux_IMAXBEL = 0020000,
	linux_IUTF8   = 0040000,
};

enum // c_oflag
{
	linux_OPOST  = 0000001,
	linux_OLCUC  = 0000002,
	linux_ONLCR  = 0000004,
	linux_OCRNL  = 0000010,
	linux_ONOCR  = 0000020,
	linux_ONLRET = 0000040,
	linux_OFILL  = 0000100,
	linux_OFDEL  = 0000200,
	linux_NLDLY  = 0000400,
	linux_NL0    = 0000000,
	linux_NL1    = 0000400,
	linux_CRDLY  = 0003000,
	linux_CR0    = 0000000,
	linux_CR1    = 0001000,
	linux_CR2    = 0002000,
	linux_CR3    = 0003000,
	linux_TABDLY = 0014000,
	linux_TAB0   = 0000000,
	linux_TAB1   = 0004000,
	linux_TAB2   = 0010000,
	linux_TAB3   = 0014000,
	linux_XTABS  = 0014000,
	linux_BSDLY  = 0020000,
	linux_BS0    = 0000000,
	linux_BS1    = 0020000,
	linux_VTDLY  = 0040000,
	linux_VT0    = 0000000,
	linux_VT1    = 0040000,
	linux_FFDLY  = 0100000,
	linux_FF0    = 0000000,
	linux_FF1    = 0100000,
};

enum // c_cflag
{
	linux_CBAUD    = 0010017,
	linux_B0       = 0000000,
	linux_B50      = 0000001,
	linux_B75      = 0000002,
	linux_B110     = 0000003,
	linux_B134     = 0000004,
	linux_B150     = 0000005,
	linux_B200     = 0000006,
	linux_B300     = 0000007,
	linux_B600     = 0000010,
	linux_B1200    = 0000011,
	linux_B1800    = 0000012,
	linux_B2400    = 0000013,
	linux_B4800    = 0000014,
	linux_B9600    = 0000015,
	linux_B19200   = 0000016,
	linux_B38400   = 0000017,
	linux_EXTA     = linux_B19200,
	linux_EXTB     = linux_B38400,
	linux_CSIZE    = 0000060,
	linux_CS5      = 0000000,
	linux_CS6      = 0000020,
	linux_CS7      = 0000040,
	linux_CS8      = 0000060,
	linux_CSTOPB   = 0000100,
	linux_CREAD    = 0000200,
	linux_PARENB   = 0000400,
	linux_PARODD   = 0001000,
	linux_HUPCL    = 0002000,
	linux_CLOCAL   = 0004000,
	linux_CBAUDEX  = 0010000,
	linux_BOTHER   = 0010000,
	linux_B57600   = 0010001,
	linux_B115200  = 0010002,
	linux_B230400  = 0010003,
	linux_B460800  = 0010004,
	linux_B500000  = 0010005,
	linux_B576000  = 0010006,
	linux_B921600  = 0010007,
	linux_B1000000 = 0010010,
	linux_B1152000 = 0010011,
	linux_B1500000 = 0010012,
	linux_B2000000 = 0010013,
	linux_B2500000 = 0010014,
	linux_B3000000 = 0010015,
	linux_B3500000 = 0010016,
	linux_B4000000 = 0010017,
};

enum
{
	linux_CIBAUD   = 002003600000,
	linux_CMSPAR   = 010000000000,
	linux_CRTSCTS  = (int)020000000000,
};

enum
{
	linux_IBSHIFT = 16,
};

enum // c_lflag
{
	linux_ISIG    = 0000001,
	linux_ICANON  = 0000002,
	linux_XCASE   = 0000004,
	linux_ECHO    = 0000010,
	linux_ECHOE   = 0000020,
	linux_ECHOK   = 0000040,
	linux_ECHONL  = 0000100,
	linux_NOFLSH  = 0000200,
	linux_TOSTOP  = 0000400,
	linux_ECHOCTL = 0001000,
	linux_ECHOPRT = 0002000,
	linux_ECHOKE  = 0004000,
	linux_FLUSHO  = 0010000,
	linux_PENDIN  = 0040000,
	linux_IEXTEN  = 0100000,
	linux_EXTPROC = 0200000,
};

enum // linux_TCXONC
{
	linux_TCOOFF = 0,
	linux_TCOON  = 1,
	linux_TCIOFF = 2,
	linux_TCION  = 3,
};

enum // linux_TCFLSH
{
	linux_TCIFLUSH  = 0,
	linux_TCOFLUSH  = 1,
	linux_TCIOFLUSH = 2,
};

#endif // HEADER_LIBLINUX_GENERIC_TERMBITS_H_INCLUDED
