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

#ifndef HEADER_LIBLINUX_GENERIC_TERMIOX_H_INCLUDED
#define HEADER_LIBLINUX_GENERIC_TERMIOX_H_INCLUDED

#include <stdint.h>

enum
{
	linux_NFF = 5,
};

struct linux_termiox_t
{
	uint16_t x_hflag;
	uint16_t x_cflag;
	uint16_t x_rflag[linux_NFF];
	uint16_t x_sflag;
};

enum
{
	linux_RTSXOFF = 0x0001,
	linux_CTSXON  = 0x0002,
	linux_DTRXOFF = 0x0004,
	linux_DSRXON  = 0x0008,
};

#endif // HEADER_LIBLINUX_GENERIC_TERMIOX_H_INCLUDED
