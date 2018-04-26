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

#ifndef HEADER_LIBLINUX_GENERIC_IOCTL_H_INCLUDED
#define HEADER_LIBLINUX_GENERIC_IOCTL_H_INCLUDED

enum
{
	linux_IOC_NRBITS   =  8,
	linux_IOC_TYPEBITS =  8,

#ifndef LINUX_IOC_SIZEBITS
	linux_IOC_SIZEBITS = 14,
#endif
#undef LINUX_IOC_SIZEBITS

#ifndef LINUX_IOC_DIRBITS
	linux_IOC_DIRBITS  =  2,
#endif
#undef LINUX_IOC_DIRBITS
};

enum
{
	linux_IOC_NRMASK   = (1 << linux_IOC_NRBITS)   - 1,
	linux_IOC_TYPEMASK = (1 << linux_IOC_TYPEBITS) - 1,
	linux_IOC_SIZEMASK = (1 << linux_IOC_SIZEBITS) - 1,
	linux_IOC_DIRMASK  = (1 << linux_IOC_DIRBITS)  - 1,
};

enum
{
	linux_IOC_NRSHIFT   = 0,
	linux_IOC_TYPESHIFT = linux_IOC_NRSHIFT   + linux_IOC_NRBITS,
	linux_IOC_SIZESHIFT = linux_IOC_TYPESHIFT + linux_IOC_TYPEBITS,
	linux_IOC_DIRSHIFT  = linux_IOC_SIZESHIFT + linux_IOC_SIZEBITS,
};

#if !(defined(LINUX_IOC_NONE) && defined(LINUX_IOC_WRITE) && defined(LINUX_IOC_READ))
enum
{
#ifndef LINUX_IOC_NONE
	linux_IOC_NONE  = 0,
#endif
#undef LINUX_IOC_NONE

#ifndef LINUX_IOC_WRITE
	linux_IOC_WRITE = 1,
#endif
#undef LINUX_IOC_WRITE

#ifndef LINUX_IOC_READ
	linux_IOC_READ  = 2,
#endif
#undef LINUX_IOC_READ
};
#endif

#define LINUX_IOC(dir, type, nr, size) (((unsigned)(dir)  << linux_IOC_DIRSHIFT)  | \
                                        ((unsigned)(type) << linux_IOC_TYPESHIFT) | \
                                        ((unsigned)(nr)   << linux_IOC_NRSHIFT)   | \
                                        ((unsigned)(size) << linux_IOC_SIZESHIFT))

#define LINUX_IO(type, nr)         LINUX_IOC(linux_IOC_NONE, (type), (nr), 0)
#define LINUX_IOR(type, nr, size)  LINUX_IOC(linux_IOC_READ, (type), (nr), sizeof(size))
#define LINUX_IOW(type, nr, size)  LINUX_IOC(linux_IOC_WRITE, (type), (nr), sizeof(size))
#define LINUX_IOWR(type, nr, size) LINUX_IOC(linux_IOC_READ | linux_IOC_WRITE, (type), (nr), sizeof(size))

static inline unsigned int linux_IOC_DIR(unsigned int const nr)
{
	return (nr >> linux_IOC_DIRSHIFT) & linux_IOC_DIRMASK;
}
static inline unsigned int linux_IOC_TYPE(unsigned int const nr)
{
	return (nr >> linux_IOC_TYPESHIFT) & linux_IOC_TYPEMASK;
}
static inline unsigned int linux_IOC_NR(unsigned int const nr)
{
	return (nr >> linux_IOC_NRSHIFT) & linux_IOC_NRMASK;
}
static inline unsigned int linux_IOC_SIZE(unsigned int const nr)
{
	return (nr >> linux_IOC_SIZESHIFT) & linux_IOC_SIZEMASK;
}

enum
{
	linux_IOC_IN        = (int)((unsigned)linux_IOC_WRITE << linux_IOC_DIRSHIFT),
	linux_IOC_OUT       = (int)((unsigned)linux_IOC_READ << linux_IOC_DIRSHIFT),
	linux_IOC_INOUT     = (int)(((unsigned)linux_IOC_WRITE | (unsigned)linux_IOC_READ) << linux_IOC_DIRSHIFT),
	linux_IOCSIZE_MASK  = (int)((unsigned)linux_IOC_SIZEMASK << linux_IOC_SIZESHIFT),
	linux_IOCSIZE_SHIFT = linux_IOC_SIZESHIFT,
};

#endif // HEADER_LIBLINUX_GENERIC_IOCTL_H_INCLUDED
