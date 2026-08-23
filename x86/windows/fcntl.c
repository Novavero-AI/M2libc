/* SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
 * SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * Opening a file, the Windows way, behind the POSIX signature M2libc's
 * stdio.c expects.  Stands in for M2libc/x86/linux/fcntl.c.
 *
 * The flag values are POSIX's, because the C above this file uses them by
 * name; what reaches ntdll is a DesiredAccess and a CreateDisposition instead,
 * chosen by __open from whether the write bit is set.  mode is accepted and
 * ignored: Windows has no permission bits of that shape, and nothing here
 * would know what to do with them.
 */

#ifndef __FCNTL_C
#define __FCNTL_C

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 00100
#define O_EXCL 00200
#define O_TRUNC 001000
#define O_APPEND 002000

#define S_IXUSR 00100
#define S_IWUSR 00200
#define S_IRUSR 00400
#define S_IRWXU 00700

int __open_handle(char* name, int flag, int mode)
{
	asm("lea_eax,[esp+DWORD] %12"
	    "mov_eax,[eax]"
	    "lea_ebx,[esp+DWORD] %8"
	    "mov_ebx,[ebx]"
	    "call %__open");
}

/* A file that could not be opened comes back from __open as 0, because that is
 * what the handle slot NtCreateFile was given still holds and there is nothing
 * further down to say it any other way.  Everything above expects the Linux
 * answer instead -- a negative number -- and tests for exactly that: fcntl.c's
 * open() turns a negative into errno and -1, and stdio.c's fopen() gives up on
 * `0 > f`.  A plain 0 passes both, so without this a failed open produces a
 * FILE built around handle 0, which is not the file that was asked for and not
 * a file at all: 0, 1 and 2 are how this target spells the three standard
 * streams.  A caller that only opens files it knows are there never noticed; a
 * caller that opens a file to find out whether it is there -- kaem searching
 * PATH is one -- was told yes every time. */
int _open(char* name, int flag, int mode)
{
	int handle;
	handle = __open_handle(name, flag, mode);
	if(0 == handle) return -1;
	return handle;
}

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif
