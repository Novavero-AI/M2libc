/* SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
 * SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-FileCopyrightText: (C) 2026 Novavero AI Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * Stands in for M2libc/x86/linux/sys/stat.c.
 *
 * Windows has no executable bit: an image runs because its PE header says it
 * is one.  A Nix archive records one for each regular file all the same, from
 * the owner execute bit, and nova-nix, which builds Nix derivations on
 * Windows, keeps it as an NTFS alternate data stream named nova.exec beside
 * the file, whose presence is the bit.  chmod sets that stream from the owner
 * execute bit and removes it when the bit is clear.  hex2 calls
 * chmod(output, 0750) on what it links, so a program linked here archives as
 * the one linked on Linux does.  The rest of the mode is ignored: chmod
 * leaves alone the read only attribute that access reads as the write bit.
 *
 * fchmod has no path to name the stream by, and fails.  mkdir is a real call.
 * mknod has no Windows counterpart -- there are no device nodes in the
 * filesystem to make -- and umask has nothing to keep, since nothing here that
 * makes a file reads the mode it is given.
 */

#ifndef __SYS_STAT_C
#define __SYS_STAT_C

#define S_IRWXU 00700
#define S_IXUSR 00100
#define S_IWUSR 00200
#define S_IRUSR 00400

/* The OBJECT_ATTRIBUTES naming the nova.exec stream of the file that `file`,
 * from __ntobject, names: the same NT path with the stream's name after it.
 * The name goes on the NT path rather than on the path chmod was given
 * because Win32 reads "a:nova.exec" as the path nova.exec on drive A. */
int* __exec_stream(int* file)
{
	char* suffix;
	int* path;
	int* name;
	int* oa;
	char* from;
	char* to;
	int length;
	int n;
	int i;

	suffix = ":nova.exec";
	n = 0;
	while(0 != suffix[n]) n = n + 1;

	path = file[2];
	length = 65535 & path[0];      /* Length, in bytes, with no terminator */
	from = path[1];
	to = calloc(length + (2 * n) + 2, 1);
	i = 0;
	while(i < length)
	{
		to[i] = from[i];
		i = i + 1;
	}
	i = 0;
	while(i < n)
	{
		to[length + (2 * i)] = suffix[i];
		i = i + 1;
	}

	name = calloc(2, 4);
	name[0] = (length + (2 * n)) + (65536 * (length + (2 * n) + 2));
	name[1] = to;

	oa = calloc(6, 4);
	oa[0] = 24;
	oa[2] = name;
	oa[3] = file[3];
	return oa;
}

/* The stream holds "1", as nova-nix writes it, though only its presence is
 * read.  Opening a stream with a disposition that creates makes the file it
 * belongs to as well, so the file is looked up first and one that is not there
 * fails with nothing made.  A directory is left as it is, since a Nix archive
 * records no mode for one.  NTFS refuses to write or delete any stream of a
 * file with the read only attribute, so chmod fails on such a file whichever
 * way the bit goes; nothing in this layer sets that attribute. */
int chmod(char* pathname, int mode)
{
	int (*NtQueryAttributesFile)(int, int);
	int (*NtDeleteFile)(int);
	int (*NtCreateFile)(int, int, int, int, int, int, int, int, int, int, int);
	int (*NtWriteFile)(int, int, int, int, int, int, int, int, int);
	int (*NtClose)(int);
	int* file;
	int* stream;
	int* basic;
	int* iosb;
	int* handle;
	char* one;
	int h;
	int written;

	file = __ntobject(pathname);
	if(NULL == file) return -1;

	/* FILE_BASIC_INFORMATION: four timestamps and then FileAttributes */
	basic = calloc(10, 4);
	NtQueryAttributesFile = __ntdll_resolve("NtQueryAttributesFile");
	/* forwards: NtQueryAttributesFile(file, basic) */
	if(0 != NtQueryAttributesFile(basic, file)) return -1;

	/* FILE_ATTRIBUTE_DIRECTORY */
	if(0 != (basic[8] & 0x10)) return 0;

	stream = __exec_stream(file);
	if(0 == (mode & S_IXUSR))
	{
		/* A stream that is not there is already the answer. */
		/* forwards: NtQueryAttributesFile(stream, basic) */
		if(0 != NtQueryAttributesFile(basic, stream)) return 0;
		NtDeleteFile = __ntdll_resolve("NtDeleteFile");
		if(0 != NtDeleteFile(stream)) return -1;
		return 0;
	}

	iosb = calloc(2, 4);
	handle = calloc(1, 4);
	NtCreateFile = __ntdll_resolve("NtCreateFile");
	/* forwards: NtCreateFile(handle, GENERIC_WRITE|SYNCHRONIZE, stream, iosb,
	 *                        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
	 *                        FILE_OVERWRITE_IF,
	 *                        FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
	 *                        NULL, 0) */
	if(0 != NtCreateFile(0, 0, 0x60, 5, 1, 0x80, 0, iosb, stream, 0x40100000, handle)) return -1;

	h = handle[0];                 /* not in the argument list: see ntdll.c */
	one = "1";
	NtWriteFile = __ntdll_resolve("NtWriteFile");
	/* forwards: NtWriteFile(h, NULL, NULL, NULL, iosb, one, 1, NULL, NULL) */
	written = NtWriteFile(0, 0, 1, one, iosb, 0, 0, 0, h);
	NtClose = __ntdll_resolve("NtClose");
	NtClose(h);
	if(0 != written) return -1;
	return 0;
}

/* A handle does not know the path it was opened by (see fchdir in unistd.c),
 * and the stream chmod keeps is named by that path.  Nothing calls this, so it
 * fails rather than report a change it did not make. */
int fchmod(int a, mode_t b)
{
	return -1;
}

/* NtCreateFile makes a directory as readily as a file, given
 * FILE_DIRECTORY_FILE and FILE_CREATE, and the handle it hands back is closed
 * straight away because the directory is what was wanted, not a way in to it.
 * mode is accepted and ignored, as chmod ignores it for a directory. */
int mkdir(char* a, mode_t b)
{
	int (*NtCreateFile)(int, int, int, int, int, int, int, int, int, int, int);
	int (*NtClose)(int);
	int* oa;
	int* iosb;
	int* handle;
	int h;

	oa = __ntobject(a);
	if(NULL == oa) return -1;

	iosb = calloc(2, 4);
	handle = calloc(1, 4);
	NtCreateFile = __ntdll_resolve("NtCreateFile");

	/* forwards: NtCreateFile(handle, FILE_LIST_DIRECTORY|SYNCHRONIZE, oa,
	 *                        iosb, NULL, FILE_ATTRIBUTE_NORMAL,
	 *                        FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_CREATE,
	 *                        FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
	 *                        NULL, 0) */
	if(0 != NtCreateFile(0, 0, 0x21, 2, 3, 0x80, 0, iosb, oa, 0x00100001, handle)) return -1;

	NtClose = __ntdll_resolve("NtClose");
	h = handle[0];                 /* not in the argument list: see ntdll.c */
	NtClose(h);
	return 0;
}

/* A device is not a file on Windows and there is nothing in a directory to
 * make one out of.  Nothing here calls this; M2libc's sys/stat.h declares it. */
int mknod(char* a, mode_t b, dev_t c)
{
	return -1;
}

/* There is nothing to mask.  The mask applies to the mode a new file or
 * directory is made with, and open and mkdir here ignore that mode; what this
 * keeps is the number, so that a caller which sets a mask and puts the old one
 * back sees what it expects. */
mode_t _the_umask;

mode_t umask(mode_t m)
{
	mode_t was;

	was = _the_umask;
	_the_umask = m;
	return was;
}
#endif
