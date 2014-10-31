/*
 * Relatively simple hack to enable chat window logging in the 
 * NWN client. 
 * 
 * FWIW, this is copywritten by David Holland (1/2004) 
 *
 * Copyright 2008, David Holland, david.w.holland@gmail.com
 * 
 * There is no warrenty provided with this code. Use it at your
 * own risk.
 * 
 * I'm unwilling to give too many details out about this code due to
 * the code I'd be talking about isn't mine, and I'm not fond of
 * running into EULA/DMCA issues. (As if this wasn't flakey enough)
 * 
 * We hook multiple functions.   
 *   one to get the string that's going into the chat window. 
 *   one to whack the log file at loadgame time. 
 *   one to save the log file when saving the game. (mkdir()) 
 *   one to put a death message in the log file when we die. 
 *                (sometimes it doesn't show up.).
 *   One to show how we got out of the 'death' menu. 
 */

#define _GNU_SOURCE
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <link.h>

#include <errno.h>

#include <sys/mman.h>
#include <limits.h>

#include "nwlogger.h"

#ifndef PAGESIZE
#define PAGESIZE 4096
#endif

/* I'm sure there are approximately 4billion better ways to do this 
   However, this is the one that I came up with, and most importantly
   works at least most of the time */

const char libc_lib_name[] = "libc.so.6"; 

int		_NWL_FD = -1; 

static int (*libc_mkdir_ptr)(const char *, mode_t) = NULL; 
int		_NWL_enabled = 0; 

unsigned long _NWL_msg_retaddr = 0x0;  /* modified by setup_memory() */
unsigned long _NWL_load_retaddr = 0x0; 
unsigned long _NWL_dead_retaddr = 0x0; 
unsigned long _NWL_spwn_retaddr = 0x0; 
unsigned long _NWL_exit_retaddr = 0x0; 

void NWLogger_setup_memory(unsigned int patch0, unsigned int patch1, unsigned int patch2, unsigned int patch3, unsigned int patch4);
void NWLogger_printdata(char *ptr, int len);
void NWLogger_memcpy(char *dest,  char *src, size_t n);

extern void NWLogger_writeloadlog(void); 
extern void NWLogger_writeloadlog_start(void); 
extern void NWLogger_writeloadlog_end(void); 

extern void NWLogger_writedeadlog(void); 
extern void NWLogger_writedeadlog_start(void); 
extern void NWLogger_writedeadlog_end(void); 

extern void NWLogger_writespwnlog(void); 
extern void NWLogger_writespwnlog_start(void); 
extern void NWLogger_writespwnlog_end(void); 

extern void NWLogger_writeexitlog(void); 
extern void NWLogger_writeexitlog_start(void); 
extern void NWLogger_writeexitlog_end(void); 

extern void NWLogger_writemsglog(void); 

unsigned int *NWLogger_findcookie(char *file);

void NWL_initialize_handles(void) __attribute__((constructor));

int mkdir(const char *_path, mode_t _mode) 
{
	int 		retval; 
	char		save_cmd[PATH_MAX]; 
	static	int	save_cntr = 0; 

	if( ! _NWL_enabled ) { 
		return(libc_mkdir_ptr(_path, _mode)); 
	}

	if( _path != NULL ) { 
		fprintf(stderr, "NOTICE: NWLogger: mkdir(%s, 0%o) caught\n", _path, _mode); 
	} else { 
		fprintf(stderr, "WARNING: NWLogger: mkdir(NULL) caught.  Curious\n"); 
	}
	retval = libc_mkdir_ptr(_path, _mode); 

	if( _path != NULL && strncmp(_path, "./saves/", 8) == 0 ) { 		/* accessing the saves directory */
		if( strlen(_path) > 8 && save_cntr > 0 ) {			/* Creating a directory under saves then. */
			snprintf(save_cmd, PATH_MAX, "%s \"%s\" >> nwlogger_save.log 2>&1", "./nwlogger.pl", _path);

			/* clean up the log file */
			close(_NWL_FD); 
			_NWL_FD = -1; 

			system(save_cmd); 
			save_cntr = 0; 
		} else { 
			if( strcmp(_path, "./saves/") == 0 ) { 
				save_cntr++; 
			} else { 
				save_cntr = 0; 
			}
		} 
	} else { 
		save_cntr = 0; 
	}
	return retval; 
}


void NWL_initialize_handles(void) {

	struct 	stat 		statbuf; 

	Dl_info			info; 

	FILE			*fp; 
	char			string1[80]; 
	char			string2[80]; 

	unsigned int		patch0_addr = 0;
	unsigned int		patch1_addr = 0;
	unsigned int		patch2_addr = 0;
	unsigned int		patch3_addr = 0;
	unsigned int		patch4_addr = 0;

	unsigned int		file_size, file_date; 

	unsigned int		*patch_address;

	/* Make certain we're allowed to load. */

	void	*self_handle; 
	void	*self_ptr; 
	char	*self_name_ptr; 

	char	*level; 
	int	sleeptime; 

/* sleep so we can attach a debugger */

	if ((level = getenv("NWL_SLEEPTIME"))) {
		sleeptime = atoi(level);
		sleep(sleeptime);
	}

	/* Must always initialize this.. */

	libc_mkdir_ptr = dlsym(RTLD_NEXT, "mkdir"); 
	if( libc_mkdir_ptr == NULL ) { 
		fprintf(stderr, "ERROR: NWLogger: dlsym 'mkdir': %s\n", dlerror()); 
		abort(); 
	}

	self_handle = dlopen("", RTLD_NOW | RTLD_GLOBAL);
	self_ptr = dlsym(self_handle, "_init");
	if( self_ptr == NULL || dladdr( self_ptr, &info ) <= 0 ) {
		fprintf(stderr, "ERROR: NWUser: dladdr(self: _init): %s\n", dlerror());
		abort();
	}

	/* recycle library_name */
	self_name_ptr = basename((char *)info.dli_fname);
	if( strncmp( self_name_ptr, "nwmain", PATH_MAX) != 0 ) {
		dlclose(self_handle);
		return;
	}
	dlclose(self_handle);


	/* Spit out a version number */
	fprintf(stderr, "NOTICE: NWLogger: Version: %s\n", _NWLOGGER_VERSION); 
	fprintf(stderr, "NOTICE: NWLogger: Initializing handles.\n"); 
	_NWL_enabled = 1; 

	/* stat the ol' allowed executable */
	if( stat("nwmain", &statbuf) != 0 ) { 
		fprintf(stderr, "ERROR: NWLogger: Unable to stat nwmain: %d\n", errno); 
		exit(-1); 
	}

	/* ini parsing.  No, this doesn't have a lot of error checking. */

	fp = fopen("nwlogger.ini", "r"); 
	if( fp == NULL ) { 
		fprintf(stderr, "WARNING: NWLogger: No INI file.  Creating.\n"); 
		fp = fopen("nwlogger.ini", "w"); 
		if( fp == NULL ) { 
			fprintf(stderr, "ERROR: NWLogger: Unable to create INI file.  Aborting: %d\n", errno); 
			exit(-1); 
		}
		fprintf(fp, "size 0\n"); 
		fprintf(fp, "time 0\n"); 
		fprintf(fp, "patch0 0\n"); 
		fprintf(fp, "patch1 0\n"); 
		fprintf(fp, "patch2 0\n"); 
		fprintf(fp, "patch3 0\n"); 
		fprintf(fp, "patch4 0\n"); 
		fclose(fp); 
		fp = fopen("nwlogger.ini", "r"); 
		if( fp == NULL ) { 
			fprintf(stderr, "ERROR: NWLogger: Unable to re-open nwlogger.ini. Aborting: %d\n", errno); 
			exit(-1); 
		}
	}
	while( fscanf(fp, "%s %s\n", string1, string2) != EOF ) { 
		if( strcmp(string1, "size") == 0 ) { 
			file_size = atoi(string2); 
		}
		if( strcmp(string1, "time") == 0 ) { 
			file_date = atoi(string2); 
		} 
		if( strcmp(string1, "patch0") == 0 ) { 
			patch0_addr = strtol(string2, NULL, 0); 
		} 
		if( strcmp(string1, "patch1") == 0 ) { 
			patch1_addr = strtol(string2, NULL, 0); 
		} 
		if( strcmp(string1, "patch2") == 0 ) { 
			patch2_addr = strtol(string2, NULL, 0); 
		} 
		if( strcmp(string1, "patch3") == 0 ) { 
			patch3_addr = strtol(string2, NULL, 0); 
		} 
		if( strcmp(string1, "patch4") == 0 ) { 
			patch4_addr = strtol(string2, NULL, 0); 
		} 
	}
	fclose(fp); 
		
	if( 	statbuf.st_size != file_size || statbuf.st_mtime != file_date ) { 

		fprintf(stderr, "WARNING: NWLogger: INI recalculation required: %d:%d %d:%d\n", 
			(int)statbuf.st_size, file_size, (int)statbuf.st_mtime, file_date); 

		patch_address = NWLogger_findcookie( "nwmain" ); 
		
		fp = fopen("nwlogger.ini", "w"); 
		if( fp == NULL ) { 
			fprintf(stderr, "ERROR: NWLogger: Unable to create INI file.  Aborting: %d\n", errno); 
			exit(-1); 
		}
		fprintf(fp, "%s %d\n", "size", (int)statbuf.st_size); 
		fprintf(fp, "%s %d\n", "time", (int)statbuf.st_mtime); 
		fprintf(fp, "%s 0x%08x\n", "patch0", patch_address[0]); 
		fprintf(fp, "%s 0x%08x\n", "patch1", patch_address[1]); 
		fprintf(fp, "%s 0x%08x\n", "patch2", patch_address[2]); 
		fprintf(fp, "%s 0x%08x\n", "patch3", patch_address[3]); 
		fprintf(fp, "%s 0x%08x\n", "patch4", patch_address[4]); 
		fclose(fp); 
		fprintf(stderr, "NOTICE: NWLogger: INI File written: Now exiting.  This is perfectly normal!\n"); 
		fprintf(stderr, "NOTICE: Your next run of NWN should be complete, and include logging.\n"); 
		exit(0); 
	}

	fprintf(stderr, "NOTICE: NWLogger: Patch 0 Address: 0x%08x\n", patch0_addr); 
	fprintf(stderr, "NOTICE: NWLogger: Patch 1 Address: 0x%08x\n", patch1_addr); 
	fprintf(stderr, "NOTICE: NWLogger: Patch 2 Address: 0x%08x\n", patch2_addr); 
	fprintf(stderr, "NOTICE: NWLogger: Patch 3 Address: 0x%08x\n", patch3_addr); 
	fprintf(stderr, "NOTICE: NWLogger: Patch 4 Address: 0x%08x\n", patch4_addr); 

	NWLogger_setup_memory(patch0_addr, patch1_addr, patch2_addr, patch3_addr, patch4_addr);


	fprintf(stderr, "NOTICE: NWLogger: Handles Initialized.\n"); 
	return; 
}

void NWLogger_setup_memory(unsigned int patch0, unsigned int patch1, unsigned int patch2, unsigned int patch3, unsigned int patch4)
{
	char	instruction[30]; 			/* plenty of room in the instructions array. */
	unsigned long	address_offset; 
	unsigned long	patchlength;
	int		i; 

	fprintf(stderr, "NOTICE: NWLogger: PrePatch0 : "); 
	NWLogger_printdata((void *)patch0, 7); 
	fprintf(stderr, "\n"); 

	address_offset = (unsigned long) &NWLogger_writemsglog;
	address_offset = address_offset - (unsigned long) patch0 - 5; /* How many bytes should the jump be */
	memcpy(instruction + 1, &address_offset, 4); 
	instruction[0] = '\xe9'; 
	instruction[5] = '\x90';					/* Nop */
	instruction[6] = '\x90';					/* nop */
	NWLogger_memcpy((void *)patch0, instruction, 7); 			/* Put the jump in */
	_NWL_msg_retaddr = (unsigned long)patch0 + 0x7; 			/* setup return address */

	fprintf(stderr, "NOTICE: NWLogger: PostPatch0: "); 
	NWLogger_printdata((void *)patch0, 7); 
	fprintf(stderr, "\n"); 

	/* Patch1 */
	patchlength = (unsigned long) &NWLogger_writeloadlog_end - (unsigned long) &NWLogger_writeloadlog_start; 

	fprintf(stderr, "NOTICE: NWLogger: PrePatch1 : "); 
	NWLogger_printdata((void *)patch1, patchlength); 
	fprintf(stderr, "\n"); 

	memset(instruction, '\0', sizeof(instruction)); 
	NWLogger_memcpy((void *)&NWLogger_writeloadlog_start, (void *)patch1, patchlength); 
	address_offset = (unsigned long) &NWLogger_writeloadlog; 
	address_offset = address_offset - (unsigned long) patch1 - 5; 
	memcpy(instruction + 1, &address_offset, 4); 
	instruction[0] = '\xe9'; 
	for(i=5; i<patchlength; i++) { instruction[i] = '\x90'; }; 
	NWLogger_memcpy((void *)patch1, instruction, patchlength); 
	_NWL_load_retaddr = (unsigned long)patch1 + patchlength; 

	fprintf(stderr, "NOTICE: NWLogger: PostPatch1: "); 
	NWLogger_printdata((void *)patch1, patchlength); 
	fprintf(stderr, "\n"); 

	/* Patch2 */
	patchlength = (unsigned long) &NWLogger_writedeadlog_end - (unsigned long) &NWLogger_writedeadlog_start; 

	fprintf(stderr, "NOTICE: NWLogger: PrePatch2 : "); 
	NWLogger_printdata((void *)patch2, patchlength); 
	fprintf(stderr, "\n"); 

	memset(instruction, '\0', sizeof(instruction)); 
	NWLogger_memcpy((void *)&NWLogger_writedeadlog_start, (void *)patch2, patchlength); 
	address_offset = (unsigned long) &NWLogger_writedeadlog; 
	address_offset = address_offset - (unsigned long) patch2 - 5; 
	memcpy(instruction + 1, &address_offset, 4); 
	instruction[0] = '\xe9'; 
	for(i=5; i<patchlength; i++) { instruction[i] = '\x90'; }; 
	NWLogger_memcpy((void *)patch2, instruction, patchlength); 
	_NWL_dead_retaddr = (unsigned long)patch2 + patchlength; 

	fprintf(stderr, "NOTICE: NWLogger: PostPatch2: "); 
	NWLogger_printdata((void *)patch2, patchlength); 
	fprintf(stderr, "\n"); 

	/* Patch3 */
	patchlength = (unsigned long) &NWLogger_writespwnlog_end - (unsigned long) &NWLogger_writespwnlog_start; 

	fprintf(stderr, "NOTICE: NWLogger: PrePatch3 : "); 
	NWLogger_printdata((void *)patch3, patchlength); 
	fprintf(stderr, "\n"); 

	memset(instruction, '\0', sizeof(instruction)); 
	NWLogger_memcpy((void *)&NWLogger_writespwnlog_start, (void *)patch3, patchlength); 
	address_offset = (unsigned long) &NWLogger_writespwnlog; 
	address_offset = address_offset - (unsigned long) patch3 - 5; 
	memcpy(instruction + 1, &address_offset, 4); 
	instruction[0] = '\xe9'; 
	for(i=5; i<patchlength; i++) { instruction[i] = '\x90'; }; 
	NWLogger_memcpy((void *)patch3, instruction, patchlength); 
	_NWL_spwn_retaddr = (unsigned long)patch3 + patchlength; 

	fprintf(stderr, "NOTICE: NWLogger: PostPatch3: "); 
	NWLogger_printdata((void *)patch3, patchlength); 
	fprintf(stderr, "\n"); 

	/* Patch4 */
	patchlength = (unsigned long) &NWLogger_writeexitlog_end - (unsigned long) &NWLogger_writeexitlog_start; 

	fprintf(stderr, "NOTICE: NWLogger: PrePatch4 : "); 
	NWLogger_printdata((void *)patch4, patchlength); 
	fprintf(stderr, "\n"); 

	memset(instruction, '\0', sizeof(instruction)); 
	NWLogger_memcpy((void *)&NWLogger_writeexitlog_start, (void *)patch4, patchlength); 
	address_offset = (unsigned long) &NWLogger_writeexitlog; 
	address_offset = address_offset - (unsigned long) patch4 - 5; 
	memcpy(instruction + 1, &address_offset, 4); 
	instruction[0] = '\xe9'; 
	for(i=5; i<patchlength; i++) { instruction[i] = '\x90'; }; 
	NWLogger_memcpy((void *)patch4, instruction, patchlength); 
	_NWL_exit_retaddr = (unsigned long)patch4 + patchlength; 

	fprintf(stderr, "NOTICE: NWLogger: PostPatch4: "); 
	NWLogger_printdata((void *)patch4, patchlength); 
	fprintf(stderr, "\n"); 
}

void NWLogger_printdata(char *ptr, int len)
{
	int i; 

	for(i=0; i<len; i++) { 
		fprintf(stderr, "%02x ", (unsigned char) ptr[i]); 
	}
	return; 
}

void NWLogger_memcpy(char *dest, char *src, size_t n) 
{
//	int i; 
	char *p = dest; 

	/* Align to a multiple of PAGESIZE, assumed to be a power of two */
	/* Do two pages, just to make certain we get a big enough chunk */
	p = (char *)(((int) p + PAGESIZE-1) & ~(PAGESIZE-1));
	if( mprotect(p-PAGESIZE, 2 * PAGESIZE, PROT_READ|PROT_WRITE|PROT_EXEC) != 0 ) { 
		fprintf(stderr, "ERROR: NWLogger: Could not de-mprotect(%p)\n", p); 
		exit(-1); 
	}

//	for(i=0; i<n; i++) {
//		printf("%08x: %02x  ->  %08x: %02x\n", src + i, (unsigned char)src[i], dest + i, (unsigned char)dest[i]); 
//	}
	memcpy(dest, src, n);
	/* restore memory protection */
	if( mprotect(p-PAGESIZE, 2 * PAGESIZE, PROT_READ|PROT_EXEC) != 0 ) { 
		fprintf(stderr, "ERROR: NWLogger: Could not re-mprotect(%p)\n", p); 
		exit(-1); 
	}
//	printf("memcpy: src: %08x dst: %08x len: %02x\n", src, dest, n); 
	// memcpy(dest, src, n);
}

unsigned long	_NWLogger_EBX;

void NWLogger_writelog2(void)
{
	char		date_str[30]; 
	time_t		timet_ptr; 
	struct	tm	*tm_ptr; 
	char		str_null[] = "NULL\n"; 

	char 	*string; 

	timet_ptr = time(NULL); 
	tm_ptr	= localtime(&timet_ptr); 

	snprintf(date_str, 29, "%04d:%02d:%02d:%02d:%02d:%02d:%01d:%03d:%01d ", 
			tm_ptr->tm_year + 1900, 
			tm_ptr->tm_mon + 1, 
			tm_ptr->tm_mday, 
			tm_ptr->tm_hour, 
			tm_ptr->tm_min, 
			tm_ptr->tm_sec, 
			tm_ptr->tm_wday, 
			tm_ptr->tm_yday, 
			tm_ptr->tm_isdst ); 
	
	memcpy(&string, (void *)_NWLogger_EBX, 4);

	if( _NWL_FD == -1 ) { 
		_NWL_FD = open("nwlogger.log", O_CREAT | O_APPEND | O_WRONLY, 0755 ) ;
	}

	if( _NWL_FD >= 0 ) {
		if( !string ) { 
			write(_NWL_FD, date_str, strlen(date_str)); 
			write(_NWL_FD, str_null, strlen(str_null)); 
		} else { 
			write(_NWL_FD, date_str, strlen(date_str));
			write(_NWL_FD, string, strlen(string)); 
			write(_NWL_FD, "\n", 1);
		}
	}

	return; 
}

char	_NWL_dead_msg[] = "NWL: Main Player Character Died."; 
char	*_NWL_dead_msg_ptr = _NWL_dead_msg; 

char	_NWL_load_msg[] = "NWL: Loaded a saved game."; 
char	*_NWL_load_msg_ptr = _NWL_load_msg; 

char	_NWL_spwn_msg[] = "NWL: Main Player Character chose to Re-Spawn."; 
char	*_NWL_spwn_msg_ptr = _NWL_spwn_msg; 

char	_NWL_exit_msg[] = "NWL: Main Player Character chose to exit the game."; 
char	*_NWL_exit_msg_ptr = _NWL_exit_msg; 

void NWLogger_write_dead_log(void) 
{ 
	_NWLogger_EBX = (unsigned long)&_NWL_dead_msg_ptr; 
	NWLogger_writelog2(); 
	return; 
} 

void NWLogger_write_load_log(void) 
{ 
	_NWLogger_EBX = (unsigned long)&_NWL_load_msg_ptr; 
	NWLogger_writelog2(); 
	if( _NWL_FD >= 0 ) { 
		// ftruncate(_NWL_FD, 0); 
		NWLogger_writelog2(); 
	}
	return; 
} 

void NWLogger_write_spwn_log(void) 
{ 
	_NWLogger_EBX = (unsigned long)&_NWL_spwn_msg_ptr; 
	NWLogger_writelog2(); 
	return; 
} 

void NWLogger_write_exit_log(void) 
{ 
	_NWLogger_EBX = (unsigned long)&_NWL_exit_msg_ptr; 
	NWLogger_writelog2(); 
	return; 
} 
