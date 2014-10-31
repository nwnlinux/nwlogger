#define _GNU_SOURCE		/* Needed so dlfcn.h defines the right stuff */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dlfcn.h>
#include <errno.h>

#include <sys/mman.h>
#include <limits.h>

#include <elf.h>
#include <libelf.h>

#include <linux/user.h>
#include <link.h>

#include "libdis.h"

#ifndef PAGESIZE
#define PAGESIZE 4096
#endif

unsigned long NWLogger_findacrumb(unsigned char *buf, Elf32_Shdr *header, char **crumb, int counts); 

static char *NWLogger_msg_cookies[] = { 
	"mov",
	"lea",
	"mov",
	"mov",
	"call",
	"lea",
	"mov",
	"mov",
	"call",
	"lea",
	"mov",
	"call",
	"pop",
	"pop",
	NULL,
};

static char *NWLogger_load_cookies[] = { "call", "pop", "pop", "push", "push", "call", "pop", "pop", "push", "push", "call", "add", "test", "jz", "mov", "test", NULL }; 
static char *NWLogger_dead_cookies[] = { "push", "push", "mov", "mov", "test", "jnz", "sub", "push", "call", "mov", "mov", "call", "mov", "mov", "call", NULL };
static char *NWLogger_spwn_cookies[] = { "push", "sub", "mov", "mov", "push", "call", "mov", "call", "pop", "mov", "push", "call", NULL };
static char *NWLogger_exit_cookies[] = { "push", "push", "cmp", "mov", "jnz", "mov", "mov", "test", "jz", "mov", "test", "jnz", NULL };

static int(*NWL_disassemble_address_ptr)(char *, struct instr *);

unsigned long *NWLogger_findcookie(char *filename)
{
	Elf			*elf_ptr; 
	int			fd; 
	Elf32_Ehdr		*ehdr; 
	Elf_Scn			*section; 
	Elf32_Shdr		*section_header;
	Elf32_Shdr		*code_header;
	unsigned int		i, instruction_size; 
	unsigned char		*buffer, *entry; 
	unsigned char		*buffer_ptr; 
	unsigned char		*cookie_address; 
	struct 		instr 	current_instruction;
	struct		stat	statbuf; 
	float			pct_complete;

	int			call_counter; 
	char			search_instr[5]; 

	static unsigned long		calls[5]; 				/* Return value */
	unsigned int		magic_routine; 			/* Address of the magic routine */ 
	unsigned int		push_ebx_addr; 

	unsigned int		call_destination; 
	unsigned int		first_call, second_call; 

	/* Dynamic Linking, we only use this stuff if we need it */

	int			(*disassemble_init_ptr)(int, int); 
	int			(*disassemble_cleanup_ptr)(void); 
	void			*dlhandle; 

	dlhandle = dlopen("nwlogger/libdis/libdisasm.so", RTLD_NOW); 
	if( !dlhandle ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) dlopen of libdisasm.so failed: %s\n", dlerror()); 
		abort(); 
	}

	disassemble_init_ptr = dlsym(dlhandle, "disassemble_init"); 
	if( disassemble_init_ptr == NULL ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) dlsym(disassemble_init) failed: %s\n", dlerror()); 
		abort(); 
	}
	NWL_disassemble_address_ptr = dlsym(dlhandle, "disassemble_address"); 
	if( NWL_disassemble_address_ptr == NULL ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) dlsym(disassemble_address) failed: %s\n", dlerror()); 
		abort(); 
	}
	disassemble_cleanup_ptr = dlsym(dlhandle, "disassemble_cleanup"); 
	if( disassemble_cleanup_ptr == NULL ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) dlsym(disassemble_cleanup) failed: %s\n", dlerror()); 
		abort(); 
	}
	disassemble_init_ptr(0, INTEL_SYNTAX); 
		
/* Initialize the elves. */

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ERROR: NWLogger: (cookie) libelf version mismatch.\n"); 
		abort(); 
	}

/* open library */ 	

	fd = open(filename, O_RDONLY); 
	if( fd < 0 ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) Unable to open shared library: %s (%d)\n", filename, errno); 
		abort(); 
	}
	if( fstat(fd, &statbuf) < 0 ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) Unable to stat shared library: %s (%d) Howd that happen?\n", filename, errno); 
		abort(); 
	}
	buffer = mmap(0, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if( buffer < 0 ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) Unable to mmap executable: %s (%d)\n", filename, errno); 
		abort(); 
	}
	elf_ptr = elf_begin(fd, ELF_C_READ, (Elf *)0);
	if( elf_ptr == NULL) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) elf_begin failed: %s.\n", elf_errmsg(elf_errno())); 
		abort(); 
	} 

	/* Get the Header */
	if ( (ehdr = elf32_getehdr(elf_ptr)) == NULL) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) Unable to get Elf header: %s\n",  elf_errmsg(elf_errno()) ); 
		abort(); 
	}
	section = 0; 
	code_header = NULL; 
	while( (section = elf_nextscn( elf_ptr, section )) ) { 
		section_header = elf32_getshdr(section); 
		if( 	ehdr->e_entry >= section_header->sh_addr &&
			ehdr->e_entry < (section_header->sh_addr + section_header->sh_size)) {
				code_header = section_header; 
				break; 
		}
	}
	if( code_header == NULL ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) Unable to locate appropriate code section.\n"); 
		abort(); 
	}

	/* Found start of program  - Locate the Magic cookie locator */
	entry = (unsigned char *)ehdr->e_entry - (code_header->sh_addr - code_header->sh_offset);
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Entry point determined: %p\n", entry); 
	buffer_ptr = (unsigned char *) (int)entry + (int)buffer; 

	cookie_address = (unsigned char *)NWLogger_findacrumb( buffer_ptr, code_header, NWLogger_msg_cookies, 1 ); 

	if( cookie_address == NULL ) { 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie) Magic cookie not found.\n"); 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}

	fprintf(stderr, "NOTICE: NWLogger: (cookie) Cookie location: %p\n", cookie_address); 

	/* Search for two ret's, and then a push ebp */	
	call_counter = 0; 
	i = (int)cookie_address; 
	strcpy(search_instr, "ret"); 		/* What we search for */

	pct_complete = ((float)i / ((int)code_header->sh_size)) * 100.0; 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Searching executable: %02d", (int)pct_complete); 
	while( i < (int)code_header->sh_size ) {
		pct_complete = ((float)i / ((int)code_header->sh_size)) * 100.0; 
		if( ((int)pct_complete % 4) == 0 ) { 
			printf("%02d", (int)pct_complete); 
		}
		memset(&current_instruction, 0, sizeof(struct code));
		memset(&current_instruction, 0, sizeof(struct code));
		instruction_size = NWL_disassemble_address_ptr( (char *) buffer_ptr + i, &current_instruction );
		if( instruction_size ) {
			if( strcmp(current_instruction.mnemonic, search_instr) == 0 ) { 
				call_counter++; 
			}
			if( call_counter == 2 ) { 
				strcpy(search_instr, "push"); 
			}
			if( call_counter == 3 ) { 
				break; 
			} 
			i += instruction_size; 
		} else { 
			fprintf(stderr, "\nERROR: NWLogger: (cookie) Invalid instruction disassembled: %08x\n", i); 
			fprintf(stderr, "ERROR: NWLogger: (cookie) Probably a bug in libdis.\n"); 
			fprintf(stderr, "ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
			abort();
		}
	}
	fprintf(stderr, "\n"); /* Clean up after percent display */
	magic_routine = i; 

	fprintf(stderr, "NOTICE: NWLogger: (cookie) Address #1: %08x\n", magic_routine + code_header->sh_addr ); 

/* Locate the first call to the magic routine. */ 

	first_call = second_call = 0; 
	i = 0; 
	pct_complete = ((float)i / ((int)code_header->sh_size)) * 100.0; 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Searching executable: %02d", (int)pct_complete); 
	while( i < (int)code_header->sh_size ) { 
		pct_complete = ((float)i / ((int)code_header->sh_size)) * 100.0; 
		if( ((int)pct_complete % 4) == 0 ) { 
			printf("%02d", (int)pct_complete); 
		}
		memset(&current_instruction, 0, sizeof(struct code)); 
		instruction_size = NWL_disassemble_address_ptr( (char *)buffer_ptr + i, &current_instruction ); 
		if( instruction_size ) { 
			if( strcmp(current_instruction.mnemonic, "push") == 0 && strcmp(current_instruction.dest, "ebx") == 0 ) { 
				push_ebx_addr = i; 
			} 
			if( strcmp(current_instruction.mnemonic, "call") == 0 ) { 
				call_destination = i + current_instruction.size + strtol(current_instruction.dest, NULL, 0); 
				if( call_destination == magic_routine ) { 
					first_call = i; 
					break; 
				}
			}
		} else { 
			fprintf(stderr, "\nERROR: NWLogger: (cookie) Invalid instruction disassembled: %08x\n", i); 
			fprintf(stderr, "ERROR: NWLogger: (cookie) Probably a bug in libdis.\n"); 
			fprintf(stderr, "ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
			abort();
		}
		i += instruction_size; 
	}
	fprintf(stderr, "\n"); /* Clean up after percent display */
	if( first_call == 0 ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) Failed to locate the first call to the magic routine.\n"); 
		fprintf(stderr, "ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Magic hook location: 0x%08x\n", push_ebx_addr + code_header->sh_addr ); 


/* Theoretically we could quit here, but lets check it out.  The 2nd call after 'first_call' should be
   another call to the magic routine 
 */ 

	call_counter = 0; 
	i = first_call; 

	pct_complete = ((float)i / ((int)code_header->sh_size)) * 100.0; 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Searching executable: %02d", (int)pct_complete); 
	while( i< (int)code_header->sh_size ) { 
		pct_complete = ((float)i / ((int)code_header->sh_size)) * 100.0; 
		if( ((int)pct_complete % 4) == 0 ) { 
			printf("%02d", (int)pct_complete); 
		}
		memset(&current_instruction, 0, sizeof(struct code));
		memset(&current_instruction, 0, sizeof(struct code)); 
		instruction_size = NWL_disassemble_address_ptr( (char *)buffer_ptr + i, &current_instruction ); 
		if( instruction_size ) { 
			if( strcmp(current_instruction.mnemonic, "call") == 0 ) { 
				call_counter++; 
			} 
			if( call_counter == 3 ) { 
				second_call = i; 
				break; 
			} 
		} else { 
			fprintf(stderr, "\nERROR: NWLogger: (cookie) Invalid instruction disassembled: %08x\n", i); 
			fprintf(stderr, "ERROR: NWLogger: (cookie) Probably a bug in libdis.\n"); 
			fprintf(stderr, "ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
			abort();
		}
		i += instruction_size; 
	}
	fprintf(stderr, "\n"); /* Clean up after percent display */

	if( second_call != 0 ) { 
		memset(&current_instruction, 0, sizeof(struct code)); 
		NWL_disassemble_address_ptr( (char *)buffer_ptr + second_call, &current_instruction ); 
	} else { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) Failed to locate the second call to the magic routine.\n"); 
		fprintf(stderr, "ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}

	if( strcmp(current_instruction.mnemonic, "call") != 0 ) { 	
		fprintf(stderr, "ERROR: NWLogger: (cookie) 2nd Call 0x%08x Instruction mismatch. %s\n", second_call, current_instruction.mnemonic ); 
		fprintf(stderr, "ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}
	call_destination = second_call + current_instruction.size + strtol(current_instruction.dest, NULL, 0); 
	if( call_destination != magic_routine ) { 
		fprintf(stderr, "ERROR: NWLogger: (cookie) 2nd Call 0x%08x did not point to magic routine: 0x%08x\n", second_call, call_destination ); 
		fprintf(stderr, "ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}
	calls[0] = calls[1] = calls[2] = calls[3] = calls[4] = 0; 

	calls[1] = (unsigned long)NWLogger_findacrumb( buffer_ptr, code_header, NWLogger_load_cookies, 1 ); 
	if( calls[1] == 0 ) { 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie) Function #1 Not found. .\n"); 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}

	/* Search for ret, and then 2nd push  - to finish out location of patch #1 */	
	call_counter = 0; 
	i = (int)calls[1]; 
	strcpy(search_instr, "ret"); 		/* What we search for */

	pct_complete = ((float)i / ((int)code_header->sh_size)) * 100.0; 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Searching executable: %02d", (int)pct_complete); 
	while( i < (int)code_header->sh_size ) {
		pct_complete = ((float)i / ((int)code_header->sh_size)) * 100.0; 
		if( ((int)pct_complete % 4) == 0 ) { 
			printf("%02d", (int)pct_complete); 
		}
		memset(&current_instruction, 0, sizeof(struct code));
		memset(&current_instruction, 0, sizeof(struct code));
		instruction_size = NWL_disassemble_address_ptr( (char *)buffer_ptr + i, &current_instruction );
		if( instruction_size ) {
			if( strcmp(current_instruction.mnemonic, search_instr) == 0 ) { 
				call_counter++; 
			}
			if( call_counter == 1 ) { 
				strcpy(search_instr, "push"); 
			}
			if( call_counter == 4 ) { 
				break; 
			} 
			i += instruction_size; 
		} else { 
			fprintf(stderr, "\nERROR: NWLogger: (cookie) Invalid instruction disassembled: %08x\n", i); 
			fprintf(stderr, "ERROR: NWLogger: (cookie) Probably a bug in libdis.\n"); 
			fprintf(stderr, "ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
			abort();
		}
	}
	fprintf(stderr, "\n"); /* Clean up after percent display */
	calls[1] = i; 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Function #1 location: %08x\n", (unsigned int)calls[1]); 

	calls[2] = (unsigned long)NWLogger_findacrumb( buffer_ptr, code_header, NWLogger_dead_cookies , 2 ); 
	if( calls[2] == 0 ) { 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie) Function #2 Not found. .\n"); 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Function #2 location: %08x\n", (unsigned int)calls[2]); 

	calls[3] = (unsigned long)NWLogger_findacrumb( buffer_ptr, code_header, NWLogger_spwn_cookies, 1 ); 
	if( calls[3] == 0 ) { 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie) Function #3 Not found. .\n"); 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Function #3 location: %08x\n", (unsigned int)calls[3]); 

	calls[4] = (unsigned long)NWLogger_findacrumb( buffer_ptr, code_header, NWLogger_exit_cookies, 1); 
	if( calls[4] == 0 ) { 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie) Function #4 Not found. .\n"); 
		fprintf(stderr, "SERIOUS FATAL ERROR: NWLogger: (cookie)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
		abort(); 
	}
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Function #4 location: %08x\n", (unsigned int)calls[4]); 
	

	/* Hey it all matches up. */

	calls[0] = (unsigned long)push_ebx_addr; 

/* Calls "loaded".  Correct into virtual addresses */

	calls[0] = calls[0] + code_header->sh_addr; 
	calls[1] = calls[1] + code_header->sh_addr; 
	calls[2] = calls[2] + code_header->sh_addr; 
	calls[3] = calls[3] + code_header->sh_addr; 
	calls[4] = calls[4] + code_header->sh_addr; 

	fprintf(stderr, "NOTICE: NWLogger: (cookie) Recalculated calls 0: %08x\n", (unsigned int)calls[0]); 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Recalculated calls 1: %08x\n", (unsigned int)calls[1]); 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Recalculated calls 2: %08x\n", (unsigned int)calls[2]); 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Recalculated calls 3: %08x\n", (unsigned int)calls[3]); 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Recalculated calls 4: %08x\n", (unsigned int)calls[4]); 
		
	elf_end(elf_ptr); 
	munmap(buffer, statbuf.st_size ); 
	close(fd); 
	dlclose(dlhandle); 
	return(calls); 
}

unsigned long NWLogger_findacrumb(unsigned char *buf, Elf32_Shdr *header, char **crumb, int counts) 
{
	int i;  
	int matches_found; 
	unsigned long		start_address; 
	struct 		instr 	current_instruction;
	float			pct_complete;
	int			instruction_size;
	unsigned int		xx; 
	int			current_count = 0; 

	xx = 0; 
	i = 0; 
	pct_complete = ((float)i / ((int)header->sh_size)) * 100.0; 
	fprintf(stderr, "NOTICE: NWLogger: (cookie) Searching executable: %02d", (int)pct_complete); 
	while( current_count < counts ) { 

		matches_found = 0; 
		start_address = 0; 

		while( i < (int)header->sh_size ) { 

#ifndef LIBDISDEBUG

			pct_complete = ((float)i / ((int)header->sh_size)) * 100.0; 
			if( ((int)pct_complete % 4) == 0 ) { 
				printf("%02d", (int)pct_complete); 
			}
#endif
			memset(&current_instruction, 0, sizeof(struct code));
			instruction_size = NWL_disassemble_address_ptr( (char *)buf + i, &current_instruction ); 
			if( instruction_size ) { 

#ifdef LIBDISDEBUG
					printf("%02d %08x ", matches_found, i + header->sh_addr); 
					for (xx = 0; xx < 12; xx++) {
						if (xx < instruction_size) printf("%02x ", buf[i + xx]);
						else printf("   ");
					}
	
					printf("%s", current_instruction.mnemonic);
					if (current_instruction.dest[0] != 0) printf("\t%s", current_instruction.dest);
					if (current_instruction.src[0] != 0) printf(", %s", current_instruction.src);
					if (current_instruction.aux[0] != 0) printf(", %s", current_instruction.aux);
					printf("\n");
#endif
				
				if( strcmp(current_instruction.mnemonic, (char *)crumb[matches_found]) == 0 ) { 
					matches_found++; 
					if( matches_found == 1 ) { start_address = i; } 
					if( crumb[matches_found] == NULL ) { 
						break; 
					}
				} else { 
					matches_found = 0; 
					if( strcmp(current_instruction.mnemonic, (char *)crumb[matches_found]) == 0 ) { 
						matches_found++; 
						if( matches_found == 1 ) { start_address = i; }
						if( crumb[matches_found] == NULL ) { 
							break; 
						}
					}
				}
				i += instruction_size; 
			} else { 
				fprintf(stderr, "\nERROR: NWLogger: (crumb) Invalid instruction disassembled: %08x\n", i); 
				fprintf(stderr, "ERROR: NWLogger: (crumb) Probably a bug in libdis.\n"); 
				fprintf(stderr, "ERROR: NWLogger: (crumb)    Please contact David Holland (david.w.holland@gmail.com)\n"); 
				abort();
			}
		}
	current_count++; 
	}
	fprintf(stderr, "\n"); /* Clean up after percent display */
	return(start_address); 
}

