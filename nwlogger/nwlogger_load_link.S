/*
 * Link the modified nwmain with the nwlogger C code
 */

	.text

	.align	4,0x90
	.globl	NWLogger_writeloadlog
	.globl	NWLogger_writeloadlog_start
	.globl	NWLogger_writeloadlog_end

NWLogger_writeloadlog:
	nop

NWLogger_writeloadlog_start:
	/* replicate code we whacked */
	push   %esi
	push   %ebx
	sub    $0xc8,%esp

NWLogger_writeloadlog_end:
	nop

	pusha
	call	NWLogger_write_load_log
	popa

	jmp	*_NWL_load_retaddr
