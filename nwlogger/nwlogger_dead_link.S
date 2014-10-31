/*
 * Link the modified nwmain with the nwlogger C code
 */

	.text

	.align	4,0x90
	.globl NWLogger_writedeadlog
	.globl NWLogger_writedeadlog_start
	.globl NWLogger_writedeadlog_end
NWLogger_writedeadlog:
	nop 

NWLogger_writedeadlog_start:
	/* replicate code we whacked */
	push   %esi
	push   %ebx
	mov    0x8(%ebp),%esi

NWLogger_writedeadlog_end:
	nop

	pusha
	call	NWLogger_write_dead_log
	popa

	jmp	*_NWL_dead_retaddr
