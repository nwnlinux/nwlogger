/*
 * Link the modified nwmain with the nwlogger C code
 */

	.text

	.align	4,0x90
	.globl	NWLogger_writespwnlog
	.globl	NWLogger_writespwnlog_start
	.globl  NWLogger_writespwnlog_end
NWLogger_writespwnlog:
	nop

	/* replicate code we whacked */
NWLogger_writespwnlog_start:
	push   %ebx
	sub    $0x10,%esp
	mov    0xfffffff,%eax

NWLogger_writespwnlog_end:
	nop

	pusha
	call	NWLogger_write_spwn_log
	popa

	jmp	*_NWL_spwn_retaddr
