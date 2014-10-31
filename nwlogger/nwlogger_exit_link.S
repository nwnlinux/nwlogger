/*
 * Link the modified nwmain with the nwlogger C code
 */

	.text

	.align	4,0x90
	.globl	NWLogger_writeexitlog
	.globl	NWLogger_writeexitlog_start
	.globl	NWLogger_writeexitlog_end
NWLogger_writeexitlog:
	nop

	pusha
	call	NWLogger_write_exit_log
	popa
NWLogger_writeexitlog_start:
	/* replicate code we whacked */

	push   %esi
	push   %ebx
	cmpl   $0x1,0xc(%ebp)

NWLogger_writeexitlog_end:
	nop
	jmp	*_NWL_exit_retaddr
