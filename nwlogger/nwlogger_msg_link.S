/*
 * Link the modified nwmain with the nwlogger C code
 */

	.text

	.align	4,0x90
	.globl	NWLogger_writemsglog
NWLogger_writemsglog:
	mov %ebx, _NWLogger_EBX

	/* replicate code we whacked */
	push	%ebx
	mov	0x8(%ebp),%eax
	pushl	0x8(%eax)

	pusha
	call	NWLogger_writelog2
	popa

	jmp	*_NWL_msg_retaddr
