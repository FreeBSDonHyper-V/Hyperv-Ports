
#define	LOCORE

#include <machine/asmacros.h>
#include <x86/apicreg.h>
#include "assym.s" 


/*
 * This is the Hyper-V vmbus channel direct callback interrupt.
 * Only used when it is running on Hyper-V.
 */
	.text
	SUPERALIGN_TEXT
IDTVEC(hv_vmbus_callback)
	PUSH_FRAME
	FAKE_MCOUNT(TF_RIP(%rsp))
        movq     %rsp, %rdi
        call hv_vector_handler
	MEXITCOUNT
	jmp	doreti
