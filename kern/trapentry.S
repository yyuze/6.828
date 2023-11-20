/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
TRAPHANDLER_NOEC(trap_devide,                       T_DIVIDE)
TRAPHANDLER_NOEC(trap_debug,                        T_DEBUG)
TRAPHANDLER_NOEC(trap_non_mask_interrupt,           T_NMI)
TRAPHANDLER_NOEC(trap_breakpointer,                 T_BRKPT)
TRAPHANDLER_NOEC(trap_overflow,                     T_OFLOW)
TRAPHANDLER_NOEC(trap_bounds_check,                 T_BOUND)
TRAPHANDLER_NOEC(trap_illegal_opcode,               T_ILLOP)
TRAPHANDLER_NOEC(trap_device_not_available,         T_DEVICE)
TRAPHANDLER(trap_double_fault,                      T_DBLFLT)
TRAPHANDLER(trap_invalid_task_switch_segment,       T_TSS)
TRAPHANDLER(trap_segment_not_present,               T_SEGNP)
TRAPHANDLER(trap_stack_exception,                   T_STACK)
TRAPHANDLER(trap_general_protection_fault,          T_GPFLT)
TRAPHANDLER(trap_page_fault,                        T_PGFLT)
TRAPHANDLER_NOEC(trap_floating_point_error,         T_FPERR)
TRAPHANDLER_NOEC(trap_alignment_check,              T_ALIGN)
TRAPHANDLER_NOEC(trap_machine_check,                T_MCHK)
TRAPHANDLER_NOEC(trap_SIMD_floating_point_error,    T_SIMDERR)
TRAPHANDLER_NOEC(trap_syscall,                      T_SYSCALL)

/* Lab4: irqs */
TRAPHANDLER_NOEC(trap_irq_0,    IRQ_OFFSET + 0)
TRAPHANDLER_NOEC(trap_irq_1,    IRQ_OFFSET + 1)
TRAPHANDLER_NOEC(trap_irq_2,    IRQ_OFFSET + 2)
TRAPHANDLER_NOEC(trap_irq_3,    IRQ_OFFSET + 3)
TRAPHANDLER_NOEC(trap_irq_4,    IRQ_OFFSET + 4)
TRAPHANDLER_NOEC(trap_irq_5,    IRQ_OFFSET + 5)
TRAPHANDLER_NOEC(trap_irq_6,    IRQ_OFFSET + 6)
TRAPHANDLER_NOEC(trap_irq_7,    IRQ_OFFSET + 7)
TRAPHANDLER_NOEC(trap_irq_8,    IRQ_OFFSET + 8)
TRAPHANDLER_NOEC(trap_irq_9,    IRQ_OFFSET + 9)
TRAPHANDLER_NOEC(trap_irq_10,   IRQ_OFFSET + 10)
TRAPHANDLER_NOEC(trap_irq_11,   IRQ_OFFSET + 11)
TRAPHANDLER_NOEC(trap_irq_12,   IRQ_OFFSET + 12)
TRAPHANDLER_NOEC(trap_irq_13,   IRQ_OFFSET + 13)
TRAPHANDLER_NOEC(trap_irq_14,   IRQ_OFFSET + 14)
TRAPHANDLER_NOEC(trap_irq_15,   IRQ_OFFSET + 15)

/*
 * Lab 3: Your code here for _alltraps
 */
.globl _alltraps;
_alltraps:
    /* according to https://pdos.csail.mit.edu/6.828/2018/readings/i386/INT.htm --- INTERRUPT-FROM-V86-MODE */
    # pushl (32)(%esp)    /* tf_padding2 : tf_ds, bug for qemu, expect: 0x23 */
    # pushl (32)(%esp)    /* tf_padding1 : tf_es, bug for qemu, expect: 0x23 */
    pushw $0;           /* tf_padding2 */
    pushw %ds;          /* tf_ds */
    pushw $0;           /* tf_padding1 */
    pushw %es;          /* tf_es */
    pushal;             /* tf_regs */
    pushl %esp;         /* struct Trapframe* */

    movw $GD_KD, %ax
    movw %ax, %ds;
    movw %ax, %es;

    call trap;
