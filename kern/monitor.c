// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line

struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
    { "backtrace", "Display the kernel stack backtrace", mon_backtrace },
    { "mapinfo", "Display map info of [va, va + len)", mon_mapinfo},
    { "memdump", "Display mem bytes on [addr, addr + len)", mon_memdump},
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int __attribute__((noinline))mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    if (tf == NULL)
        cprintf("Stack backtrace:\n");
	// Your code here.
    uint32_t cur_ebp = tf == NULL ? read_ebp() : tf->ebp;
    struct {
        struct Trapframe cur_frame;
        uint32_t args[5];
    } invoc;
    memcpy(&invoc, (void *)cur_ebp, sizeof(invoc));
    cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n",
            invoc.cur_frame.ebp, invoc.cur_frame.eip,
            invoc.args[0], invoc.args[1], invoc.args[2], invoc.args[3], invoc.args[4]);

    struct Eipdebuginfo info;
    debuginfo_eip(invoc.cur_frame.eip, &info);
    cprintf("         %s:%u: %.*s+%u\n",
            info.eip_file, info.eip_line,
            info.eip_fn_namelen, info.eip_fn_name,
            invoc.cur_frame.eip - info.eip_fn_addr);
    if (invoc.cur_frame.ebp == 0) {
        return 0;
    }
    mon_backtrace(argc, argv, &invoc.cur_frame);
	return 0;
}

static unsigned long stoi(const char *str)
{
    static char c2i[] = {
        ['0'] = 0, ['1'] = 1, ['2'] = 2, ['3'] = 3,
        ['4'] = 4, ['5'] = 5, ['6'] = 6, ['7'] = 7,
        ['8'] = 8, ['9'] = 9, ['a'] = 10, ['b'] = 11,
        ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15,
    };
    unsigned long exp;
    if (str[0] == '0') {
        if (str[1] == 'x') {
            exp = 16;
            str += 2;
        } else {
            exp = 8;
            str += 1;
        }
    } else {
        exp = 10;
    }
    unsigned long base = 1;
    unsigned long num = 0;
    for (int i = strlen(str) - 1; i >=0; i--) {
        num += c2i[(unsigned)str[i]] * base;
        base *= exp;
    }
    return num;
}

#include <kern/pmap.h>
int mon_mapinfo(int argc, char **argv, struct Trapframe *tf)
{
    uintptr_t va = 0;
    unsigned long size = 0;
    for (int i = 1; i < argc; ++i) {
        if (memcmp(argv[i], "-va", strlen("-va")) == 0) {
            va = (uintptr_t)stoi(argv[++i]);
        } else if (memcmp(argv[i], "-size", strlen("-size")) == 0) {
            size = stoi(argv[++i]);
        } else {
            ERR("unkown param: %s\n", argv[i]);
            goto help;
        }
    }
    if (va == 0 || size == 0) {
        ERR("missing args\n");
        goto help;
    }
    physaddr_t pgdir_pa = rcr3();
    pde_t *pgdir = KADDR(pgdir_pa);
    va = ROUNDDOWN(va, PGSIZE);
    size = ROUNDUP(size, PGSIZE);
    for (unsigned long offset = 0; offset < size; offset += PGSIZE) {
        pte_t *pte_ptr = pgdir_walk(pgdir, (void *)(va + offset), 0);
        static PTE zero_pte = { 0 };
        PTE *pte = pte_ptr != NULL ? (PTE *)(pte_ptr) : &zero_pte;
        INFO("%08lx-%08lx: PA %08x | AVAIL %x | D %x | A %x | U/S %x | R/W %x | P %x\n",
             va + offset, va + offset + PGSIZE,
             pte->bits.PA << 12,
             pte->bits.AVAIL,
             pte->bits.D,
             pte->bits.A,
             pte->bits.U_S,
             pte->bits.R_W,
             pte->bits.P);
    }
    goto end;

help:
    INFO("-va: start addr of [va, va + size)\n");
    INFO("-size: size of [va, va + size)\n");
end:
    return 0;
}

#define BYTE_PER_LINE 16
static void memdump(const char *addr, unsigned long cnt, bool zero)
{
    for (unsigned long i = 0; i < cnt; ++i) {
        if (i != 0 && i % BYTE_PER_LINE == 0)
            INFO("\n");
        INFO("%02x ", zero ? 0 : (uint8_t)addr[i]);
    }
    INFO("\n");
}

int mon_memdump(int argc, char **argv, struct Trapframe *tf)
{
    bool physical = false;
    unsigned long addr = 0;
    unsigned long size = 0;
    if (argc < 3)
        goto help;
    for (int i = 1; i < argc; ++i) {
        if (memcmp(argv[i], "-p", strlen("-p")) == 0) {
            physical = true;
        } else {
            if (argc - i != 2)
                goto help;
            addr = stoi(argv[i++]);
            size = stoi(argv[i++]);
        }
    }
    addr = physical ? (unsigned long)KADDR(addr) : addr;
    pde_t *pgdir = KADDR(rcr3());
    unsigned long acc = 0;
    if (size > 0xFFFFFFFF - addr)
        size = 0xFFFFFFFF - addr;
    while (acc < size) {
        char *addr_ptr = (char *)(uintptr_t)addr + acc;
        pte_t *pte_ptr = pgdir_walk(pgdir, (void *)addr_ptr, 0);
        static PTE zero_pte = { 0 };
        PTE *pte = pte_ptr != NULL ? (PTE *)(pte_ptr) : &zero_pte;
        unsigned long cnt = size - acc > PGSIZE ? PGSIZE : size - acc;
        memdump(addr_ptr, cnt, pte->bits.P == 0);
        acc += cnt;
    }
    goto end;
help:
    INFO("[-p] start size: dump memory [start, start + size)\n");
    INFO("-p: dump physical memory\n");
end:
    return 0;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
