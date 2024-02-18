// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) ROUNDDOWN(utf->utf_fault_va, PGSIZE);
	uint32_t err = utf->utf_err;
	int r = 0;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).
	// LAB 4: Your code here.
    unsigned pn = ((uintptr_t)addr) >> 12;
    pte_t pte = uvpt[pn];
    if ((err & FEC_WR) == 0) {
        ERR("page fault is not caused by write access\n");
        goto err;
    }
    if ((pte & PTE_COW) == 0) {
        ERR("page is not COW, pte: 0x%08x, 0x%08x\n", pte, (uintptr_t)addr);
        goto err;
    }

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.
    void *temp = (void *)PFTEMP;
    r = sys_page_alloc(thisenv->env_id, temp, PTE_P | PTE_W | PTE_U);
    if (r != 0) {
        ERR("allocate temp page failed\n");
        goto err;
    }
    memcpy(temp, addr, PGSIZE);
    r = sys_page_map(thisenv->env_id, temp, thisenv->env_id, addr, PTE_P | PTE_W | PTE_U);
    if (r != 0) {
        ERR("remap page failed\n");
        goto err;
    }
    r = sys_page_unmap(thisenv->env_id, temp);
    if (r != 0) {
        ERR("unmap temp page failed\n");
        goto err;
    }
    goto end;

err:
    panic("handler page fault failed, fault va: %p, pte: 0x%08x, fault eip: 0x%x, errcode: 0x%x, r: %e\n",
          addr, pte, utf->utf_eip, err, r);
end:
    return;
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function? Answer: also trigger cow when page is written by parent)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int ret = 0;
	// LAB 4: Your code here.
    pte_t pte = uvpt[pn];
    int perm = 0;
    if ((pte & PTE_SHARE) != 0) {
        /* shared page */
        perm = pte & PTE_SYSCALL;
    } else if ((pte & PTE_COW) != 0 || (pte & PTE_W) != 0) {
        /* cow page */
        perm = PTE_P | PTE_U | PTE_COW;
    } else {
        /* read only page */
        perm = PTE_P | PTE_U;
    }
    uintptr_t va = pn * PGSIZE;
    ret = sys_page_map(thisenv->env_id, (void *)va, envid, (void *)va, perm);
    if (ret != 0) {
        ERR("map child cow page failed, 0x%08x\n", va);
        goto end;
    }
    ret = sys_page_map(thisenv->env_id, (void *)va, thisenv->env_id, (void *)va, perm);
    if (ret != 0) {
        ERR("remap self page failed, 0x%08x\n", va);
        goto unmap_child;
    }
    goto end;
unmap_child:
    (void)sys_page_unmap(envid, (void *)va);
end:
	return ret;
}

static int dup_pages(envid_t env_id)
{
    int ret = 0;
    for (uintptr_t i = 0; i < USTACKTOP - PGSIZE; i += PGSIZE) {
        if (i == (uintptr_t)ROUNDDOWN(&thisenv, PGSIZE))
            /* skip page which contains 'thisenv' */
            continue;
        unsigned pn = i >> 12;
        unsigned pdn = pn >> 10;
        if ((uvpd[pdn] & PTE_P) == 0 || (uvpt[pn] & PTE_P) == 0)
            continue;
        ret = duppage(env_id, pn);
        if (ret != 0) {
            ERR("duppage failed, va: 0x%x\n", i);
            goto end;
        }
    }
end:
    return ret;
}

static int dup_normal_page(envid_t env_id, void *va)
{
    int ret = 0;
    pte_t pte = uvpt[((uintptr_t)va) >> 12];
    if ((pte & PTE_P) == 0) {
        ERR("page is not presented, %p\n", va);
        goto end;
    }
    ret = sys_page_alloc(env_id, va, pte & 0x7);
    if (ret != 0) {
        ERR("allocate child va %p failed, %e\n", va, ret);
        goto end;
    }
    void *temp = (void *)UTEMP;
    ret = sys_page_map(env_id, va, thisenv->env_id, temp, PTE_P | PTE_U | PTE_W);
    if (ret != 0) {
        ERR("map child va %p to UTEMP failed, %e\n", va, ret);
        goto end;
    }
    memcpy(temp, va, PGSIZE);
    ret = sys_page_unmap(thisenv->env_id, temp);
    if (ret != 0) {
        ERR("unmap UTEMP failed, %e\n", ret);
        goto end;
    }
end:
    return ret;
}

static int dup_stack(envid_t env_id)
{
    int ret = 0;
    /* allocate new exception stack */
    ret = sys_page_alloc(env_id, (void *)(UXSTACKTOP - PGSIZE), PTE_P | PTE_U | PTE_W);
    if (ret != 0) {
        ERR("allocate child exception stack failed, %e\n", ret);
        goto end;
    }
    /* dup a new normal stack */
    ret = dup_normal_page(env_id, (void *)USTACKTOP - PGSIZE);
    if (ret != 0) {
        ERR("dup stack failed\n");
        goto end;
    }
end:
    return ret;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
    set_pgfault_handler(pgfault);
    envid_t env_id = sys_exofork();
    if (env_id == 0) {
        /* child */
        thisenv = &envs[ENVX(sys_getenvid())];
        goto end;
    } else if (env_id > 0) {
        /* parent */
        int ret = 0;
        /*
         * 'thisenv' should be set without any pgfault in child process,
         * otherwise there is no way to correct thisenv->env_id, so that we cannot
         * handle any page fault including the one caused by access 'thisenv'
         * with the incorrect env_id.
         */
        ret = dup_normal_page(env_id, (void *)ROUNDDOWN((uintptr_t)&thisenv, PGSIZE));
        if (ret != 0) {
            ERR("dup 'thisenv' page failed\n");
            goto err;
        }
        /*
         * allocate a new exception stack, and dup a rw normal stack,
         * if stack cow, it will be impossible to execute any functions in child,
         * including 'sys_getenvid()', so caused a page fault which cannot be handled
         */
        ret = dup_stack(env_id);
        if (ret != 0) {
            ERR("dup stack failed\n");
            goto err;
        }
        /*
         * dup other pages to be cow
         */
        ret = dup_pages(env_id);
        if (ret != 0) {
            ERR("dup pages failed\n");
            goto err;
        }
        ret = sys_env_set_status(env_id, ENV_RUNNABLE);
        if (ret != 0) {
            ERR("set child env to runnable failed, %e\n", ret);
            goto err;
        }
    } else {
        ERR("fork syscall failed, %e\n", -env_id);
        goto err;
    }
    goto end;

err:
    panic("fork failed\n");
end:
    return env_id;
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
