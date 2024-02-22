#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>

int pci_e1000_attach(struct pci_func *pf);
int e1000_send(void *src, size_t src_sz);
int e1000_recv(void *dst, size_t dst_sz);

#endif  // SOL >= 6
