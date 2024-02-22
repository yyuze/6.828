#include "ns.h"

#include <inc/lib.h>
#include <inc/stdio.h>

extern union Nsipc nsipcbuf;

void
output(envid_t ns_envid)
{
	binaryname = "ns_output";

	// LAB 6: Your code here:
	// 	- read a packet from the network server
	//	- send the packet to the device driver
    int ret = 0;
    while (true) {
        ret = ipc_recv(NULL, &nsipcbuf, NULL);
        if (ret != NSREQ_OUTPUT)
            panic("invalid request id: 0x%x\n", ret);
        struct jif_pkt *pkt = &nsipcbuf.pkt;
        size_t acc = 0;
        while (acc < pkt->jp_len) {
            ret = sys_net_send((void *)((uintptr_t)pkt->jp_data + acc), pkt->jp_len - acc);
            if (ret < 0) {
                ERR("send data failed: %e\n", ret);
                break;
            }
            acc += ret;
        }
    }
}
