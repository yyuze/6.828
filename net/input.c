#include "ns.h"

extern union Nsipc nsipcbuf;

void
input(envid_t ns_envid)
{
	binaryname = "ns_input";

	// LAB 6: Your code here:
	// 	- read a packet from the device driver
	//	- send it to the network server
	// Hint: When you IPC a page to the network server, it will be
	// reading from it for a while, so don't immediately receive
	// another packet in to the same physical page.
    int ret = 0;
    memset(&nsipcbuf, 0, sizeof(&nsipcbuf));
    while (true) {
        /* allocate buf to send */
        union Nsipc *buf = get_buffer();
        if (buf == NULL) {
            panic("alloc buf failed\n");
            sys_yield();
            continue;
        }
        ret = sys_page_alloc(thisenv->env_id, buf, PTE_P | PTE_U | PTE_W);
        if (ret != 0)
            panic("map buf failed: %e\n", ret);
        /* receive package from kernel */
        ret = sys_net_recv(nsipcbuf.pkt.jp_data, sizeof(nsipcbuf) - sizeof(struct jif_pkt));
        if (ret < 0)
            panic("recv data failed: %e\n", ret);
        if (ret == 0) {
            sys_yield();
            goto free_buf;
        }
        int cnt = ret;
        /* send received package to ns-server */
        buf->pkt.jp_len = cnt;
        memcpy(buf->pkt.jp_data, nsipcbuf.pkt.jp_data, cnt);
        ipc_send(ns_envid, NSREQ_INPUT, buf, PTE_P | PTE_U);
        /* free buf */
free_buf:
        ret = sys_page_unmap(thisenv->env_id, buf);
        if (ret != 0)
            panic("unmap failed: %e\n", ret);
        put_buffer(buf);
    }
}
