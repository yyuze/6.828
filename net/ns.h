#include <inc/ns.h>
#include <inc/lib.h>

#define IP "10.0.2.15"
#define MASK "255.255.255.0"
#define DEFAULT "10.0.2.2"

#define TIMER_INTERVAL 250

// Virtual address at which to receive page mappings containing client requests.
#define QUEUE_SIZE	20
#define REQVA		(0x0ffff000 - QUEUE_SIZE * PGSIZE)

/* timer.c */
void timer(envid_t ns_envid, uint32_t initial_to);

/* input.c */
void input(envid_t ns_envid);

/* output.c */
void output(envid_t ns_envid);

static bool buse[QUEUE_SIZE];

static inline void *get_buffer(void) {
	void *va;

	int i;
	for (i = 0; i < QUEUE_SIZE; i++)
		if (!buse[i]) break;

	if (i == QUEUE_SIZE) {
		panic("NS: buffer overflow");
		return 0;
	}

	va = (void *)(REQVA + i * PGSIZE);
	buse[i] = 1;

	return va;
}

static inline void put_buffer(void *va) {
	int i = ((uint32_t)va - REQVA) / PGSIZE;
	buse[i] = 0;
}
