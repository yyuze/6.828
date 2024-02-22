// LAB 6: Your driver code here
#include <kern/e1000.h>
#include <kern/e1000_hw.h>
#include <kern/pmap.h>
#include <kern/pci.h>

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/error.h>
#include <inc/types.h>
#include <inc/assert.h>
#include <inc/x86.h>

union TDESC {
    struct {
        uint64_t BufferAddress      : 64;   /* Address of the transmit data in the host memory, if TDESC.CMD.RS == 1 then TDESC>STATUS.DD is written when hardware processes transmit */
        uint64_t Length             : 16;   /* Legnth of buffer pointed by TDESC.BufferAddress. Max: 16288 */
        uint64_t CSO                : 8;    /* Checksum Offset */
        uint64_t CMD_EOP            : 1;    /* End Of Packet. When set indicates the last descriptor making up the packet. One or many descriptors can be used to form a packet */
        uint64_t CMD_IFCS           : 1;    /* Insert FCS. Insert FCS/CRC field in normal Ethernet packet. Is valid only when EOP is set */
        uint64_t CMD_IC             : 1;    /* Insert Checksum. When set, the Ethernet controller needs to insert a checksum at the offset indicated by TDESC.CSO field. Is valid only when EOP is set */
        uint64_t CMD_RS             : 1;    /* Report Status. Enable the Ethernet controller to report the transmit status infomation. For software debug use */
        uint64_t CMD_RSV            : 1;
        uint64_t CMD_DEXT           : 1;    /* Extension, should be 0 for legacy mode */
        uint64_t CMD_VLE            : 1;    /* VLAN Packet Enable */
        uint64_t CMD_IDE            : 1;    /* Interrupt Delay Enable. Enable the transmit interrupt delay timer */
        uint64_t STA_DD             : 1;    /* Descriptor Done. Indicates that the descriptor is finished and is written back after the descriptor has been processed (with RS set) */
        uint64_t STA_EC             : 1;    /* Excess Collisions. Indicates that the packet has experienced more than the maximum excessive collisions as defined by TCTL.CT and was not transmitted */
        uint64_t STA_LC             : 1;    /* Late Collision. Indicates that late collision occured while working in harf-duplex mode */
        uint64_t STA_REV            : 1;
        uint64_t RSV                : 4;
        uint64_t CSS                : 8;    /* Checksum Start Field */
        uint64_t Special            : 16;
    } bits;
    uint8_t val[16];
} __attribute__((packed));

/* Transmit Descriptor Base Address Low (for 32-bit) register */
union TDBAL {
    struct {
        uint32_t ZERO       : 4;    /* ignored */
        uint32_t TDBAL      : 28;   /* lower 32 bits of the start address for the td ringbuffer */
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Transmit Descriptor Length register */
union TDLEN {
    struct {
        uint32_t ZERO       : 7;    /* ignored */
        uint32_t LEN        : 13;   /* number of bytes of the td ringbuffer */
        uint32_t Reserved   : 12;
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Transmit Descriptor Head register */
union TDH {
    struct {
        uint32_t TDH        : 16;   /* td ringbuffer head */
        uint32_t Reserved   : 16;
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Transmit Descriptor Tail register */
union TDT {
    struct {
        uint32_t TDT        : 16;   /* td ringbuffer tail */
        uint32_t Reserved   : 16;
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Transmit Control register */
union TCTL {
    struct {
        uint32_t Reserved0  : 1;
        uint32_t EN         : 1;    /* 1 for enable, 0 for disable. After write 0, Data remains in transmit FIFO until the device is re-enable */
        uint32_t Reserved1  : 1;
        uint32_t PSP        : 1;    /* Pad Short Packets, 0 for do not pad, 1 for Pad. Padding makes the packet 64-bytes long */
        uint32_t CT         : 8;    /* Collision Threshold, determines the retry number before giving up on a packet, recommand 0x0F */
        uint32_t COLD       : 10;   /* Collision Distance, minimal number of byte times that must elapse for proper CSMA/CD operation, recommand: 0x200(512 byte-time) for Half Duplex, 0x40(64 byte-time) for Full duplex */
        uint32_t SWXOFF     : 1;    /* Software XOFF Transmission, 1 for shecdule a XOFF(PAUSE) frame using the currenct value of the PAUSE timer (FCTTV.TTV). Self-clears. Only valid in Full-Duplex mode */
        uint32_t Reserved2  : 1;
        uint32_t RTLC       : 1;    /* Re-transmit on Late Collision, enable the Ethernet controller to re-transmit on a late collision event */
        uint32_t Reserved3  : 1;
        uint32_t Reserved4  : 6;
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Transmit Inter Packet Gap register */
union TIPG {
    struct {
        uint32_t IPGT       : 10;   /* Inter Packet Gap Transmit Time */
        uint32_t IPGR1      : 10;   /* Inter Packet Gap Receive Time 1 */
        uint32_t IPGR2      : 10;   /* Inter Packet Gap Receive TIme 2 */
        uint32_t Reserved   : 2;
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Receive Address High register */
union RA {
    struct {
        uint32_t RA_0       : 8;
        uint32_t RA_1       : 8;
        uint32_t RA_2       : 8;
        uint32_t RA_3       : 8;
        uint32_t RA_4       : 8;
        uint32_t RA_5       : 8;
        uint32_t AS         : 2;    /* Address Select. Selects how the address is to be used in the address filtering. 00: destination address, 01: source address, 10: reserved, 11: reserved */
        uint32_t Reserved   : 13;
        uint32_t AV         : 1;    /* Address Valid. Determins whether this address is compared against the incomming packet */
    } bits;
    uint64_t val;
} __attribute__((packed));

/* Multicast Table Array */
union MTA {
    uint32_t val[128];
} __attribute__((packed));

/* Interrupt Mask Set/Read register */
union IMS {
    uint32_t val;
} __attribute__((packed));

/* Receive Descriptor */
union RDESC {
    struct {
        uint64_t BufferAddress      : 64;
        uint64_t Length             : 16;
        uint64_t PacketChecksum     : 16;
        uint64_t Status_DD          : 1;    /* Descriptor Done */
        uint64_t Status_EOP         : 1;    /* End Of Packet */
        uint64_t Status_IXSM        : 1;    /* Ignore Checksum Indication */
        uint64_t Status_VP          : 1;    /* Packet is 802.1Q */
        uint64_t Status_RSV         : 1;
        uint64_t Status_TCPCS       : 1;    /* TCP Checksum Caculated On Packet */
        uint64_t Status_IPCS        : 1;    /* IP Checksum Calculated On Packet */
        uint64_t Status_PIF         : 1;    /* Passed In-exact Filter */
        uint64_t Errors             : 8;
        uint64_t Special            : 16;
    } bits;
    uint8_t val[16];
} __attribute__((packed));

/* Receive Descriptor Base Address Low register */
union RDBAL {
    struct {
        uint32_t ZERO   : 4;    /* ignored */
        uint32_t RDBAL  : 28;   /* Receive Descriptor Base Address Low */
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Receive Descriptor Length register */
union RDLEN {
    struct {
        uint32_t ZERO           : 7;    /* ignored */
        uint32_t LEN            : 13;   /* Receive Descriptor length, provides the bytes of receive descriptor */
        uint32_t Reserved       : 12;
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Receive Descriptor Head register */
union RDH {
    struct {
        uint32_t RDH            : 16;   /* Receive Descriptor Head */
        uint32_t Reserved       : 16;
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Receive Descriptor Tail register */
union RDT {
    struct {
        uint32_t RDT            : 16;   /* Receive Descriptor Tail */
        uint32_t Reserved       : 16;
    } bits;
    uint32_t val;
} __attribute__((packed));

/* Receive Control Resgister */
union RCTL {
    struct {
        uint32_t Reserved1      : 1;
        uint32_t EN             : 1;    /* Receiver Enable */
        uint32_t SBP            : 1;    /* Store Bad Packets. 0: do not store, 1: store */
        uint32_t UPE            : 1;    /* Unicast Promiscuous Enabled. 0: disable, 1: enable. When set, passes without filtering out all received unicast packets. Otherwise, accepts or rejects unicast packet based on received packet destination address match with stored address */
        uint32_t MPE            : 1;    /* Multicast Promiscuous Enabled. 0: disable, 1: enable. When set, passes without filtering out all received multicast packets. Otherwise, accepts or rejects packet based on its 4096-bit bector multicast filtering table */
        uint32_t LPE            : 1;    /* Long Packet Reception Enabled. 0: disable, 1: enable. When cleared, discard packet longer than 1522 bytes. when set, discard packet longer than 16384 bytes */
        uint32_t LBM            : 2;    /* Loopback Mode. 00: no loopback, 01: undefined, 10: undefined, 11: PHY or external SerDes loopback, only allowed in full-duplex mode */
        uint32_t RDMTS          : 2;    /* Receive Descriptor Minimal Threshhold Size. 00: Free Buffer threshold is set to 1/2 of RDLEN, 01: 1/4 of RDLEN, 10: 1/8 of RDLEN, 11: Reserved */
        uint32_t Reserved2      : 2;
        uint32_t MO             : 2;    /* Multicast Offset. Determines which bits of incoming multicast address are used in looking up the 4096-bit vector. 00: bits [47:36] iof received destination multicast address, 01: [46:35], 10: [45:34] 11: [43:32] */
        uint32_t Reserved3      : 1;
        uint32_t BAM            : 1;    /* Broadcast Accept Mode. 0: ignore broadcase, 1: accept broadcast packets */
        uint32_t BSIZE          : 2;    /* Receive Buffer Size. when RCTL.BSEX == 0, 00: 2048 bytes, 01: 1024 bytes, 10: 512 bytes, 11: 256 bytes, when RCTL.BSEX == 1, 00: reserved, 01 16384 bytes, 10: 8192 bytes, 11: 4096 bytes */
        uint32_t VFE            : 1;    /* VLAN Filter Enable */
        uint32_t CFIEN          : 1;    /* Canonical Form Indicator Enable. 0: diabled, 1: enabled. */
        uint32_t CFI            : 1;    /* Canonical Form Indicator bit value. If RCTL.CLIEN == 1 && CFI == 1 then 802.1Q packet can be received, otherwise discard */
        uint32_t Reserved4      : 1;
        uint32_t DPF            : 1;    /* Discard Pause Frames. 0: follow filter comparation, 1: discard */
        uint32_t PMCF           : 1;    /* Pass Mac Control Frames. 0: do not pass MAC control frames, 1: Pass any MAC control frame that does not contain the pause opcode of 0x1 */
        uint32_t Reserved5      : 1;
        uint32_t BSEX           : 1;    /* Buffer Size Extension. Used combine with RCTL.BSIZE */
        uint32_t SECRC          : 1;    /* Strip Ethernet CRC from incomming packet. 0: do not strip CRC, 1: strip CRC */
        uint32_t Reserved6      : 5;
    } bits;
    uint32_t val;
} __attribute__((packed));

#define TD_CNT 64
#define TD_RINGBUFFER_SIZE (TD_CNT * sizeof(union TDESC))
#define TD_BUF_SIZE 1518
typedef uint8_t TDESC_BUF[TD_BUF_SIZE];

#define RD_CNT 128
#define RD_RINGBUFFER_SIZE (RD_CNT * sizeof(union RDESC))
#define RD_BUF_SIZE 2048
typedef uint8_t RDESC_BUF[RD_BUF_SIZE];

struct e1000_driver {
    volatile void *mmio;
    /* transmit */
    union TDESC tds[TD_CNT] __attribute__((aligned(16)));
    TDESC_BUF td_bufs[TD_CNT];
    /* receive */
    union RDESC rds[RD_CNT] __attribute__((aligned(16)));
    RDESC_BUF rd_bufs[RD_CNT];
};

struct e1000_driver driver = { 0 };

static void write_reg(uint32_t offset, void *src, size_t src_sz)
{
    memcpy((void *)((uintptr_t)driver.mmio + offset), src, src_sz);
}

static void read_reg(uint32_t offset, void *dst, size_t dst_sz)
{
    memcpy(dst, (void *)((uintptr_t)driver.mmio + offset), dst_sz);
}

static int init_transmit(void)
{
    /* check alignment(128byte) of transmit descriptor ringbuffer size */
    static_assert(TD_RINGBUFFER_SIZE % 128 == 0);
    int ret = 0;
    /* init buffers of transmit descriptors */
    for (size_t i = 0; i < TD_CNT; ++i) {
        driver.tds[i].bits.BufferAddress = PADDR((void *)driver.td_bufs[i]);
        driver.tds[i].bits.Length = sizeof(driver.td_bufs[i]);
        driver.tds[i].bits.CMD_RS = 1;
        driver.tds[i].bits.STA_DD = 1;
    }
    /* set td ringbuffer base address register */
    union TDBAL tdbal = {
        .bits = {
            .ZERO       = 0,
            .TDBAL      = (uintptr_t)PADDR((void *)driver.tds) >> 4,
        }
    };
    write_reg(E1000_TDBAL, &tdbal.val, sizeof(tdbal.val));
    /* set td ringbuffer length register */
    union TDLEN tdlen = {
        .bits = {
            .ZERO       = 0,
            .LEN        = TD_RINGBUFFER_SIZE >> 7,
            .Reserved   = 0,
        }
    };
    write_reg(E1000_TDLEN, &tdlen.val, sizeof(tdlen.val));
    /* set td ringbuffer head and tail register */
    union TDH tdh = {
        .bits = {
            .TDH        = 0,
            .Reserved   = 0,
        }
    };
    union TDT tdt = {
        .bits = {
            .TDT        = 0,
            .Reserved   = 0,
        }
    };
    write_reg(E1000_TDH, &tdh.val, sizeof(tdh.val));
    write_reg(E1000_TDT, &tdt.val, sizeof(tdt.val));
    /* set transmit control register */
    union TCTL tctl = {
        .bits = {
            .Reserved0  = 0,
            .EN         = 1,
            .Reserved1  = 0,
            .PSP        = 1,
            .CT         = 0,        /* full duplex mode */
            .COLD       = 0x40,     /* full duplex mode */
            .SWXOFF     = 0,
            .Reserved2  = 0,
            .RTLC       = 0,
            .Reserved3  = 0,
            .Reserved4  = 0,
        }
    };
    write_reg(E1000_TCTL, &tctl.val, sizeof(tctl.val));
    /* set transmit inter packet gap register */
    union TIPG tipg = {
        .bits = {
            .IPGT       = 10,
            .IPGR1      = 8,
            .IPGR2      = 6,
            .Reserved   = 0,
        }
    };
    write_reg(E1000_TIPG, &tipg.val, sizeof(tipg.val));

end:
    return ret;
}

static int init_receive(void)
{
    static_assert(RD_RINGBUFFER_SIZE % 128 == 0);
    int ret = 0;
    /* init MAC address */
    /*
     * hard code, can be aquired using EEPROM
     * 52:54:00:12:34:56
     */
    union RA ra = {
        .bits = {
            .RA_0       = 0x52,
            .RA_1       = 0x54,
            .RA_2       = 0x00,
            .RA_3       = 0x12,
            .RA_4       = 0x34,
            .RA_5       = 0x56,
            .AS         = 0b00,
            .Reserved   = 0,
            .AV         = 1,
        }
    };
    write_reg(E1000_RA, &ra.val, sizeof(ra.val));
    /* init MTA */
    union MTA mta = { 0 };
    write_reg(E1000_MTA, &mta.val, sizeof(mta.val));
    /* init interrupt mask (all masked for now) */
    union IMS ims = { 0 };
    write_reg(E1000_IMS, &ims.val, sizeof(ims.val));
    /* init buffers of receive descriptors */
    for (size_t i = 0; i < RD_CNT; ++i) {
        driver.rds[i].bits.BufferAddress = PADDR((void *)driver.rd_bufs[i]);
        driver.rds[i].bits.Length = sizeof(driver.rd_bufs[i]);
        driver.rds[i].bits.Status_EOP = 0;
        driver.rds[i].bits.Status_DD = 0;
    }
    /* set rd ringbuffer address */
    union RDBAL rdbal = {
        .bits = {
            .ZERO       = 0,
            .RDBAL      = (uintptr_t)PADDR((void *)driver.rds) >> 4,
        }
    };
    write_reg(E1000_RDBAL, &rdbal.val, sizeof(rdbal.val));
    /* set rd ringbuffer size */
    union RDLEN rdlen = {
        .bits = {
            .ZERO       = 0,
            .LEN        = RD_RINGBUFFER_SIZE >> 7,
            .Reserved   = 0,
        }
    };
    write_reg(E1000_RDLEN, &rdlen.val, sizeof(rdlen.val));
    /* set rd ringbuffer head and tail register */
    union RDH rdh = {
        .bits = {
            .RDH        = 0,
            .Reserved   = 0,
        }
    };
    union RDT rdt = {
        .bits = {
            .RDT        = 1,
            .Reserved   = 0,
        }
    };
    write_reg(E1000_RDH, &rdh.val, sizeof(rdh.val));
    write_reg(E1000_RDT, &rdt.val, sizeof(rdt.val));
    /* set receive control register */
    union RCTL rctl = {
        .bits = {
            .Reserved1  = 0,
            .EN         = 1,
            .SBP        = 0,
            .UPE        = 0,
            .MPE        = 0,
            .LPE        = 0,
            .LBM        = 0,
            .RDMTS      = 0,
            .Reserved2  = 0,
            .MO         = 0,
            .Reserved3  = 0,
            .BAM        = 0,
            .BSIZE      = 0,    /* 2048 byte */
            .VFE        = 0,
            .CFIEN      = 0,
            .CFI        = 0,
            .Reserved4  = 0,
            .DPF        = 0,
            .PMCF       = 0,
            .Reserved5  = 0,
            .BSEX       = 0,
            .SECRC      = 1,    /* strip CRC */
            .Reserved6  = 0,
        }
    };
    write_reg(E1000_RCTL, &rctl.val, sizeof(rctl.val));

end:
    return ret;
}

int pci_e1000_attach(struct pci_func *pf)
{
    int ret = 0;
    pci_func_enable(pf);
    driver.mmio = mmio_map_region(pf->reg_base[0], pf->reg_size[0]);
    if (driver.mmio == NULL) {
        ret = -E_NO_MEM;
        ERR("map register io memory failed\n");
        goto err;
    }
    /* check status */
    assert(*(uint32_t *)((uintptr_t)driver.mmio + E1000_STATUS) == 0x80080783);
    /* init transmit */
    ret = init_transmit();
    if (ret != 0) {
        ERR("init transmit failed\n");
        goto err;
    }
    /* init receive */
    ret = init_receive();
    if (ret != 0) {
        ERR("init receive failed\n");
        goto err;
    }
    goto end;

err:
    panic("attach e1000 failed, %e\n", ret);
end:
    return ret;
}

int e1000_send(void *src, size_t src_sz)
{
    int ret = 0;
    size_t acc = 0;
    union TDT tdt = { 0 };
    while (acc != src_sz) {
        /* get current tail desc */
        read_reg(E1000_TDT, &tdt, sizeof(tdt));
        size_t tail = tdt.bits.TDT;
        union TDESC *tdesc = &driver.tds[tail];
        /* check whether is processing */
        if (tdesc->bits.STA_DD == 0)
            break;
        /* copy data */
        size_t cnt = MIN(src_sz - acc, TD_BUF_SIZE);
        memcpy(driver.td_bufs[tail], (void *)((uintptr_t)src + acc), cnt);
        /* set TDESC */
        tdesc->bits.Length = cnt;
        tdesc->bits.CMD_EOP = 1;
        tdesc->bits.STA_DD = 0;
        /* update tail */
        mb(); /* For ensuring memcpy and update to desc is done when moving ahead tail */
        tdt.bits.TDT = (tail + 1) % TD_CNT;
        write_reg(E1000_TDT, &tdt, sizeof(tdt));
        acc += cnt;
    }
    ret = acc;
    return ret;
}

int e1000_recv(void *dst, size_t dst_sz)
{
    int ret = 0;
    size_t acc = 0;
    union RDT rdt = { 0 };
    while (true) {
        /* read first valid desc */
        read_reg(E1000_RDT, &rdt, sizeof(rdt));
        size_t tail = rdt.bits.RDT;
        size_t idx = tail != 0 ? tail - 1 : RD_CNT - 1;
        union RDESC *rdesc = &driver.rds[idx];
        if (rdesc->bits.Status_DD == 0)
            break;
        rdesc->bits.Status_DD = 0;
        /* copy data */
        size_t cnt = rdesc->bits.Length;
        if (cnt + acc > dst_sz)
            break;
        memcpy((void *)((uintptr_t)dst + acc), driver.rd_bufs[idx], cnt);
        acc += cnt;
        /* update tail */
        mb();
        rdt.bits.RDT = (tail + 1) % RD_CNT;
        write_reg(E1000_RDT, &rdt, sizeof(rdt));
        /* last desc */
        if (rdesc->bits.Status_EOP == 1) {
            rdesc->bits.Status_EOP = 0;
            break;
        }
    }
    ret = acc;
    return ret;
}
