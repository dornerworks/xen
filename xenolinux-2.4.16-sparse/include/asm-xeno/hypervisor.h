/******************************************************************************
 * hypervisor.h
 * 
 * Linux-specific hypervisor handling.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__

#include <asm/hypervisor-ifs/hypervisor-if.h>
#include <asm/ptrace.h>

/* arch/xeno/kernel/setup.c */
union start_info_union
{
    start_info_t start_info;
    char padding[512];
};
extern union start_info_union start_info_union;
#define start_info (start_info_union.start_info)

/* arch/xeno/kernel/hypervisor.c */
void do_hypervisor_callback(struct pt_regs *regs);


/* arch/xeno/mm/hypervisor.c */
/*
 * NB. ptr values should be fake-physical. 'vals' should be already
 * fully adjusted (ie. for start_info.phys_base).
 */

extern unsigned int pt_update_queue_idx;

void queue_l1_entry_update(unsigned long ptr, unsigned long val);
void queue_l2_entry_update(unsigned long ptr, unsigned long val);
void queue_pt_switch(unsigned long ptr);
void queue_tlb_flush(void);
void queue_invlpg(unsigned long ptr);
void queue_pgd_pin(unsigned long ptr);
void queue_pgd_unpin(unsigned long ptr);
void queue_pte_pin(unsigned long ptr);
void queue_pte_unpin(unsigned long ptr);

#define PT_UPDATE_DEBUG 0

#if PT_UPDATE_DEBUG > 0
typedef struct {
    unsigned long ptr, val, pteval;
    void *ptep;
    int line; char *file;
} page_update_debug_t;
extern page_update_debug_t update_debug_queue[];
#define queue_l1_entry_update(_p,_v) ({                           \
 update_debug_queue[pt_update_queue_idx].ptr  = (_p);             \
 update_debug_queue[pt_update_queue_idx].val  = (_v);             \
 update_debug_queue[pt_update_queue_idx].line = __LINE__;         \
 update_debug_queue[pt_update_queue_idx].file = __FILE__;         \
 queue_l1_entry_update((_p),(_v));                                \
})
#define queue_l2_entry_update(_p,_v) ({                           \
 update_debug_queue[pt_update_queue_idx].ptr  = (_p);             \
 update_debug_queue[pt_update_queue_idx].val  = (_v);             \
 update_debug_queue[pt_update_queue_idx].line = __LINE__;         \
 update_debug_queue[pt_update_queue_idx].file = __FILE__;         \
 queue_l2_entry_update((_p),(_v));                                \
})
#endif

#if PT_UPDATE_DEBUG > 1
#undef queue_l1_entry_update
#undef queue_l2_entry_update
#define queue_l1_entry_update(_p,_v) ({                           \
 update_debug_queue[pt_update_queue_idx].ptr  = (_p);             \
 update_debug_queue[pt_update_queue_idx].val  = (_v);             \
 update_debug_queue[pt_update_queue_idx].line = __LINE__;         \
 update_debug_queue[pt_update_queue_idx].file = __FILE__;         \
 printk("L1 %s %d: %08lx (%08lx -> %08lx)\n", __FILE__, __LINE__, \
        (_p)+start_info.phys_base, *(unsigned long *)__va(_p),    \
        (unsigned long)(_v));                                     \
 queue_l1_entry_update((_p),(_v));                                \
})
#define queue_l2_entry_update(_p,_v) ({                           \
 update_debug_queue[pt_update_queue_idx].ptr  = (_p);             \
 update_debug_queue[pt_update_queue_idx].val  = (_v);             \
 update_debug_queue[pt_update_queue_idx].line = __LINE__;         \
 update_debug_queue[pt_update_queue_idx].file = __FILE__;         \
 printk("L2 %s %d: %08lx (%08lx -> %08lx)\n", __FILE__, __LINE__, \
        (_p)+start_info.phys_base, *(unsigned long *)__va(_p),    \
        (unsigned long)(_v));                                     \
 queue_l2_entry_update((_p),(_v));                                \
})
#define queue_pt_switch(_p) ({                                    \
 printk("PTSWITCH %s %d: %08lx\n", __FILE__, __LINE__, (_p));     \
 queue_pt_switch(_p);                                             \
})   
#define queue_tlb_flush() ({                                      \
 printk("TLB FLUSH %s %d\n", __FILE__, __LINE__);                 \
 queue_tlb_flush();                                               \
})   
#define queue_invlpg(_p) ({                                       \
 printk("INVLPG %s %d: %08lx\n", __FILE__, __LINE__, (_p));       \
 queue_invlpg(_p);                                                \
})   
#define queue_pgd_pin(_p) ({                                      \
 printk("PGD PIN %s %d: %08lx\n", __FILE__, __LINE__, (_p));      \
 queue_pgd_pin(_p);                                               \
})   
#define queue_pgd_unpin(_p) ({                                    \
 printk("PGD UNPIN %s %d: %08lx\n", __FILE__, __LINE__, (_p));    \
 queue_pgd_unpin(_p);                                             \
})   
#define queue_pte_pin(_p) ({                                      \
 printk("PTE PIN %s %d: %08lx\n", __FILE__, __LINE__, (_p));      \
 queue_pte_pin(_p);                                               \
})   
#define queue_pte_unpin(_p) ({                                    \
 printk("PTE UNPIN %s %d: %08lx\n", __FILE__, __LINE__, (_p));    \
 queue_pte_unpin(_p);                                             \
})   
#endif

void _flush_page_update_queue(void);
static inline int flush_page_update_queue(void)
{
    unsigned int idx = pt_update_queue_idx;
    if ( idx != 0 ) _flush_page_update_queue();
    return idx;
}
#define XENO_flush_page_update_queue() (_flush_page_update_queue())


/*
 * Assembler stubs for hyper-calls.
 */

static inline int HYPERVISOR_set_trap_table(trap_info_t *table)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_trap_table),
        "b" (table) );

    return ret;
}


static inline int HYPERVISOR_pt_update(page_update_request_t *req, int count)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_pt_update), 
        "b" (req), "c" (count) );

    return ret;
}


static inline int HYPERVISOR_console_write(const char *str, int count)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_console_write), 
        "b" (str), "c" (count) );


    return ret;
}

static inline int HYPERVISOR_set_guest_stack(
    unsigned long ss, unsigned long esp)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_guest_stack),
        "b" (ss), "c" (esp) );

    return ret;
}

static inline int HYPERVISOR_net_update(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_net_update) );

    return ret;
}

static inline int HYPERVISOR_fpu_taskswitch(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_fpu_taskswitch) );

    return ret;
}

static inline int HYPERVISOR_yield(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_yield) );

    return ret;
}

static inline int HYPERVISOR_exit(void)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_exit) );

    return ret;
}

static inline int HYPERVISOR_dom0_op(void *dom0_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_dom0_op),
        "b" (dom0_op) : "memory" );

    return ret;
}

static inline int HYPERVISOR_network_op(void *network_op)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_network_op),
        "b" (network_op) );

    return ret;
}

static inline int HYPERVISOR_set_debugreg(int reg, unsigned long value)
{
    int ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_set_debugreg),
        "b" (reg), "c" (value) );

    return ret;
}

static inline unsigned long HYPERVISOR_get_debugreg(int reg)
{
    unsigned long ret;
    __asm__ __volatile__ (
        TRAP_INSTR
        : "=a" (ret) : "0" (__HYPERVISOR_get_debugreg),
        "b" (reg) );

    return ret;
}

#endif /* __HYPERVISOR_H__ */
