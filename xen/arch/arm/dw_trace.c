/*
 * xen/arch/arm/dw_trace.c
 *
 * Boot time instrumentation used by Dornerworks for platform
 * characterization.
 */

#include <xen/lib.h>
#include <asm/dw_trace.h>
#include <xen/time.h>

#ifdef DW_TRACE

void dw_print_boot_time(void)
{

    printk("--- Xen Boot Time Output ---\n");
    printk("Xen C Env Enter Time: xen_cstart_t = %lu ticks\n" , xen_cstart_t);
    printk("Xen C Env Enter Time: xen_cstart_t = %ld ns\n" , ticks_to_ns(xen_cstart_t));

    printk("Xen Pre-Init Time: boot_count = %lu ticks\n" , boot_count);
    printk("Xen Pre-Init Time: boot_count = %ld ns\n" , ticks_to_ns(boot_count));

    printk("Xen Boot End Time: xen_done_t = %lu ticks\n" , xen_done_t+boot_count);
    printk("Xen Boot End Time: xen_done_t = %ld ns\n" , ticks_to_ns(xen_done_t+boot_count));
    
    return;
}
#endif