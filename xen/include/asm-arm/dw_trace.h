#ifndef __DW_TRACE_H__
#define __DW_TRACE_H__

#define DW_TRACE
/* #undef DW_TRACE */

#ifdef DW_TRACE

extern uint64_t xen_done_t;
extern uint64_t xen_cstart_t;

void dw_print_boot_time(void);

#endif
#endif /* __DW_TRACE_H__ */