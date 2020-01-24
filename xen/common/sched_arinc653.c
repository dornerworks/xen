/******************************************************************************
 * sched_arinc653.c
 *
 * An ARINC653-compatible scheduling algorithm for use in Xen.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2010, DornerWorks, Ltd. <DornerWorks.com>
 */

#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/sched-if.h>
#include <xen/timer.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <xen/list.h>
#include <xen/guest_access.h>
#include <public/sysctl.h>

/**************************************************************************
 * Private Macros                                                         *
 **************************************************************************/

/**
 * Default timeslice for domain 0.
 */
#define DEFAULT_TIMESLICE MILLISECS(10)

/**
 * Retrieve the idle VCPU for a given physical CPU
 */
#define IDLETASK(cpu)  (idle_vcpu[cpu])

/**
 * Return a pointer to the ARINC 653-specific scheduler data information
 * associated with the given PCPU (pc)
 */
#define APCPU(pc)     \
    ((struct arinc653_pcpu *)per_cpu(schedule_data, pc).sched_priv)

/**
 * Return a pointer to the ARINC 653-specific scheduler data information
 * associated with the given VCPU (vc)
 */
#define AVCPU(vc) ((struct arinc653_vcpu *)(vc)->sched_priv)

/**
 * Return a pointer to the ARINC 653-specific scheduler data information
 * associated with the given domain
 */
#define ADOM(_dom)    ((struct arinc653_dom *) (_dom)->sched_priv)

/**
 * Return the global scheduler private data given the scheduler ops pointer
 */
#define SCHED_PRIV(s) ((struct a653sched_priv *)((s)->sched_data))

/**************************************************************************
 * Private Type Definitions                                               *
 **************************************************************************/

/**
 * Domain
 */
struct arinc653_dom
{
    struct domain *dom;                 /* Up-pointer to domain */
    struct list_head sdom_list_elem;    /* On the scheduler private data */
    struct list_head vcpu_list;         /* VCPUs belonging to this domain */
};

/**
 * Virtual CPU
 */
struct arinc653_vcpu
{
    struct vcpu *vc;                    /* Up-pointer to VCPU */
    struct arinc653_dom *sdom;          /* Up-pointer to domain */
    struct list_head vcpu_list_elem;    /* On the domain */
};

/**
 * Virtual CPU minor frame entry for a PCPU
 */
struct vcpu_sched_entry
{
    struct vcpu *vcpu;                  /* VCPU to run */
    s_time_t runtime;                   /* Duration of the frame */
};

/**
 * Physical CPU
 */
struct arinc653_pcpu
{
    unsigned int cpu;                   /* PCPU id */
    struct list_head pcpu_list_elem;    /* PCPU list node */

    /* Schedule of VCPUs to run on this PCPU */
    struct vcpu_sched_entry sched[ARINC653_MAX_DOMAINS_PER_SCHEDULE];

    unsigned int sched_len;             /* Active entries in sched */
    unsigned int sched_index;           /* Current frame */

    s_time_t epoch;                     /* Sync to this point in time */
    s_time_t major_frame;               /* Duration of a major frame */
    s_time_t next_switch_time;          /* When to switch to the next frame */
};

/**
 * Domain minor frame entry for the scheduler
 */
struct dom_sched_entry
{
    xen_domain_handle_t dom_handle;     /* UUID for the domain to run */
    s_time_t runtime;                   /* Duration of the frame */
};

/**
 * Scheduler private data
 */
struct a653sched_priv
{
    spinlock_t lock;                    /* Scheduler lock */

    /* Schedule of doms to run */
    struct dom_sched_entry sched[ARINC653_MAX_DOMAINS_PER_SCHEDULE];

    unsigned int sched_len;             /* Active entries in sched */

    s_time_t epoch;                     /* Sync to this point in time */
    s_time_t major_frame;               /* Duration of a major frame */

    struct list_head pcpu_list;         /* PCPUs belonging to this scheduler */
    struct list_head sdom_list;         /* Doms belonging to this scheduler */
};

/**************************************************************************
 * Helper functions                                                       *
 **************************************************************************/

/**
 * This function compares two domain handles.
 *
 * @param h1        Pointer to handle 1
 * @param h2        Pointer to handle 2
 *
 * @return          <ul>
 *                  <li> <0:  handle 1 is less than handle 2
 *                  <li>  0:  handle 1 is equal to handle 2
 *                  <li> >0:  handle 1 is greater than handle 2
 *                  </ul>
 */
static int dom_handle_cmp(const xen_domain_handle_t h1,
                          const xen_domain_handle_t h2)
{
    return memcmp(h1, h2, sizeof(xen_domain_handle_t));
}

/**
 * This function searches the domain list to find a Domain that matches
 * the domain handle.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param handle    Pointer to handler
 *
 * @return          <ul>
 *                  <li> Pointer to the matching domains scheduler info, if one is found
 *                  <li> NULL otherwise
 *                  </ul>
 */
static struct arinc653_dom *find_sdom(
    const struct scheduler *ops,
    xen_domain_handle_t handle)
{
    struct arinc653_dom *sdom;

    /* loop through the sdom_list looking for the specified domain */
    list_for_each_entry ( sdom, &SCHED_PRIV(ops)->sdom_list, sdom_list_elem )
        if (dom_handle_cmp(sdom->dom->handle, handle) == 0)
            return sdom;

    return NULL;
}

/**
 * This function searches the domain list to find a VCPU that is assigned
 * to the indicated PCPU.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param cpu       ID of the PCPU
 *
 * @return          <ul>
 *                  <li> Pointer to the matching VCPU if one is found
 *                  <li> NULL otherwise
 *                  </ul>
 */
static struct vcpu *find_sdom_vcpu(
    const struct arinc653_dom *sdom, int cpu)
{
    struct arinc653_vcpu *svc;

    /* loop through the vcpu_list looking for the specified domain */
    list_for_each_entry ( svc, &sdom->vcpu_list, vcpu_list_elem )
        if (svc->vc->processor == cpu)
            return svc->vc;

    return NULL;
}

/**
 * This function synchronizes the PCPU major/minor frame to the scheduler epoch.
 *
 * @param spc       Pointer to PCPU structure
 * @param now       The current time
 * @return          <None>
 */
static void sync_pcpu_frame(
    struct arinc653_pcpu *spc,
    s_time_t now)
{
    s_time_t next;
    unsigned int index;

    /* Determine the start of the current major frame */
    next = now - ((now - spc->epoch) % spc->major_frame);

    /* Determine which minor frame should be running */
    for ( index = 0; index < spc->sched_len; index++ )
    {
        next += spc->sched[index].runtime;

        if ( next > now )
            break;
    }

    BUG_ON(index >= spc->sched_len);

    spc->sched_index = index;
    spc->next_switch_time = next;
}

/**
 * This function builds the VCPU run schedule for the specified PCPU.
 *
 * @param spc       Pointer to PCPU structure
 * @param now       The current time
 * @return          <None>
 */
static void update_pcpu_sched(
    const struct scheduler *ops,
    struct arinc653_pcpu *spc,
    s_time_t now)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    struct arinc653_dom *sdom;
    struct vcpu *vcpu;
    unsigned int cpu = spc->cpu;
    unsigned int index;

    for ( index = 0; index < sched_priv->sched_len; index++ )
    {
        vcpu = NULL;

        sdom = find_sdom(ops, sched_priv->sched[index].dom_handle);
        if ( sdom )
        {
            vcpu = find_sdom_vcpu(sdom, cpu);
        }

        if ( vcpu == NULL )
        {
            vcpu = IDLETASK(cpu);
        }

        spc->sched[index].vcpu = vcpu;
        spc->sched[index].runtime = sched_priv->sched[index].runtime;
    }

    spc->sched_len = sched_priv->sched_len;
    spc->epoch = sched_priv->epoch;
    spc->major_frame = sched_priv->major_frame;

    sync_pcpu_frame(spc, now);
}

/**
 * This function is called by the adjust_global scheduler hook to put
 * in place a new ARINC653 schedule.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */
static int
arinc653_sched_set(
    const struct scheduler *ops,
    struct xen_sysctl_arinc653_schedule *schedule)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    struct arinc653_pcpu *spc;
    spinlock_t *lock;
    s_time_t total_runtime = 0;
    s_time_t now;
    unsigned int i;
    unsigned long flags;
    int rc = -EINVAL;

    spin_lock_irqsave(&sched_priv->lock, flags);

    now = NOW();

    /* Check for valid major frame and number of schedule entries. */
    if ( (schedule->major_frame <= 0)
         || (schedule->num_sched_entries < 1)
         || (schedule->num_sched_entries > ARINC653_MAX_DOMAINS_PER_SCHEDULE) )
        goto fail;

    for ( i = 0; i < schedule->num_sched_entries; i++ )
    {
        /* Check for a valid run time. */
        if ( schedule->sched_entries[i].runtime <= 0 )
            goto fail;

        /* Add this entry's run time to total run time. */
        total_runtime += schedule->sched_entries[i].runtime;
    }

    /*
     * Error if the major frame is not large enough to run all entries as
     * indicated by comparing the total run time to the major frame length.
     */
    if ( total_runtime > schedule->major_frame )
        goto fail;

    /* Copy the new schedule into place. */
    sched_priv->sched_len = schedule->num_sched_entries;
    sched_priv->major_frame = schedule->major_frame;
    for ( i = 0; i < schedule->num_sched_entries; i++ )
    {
        memcpy(sched_priv->sched[i].dom_handle,
               schedule->sched_entries[i].dom_handle,
               sizeof(sched_priv->sched[i].dom_handle));
        sched_priv->sched[i].runtime =
            schedule->sched_entries[i].runtime;
    }

    /*
     * The newly-installed schedule takes effect immediately. We do not even
     * wait for the current major frame to expire.
     *
     * Signal a new major frame to begin. The next major frame is set up by
     * the do_schedule callback function when it is next invoked.
     */
    sched_priv->epoch = now;
    list_for_each_entry ( spc, &sched_priv->pcpu_list, pcpu_list_elem )
    {
        lock = pcpu_schedule_lock(spc->cpu);
        update_pcpu_sched(ops, spc, now);
        pcpu_schedule_unlock(lock, spc->cpu);
    }

    rc = 0;

 fail:
    spin_unlock_irqrestore(&sched_priv->lock, flags);

    /* TODO: Trigger scheduler */

    return rc;
}

/**
 * This function is called by the adjust_global scheduler hook to read the
 * current ARINC 653 schedule
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */
static int
arinc653_sched_get(
    const struct scheduler *ops,
    struct xen_sysctl_arinc653_schedule *schedule)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    unsigned int i;
    unsigned long flags;

    spin_lock_irqsave(&sched_priv->lock, flags);

    schedule->num_sched_entries = sched_priv->sched_len;
    schedule->major_frame = sched_priv->major_frame;
    for ( i = 0; i < sched_priv->sched_len; i++ )
    {
        memcpy(schedule->sched_entries[i].dom_handle,
               sched_priv->sched[i].dom_handle,
               sizeof(sched_priv->sched[i].dom_handle));
        schedule->sched_entries[i].vcpu_id = 0;
        schedule->sched_entries[i].runtime = sched_priv->sched[i].runtime;
    }

    spin_unlock_irqrestore(&sched_priv->lock, flags);

    return 0;
}

/**************************************************************************
 * Scheduler callback functions                                           *
 **************************************************************************/

/**
 * This function performs initialization for an instance of the scheduler.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          <ul>
 *                  <li> 0 = success
 *                  <li> !0 = error
 *                  </ul>
 */
static int
a653sched_init(struct scheduler *ops)
{
    struct a653sched_priv *sched_priv;

    sched_priv = xzalloc(struct a653sched_priv);
    if ( sched_priv == NULL )
        return -ENOMEM;

    spin_lock_init(&sched_priv->lock);
    INIT_LIST_HEAD(&sched_priv->pcpu_list);
    INIT_LIST_HEAD(&sched_priv->sdom_list);

    sched_priv->epoch = NOW();

    /* Initialize the schedule to run dom0 if present, otherwise idle vcpu */
    sched_priv->sched_len = 1;
    sched_priv->sched[0].dom_handle[0] = '\0';
    sched_priv->sched[0].runtime = DEFAULT_TIMESLICE;
    sched_priv->major_frame = DEFAULT_TIMESLICE;

    ops->sched_data = sched_priv;

    return 0;
}

/**
 * This function performs deinitialization for an instance of the scheduler
 *
 * @param ops       Pointer to this instance of the scheduler structure
 */
static void
a653sched_deinit(struct scheduler *ops)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);

    BUG_ON( !list_empty(&sched_priv->pcpu_list) );
    BUG_ON( !list_empty(&sched_priv->sdom_list) );

    ops->sched_data = NULL;

    xfree(sched_priv);
}

/**
 * This function allocates ARINC653 domain-specific data
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param dom       Pointer to the domain structure
 *
 * @return          Pointer to the allocated data
 */
static void *
a653sched_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    struct arinc653_dom *sdom;
    unsigned long flags;

    sdom = xzalloc(struct arinc653_dom);
    if ( sdom == NULL )
        return ERR_PTR(-ENOMEM);

    INIT_LIST_HEAD(&sdom->sdom_list_elem);
    INIT_LIST_HEAD(&sdom->vcpu_list);
    sdom->dom = dom;

    spin_lock_irqsave(&sched_priv->lock, flags);
    list_add(&sdom->sdom_list_elem, &sched_priv->sdom_list);
    spin_unlock_irqrestore(&sched_priv->lock, flags);

    return sdom;
}

/**
 * This function frees ARINC653 domain-specific data
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param data      Pointer to the domain specific data
 *
 */
static void
a653sched_free_domdata(const struct scheduler *ops, void *data)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    struct arinc653_dom *sdom = data;
    unsigned long flags;

    BUG_ON( !list_empty(&sdom->vcpu_list) );

    spin_lock_irqsave(&sched_priv->lock, flags);
    list_del(&sdom->sdom_list_elem);
    spin_unlock_irqrestore(&sched_priv->lock, flags);

    xfree(data);
}

/**
 * This function allocates ARINC653 PCPU-specific data
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param cpu       CPU Index of the PCPU data
 *
 * @return          Pointer to the allocated data
 *
 */
static void *
a653sched_alloc_pdata(const struct scheduler *ops, int cpu)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    struct arinc653_pcpu *spc;
    unsigned long flags;

    /* Allocate per-PCPU info */
    spc = xzalloc(struct arinc653_pcpu);
    if ( spc == NULL )
        return ERR_PTR(-ENOMEM);

    INIT_LIST_HEAD(&spc->pcpu_list_elem);
    spc->cpu = cpu;

    spin_lock_irqsave(&sched_priv->lock, flags);
    list_add(&spc->pcpu_list_elem, &sched_priv->pcpu_list);
    update_pcpu_sched(ops, spc, NOW());
    spin_unlock_irqrestore(&sched_priv->lock, flags);

    return spc;
}

/**
 * This function frees ARINC653 PCPU-specific data
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param cpu       CPU Index of the PCPU data
 *
 */
static void
a653sched_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    struct arinc653_pcpu *spc = pcpu;
    unsigned long flags;

    spin_lock_irqsave(&sched_priv->lock, flags);
    list_del(&spc->pcpu_list_elem);
    spin_unlock_irqrestore(&sched_priv->lock, flags);

    xfree(spc);
}

/**
 * This function allocates scheduler-specific data for a VCPU
 *
 * @param ops       Pointer to this instance of the scheduler structure
 *
 * @return          Pointer to the allocated data
 */
static void *
a653sched_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct arinc653_vcpu *svc;

    /*
     * Allocate memory for the ARINC 653-specific scheduler data information
     * associated with the given VCPU (vc).
     */
    svc = xmalloc(struct arinc653_vcpu);
    if ( svc == NULL )
        return NULL;

    INIT_LIST_HEAD(&svc->vcpu_list_elem);
    svc->sdom = dd;
    svc->vc = vc;

    return svc;
}

static void
a653sched_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    struct arinc653_vcpu *svc = AVCPU(vc);
    struct arinc653_dom *sdom = svc->sdom;
    struct arinc653_pcpu *spc;
    spinlock_t *lock;
    s_time_t now;
    unsigned long flags;

    spin_lock_irqsave(&sched_priv->lock, flags);

    now = NOW();

    list_add(&svc->vcpu_list_elem, &sdom->vcpu_list);

    list_for_each_entry ( spc, &sched_priv->pcpu_list, pcpu_list_elem )
    {
        lock = pcpu_schedule_lock(spc->cpu);
        update_pcpu_sched(ops, spc, now);
        pcpu_schedule_unlock(lock, spc->cpu);
    }

    spin_unlock_irqrestore(&sched_priv->lock, flags);
}

/**
 * This function frees scheduler-specific VCPU data
 *
 * @param ops       Pointer to this instance of the scheduler structure
 */
static void
a653sched_free_vdata(const struct scheduler *ops, void *priv)
{
    struct arinc653_vcpu *svc = priv;

    xfree(svc);
}

static void
a653sched_vcpu_remove(const struct scheduler *ops, struct vcpu *vc)
{
    struct a653sched_priv *sched_priv = SCHED_PRIV(ops);
    struct arinc653_vcpu *svc = AVCPU(vc);
    struct arinc653_pcpu *spc;
    spinlock_t *lock;
    s_time_t now;
    unsigned long flags;

    spin_lock_irqsave(&sched_priv->lock, flags);

    now = NOW();

    list_del(&svc->vcpu_list_elem);

    list_for_each_entry ( spc, &sched_priv->pcpu_list, pcpu_list_elem )
    {
        lock = pcpu_schedule_lock(spc->cpu);
        update_pcpu_sched(ops, spc, now);
        pcpu_schedule_unlock(lock, spc->cpu);
    }

    spin_unlock_irqrestore(&sched_priv->lock, flags);
}

/**
 * Xen scheduler callback function to sleep a VCPU
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param vc        Pointer to the VCPU structure for the current domain
 */
static void
a653sched_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
    unsigned int cpu = vc->processor;

    BUG_ON( is_idle_vcpu(vc) );

    /*
     * If the VCPU being put to sleep is the same one that is currently
     * running, raise a softirq to invoke the scheduler to switch domains.
     */
    if ( curr_on_cpu(cpu) == vc )
        cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
}

/**
 * Xen scheduler callback function to wake up a VCPU
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param vc        Pointer to the VCPU structure for the current domain
 */
static void
a653sched_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    BUG_ON( is_idle_vcpu(vc) );

    cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
}

/**
 * Xen scheduler callback function to select a VCPU to run.
 * This is the main scheduler routine.
 *
 * The scheduler has already locked the PCPU, so no need to grab any locks.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param now       Current time
 *
 * @return          Address of the VCPU structure scheduled to be run next
 *                  Amount of time to execute the returned VCPU
 *                  Flag for whether the VCPU was migrated
 */
static struct task_slice
a653sched_do_schedule(
    const struct scheduler *ops,
    s_time_t now,
    bool_t tasklet_work_scheduled)
{
    const unsigned int cpu = smp_processor_id();
    struct arinc653_pcpu *spc = APCPU(cpu);
    struct vcpu * new_task;
    struct task_slice ret;

    /* Advance to the next frame if the current one has expired */
    if ( spc->next_switch_time <= now )
    {
        spc->sched_index++;
        if ( spc->sched_index >= spc->sched_len )
            spc->sched_index = 0;

        spc->next_switch_time += spc->sched[spc->sched_index].runtime;
    }

    /* Frames were somehow missed - resynchronize to epoch */
    if ( unlikely(spc->next_switch_time <= now) )
        sync_pcpu_frame(spc, now);

    new_task = spc->sched[spc->sched_index].vcpu;

    BUG_ON(new_task == NULL);

    /* Check if the new task is runnable */
    if ( !vcpu_runnable(new_task) )
        new_task = IDLETASK(cpu);

    /* Tasklet work (which runs in idle VCPU context) overrides all else */
    if ( tasklet_work_scheduled )
        new_task = IDLETASK(cpu);

    ret.time = spc->next_switch_time - now;
    ret.task = new_task;
    ret.migrated = 0;

    BUG_ON(ret.time <= 0);

    return ret;
}

/**
 * Xen scheduler callback function to select a CPU for the VCPU to run on
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param v         Pointer to the VCPU structure for the current domain
 *
 * @return          Number of selected physical CPU
 */
static int
a653sched_pick_cpu(const struct scheduler *ops, struct vcpu *vc)
{
    cpumask_t *online;
    unsigned int cpu;

    /* 
     * If present, prefer vc's current processor, else
     * just find the first valid vcpu .
     */
    online = cpupool_domain_cpumask(vc->domain);

    cpu = cpumask_first(online);

    if ( cpumask_test_cpu(vc->processor, online)
         || (cpu >= nr_cpu_ids) )
        cpu = vc->processor;

    /* TODO: handle over-provisioning */

    return cpu;
}

/**
 * Xen scheduler callback to change the scheduler of a cpu
 *
 * @param new_ops   Pointer to this instance of the scheduler structure
 * @param cpu       The cpu that is changing scheduler
 * @param pdata     scheduler specific PCPU data
 * @param vdata     scheduler specific VCPU data of the idle vcpu
 */
static void
a653_switch_sched(struct scheduler *new_ops, unsigned int cpu,
                  void *pdata, void *vdata)
{
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);
    struct arinc653_vcpu *svc = vdata;

    ASSERT(pdata && svc && is_idle_vcpu(svc->vc));

    idle_vcpu[cpu]->sched_priv = vdata;

    per_cpu(scheduler, cpu) = new_ops;
    per_cpu(schedule_data, cpu).sched_priv = pdata;

    /*
     * (Re?)route the lock to its default location. We actually do not use
     * it, but if we leave it pointing to where it does now (i.e., the
     * runqueue lock for this PCPU in the default scheduler), we'd be
     * causing unnecessary contention on that lock (in cases where it is
     * shared among multiple PCPUs, like in Credit2 and RTDS).
     */
    sd->schedule_lock = &sd->_lock;
}

/**
 * Xen scheduler callback function to perform a global (not domain-specific)
 * adjustment. It is used by the ARINC 653 scheduler to put in place a new
 * ARINC 653 schedule or to retrieve the schedule currently in place.
 *
 * @param ops       Pointer to this instance of the scheduler structure
 * @param sc        Pointer to the scheduler operation specified by Domain 0
 */
static int
a653sched_adjust_global(const struct scheduler *ops,
                        struct xen_sysctl_scheduler_op *sc)
{
    struct xen_sysctl_arinc653_schedule local_sched;
    int rc = -EINVAL;

    switch ( sc->cmd )
    {
    case XEN_SYSCTL_SCHEDOP_putinfo:
        if ( copy_from_guest(&local_sched, sc->u.sched_arinc653.schedule, 1) )
        {
            rc = -EFAULT;
            break;
        }

        rc = arinc653_sched_set(ops, &local_sched);
        break;
    case XEN_SYSCTL_SCHEDOP_getinfo:
        memset(&local_sched, -1, sizeof(local_sched));
        rc = arinc653_sched_get(ops, &local_sched);
        if ( rc )
            break;

        if ( copy_to_guest(sc->u.sched_arinc653.schedule, &local_sched, 1) )
            rc = -EFAULT;
        break;
    }

    return rc;
}

/**
 * This structure defines our scheduler for Xen.
 * The entries tell Xen where to find our scheduler-specific
 * callback functions.
 * The symbol must be visible to the rest of Xen at link time.
 */
static const struct scheduler sched_arinc653_def = {
    .name           = "ARINC 653 Scheduler",
    .opt_name       = "arinc653",
    .sched_id       = XEN_SCHEDULER_ARINC653,
    .sched_data     = NULL,

    .init           = a653sched_init,
    .deinit         = a653sched_deinit,

    .alloc_domdata  = a653sched_alloc_domdata,
    .free_domdata   = a653sched_free_domdata,

    .alloc_pdata    = a653sched_alloc_pdata,
    .free_pdata     = a653sched_free_pdata,

    .alloc_vdata    = a653sched_alloc_vdata,
    .insert_vcpu    = a653sched_vcpu_insert,
    .free_vdata     = a653sched_free_vdata,
    .remove_vcpu    = a653sched_vcpu_remove,

    .sleep          = a653sched_vcpu_sleep,
    .wake           = a653sched_vcpu_wake,
    .yield          = NULL,
    .context_saved  = NULL,

    .do_schedule    = a653sched_do_schedule,

    .pick_cpu       = a653sched_pick_cpu,

    .switch_sched   = a653_switch_sched,

    .adjust         = NULL,
    .adjust_global  = a653sched_adjust_global,

    .dump_settings  = NULL,
    .dump_cpu_state = NULL,

    .tick_suspend   = NULL,
    .tick_resume    = NULL,
};

REGISTER_SCHEDULER(sched_arinc653_def);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
