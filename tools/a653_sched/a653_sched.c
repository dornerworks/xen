/******************************************************************************
 * a653_sched.c
 *
 * ARLX (ARINC653 Realtime Linux/Xen) Scheduling Command
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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <xenctrl.h>

#ifndef MILLISECS_TO_NANOSECS
#define MILLISECS_TO_NANOSECS(ms) ((ms)*1000000ll)
#endif

#ifndef DOM1_NAME
#define DOM1_NAME "dom1"
#endif

static struct xen_sysctl_arinc653_schedule sched;

static void usage(char *pname, int rc)
{
    printf("Usage: %s <domname:runtime> ...\n\n", pname);
    printf("\tAll times are in milliseconds\n");
    printf("\tMajor Frame is the sum of all runtimes\n");
    printf("Options:\n");
    printf("\t--help|-h\t\tdisplay this usage information\n");
    printf("\t--pool|-p\t\tpool id\n");
    exit(rc);
}

int arinc653_schedule_set(uint32_t cpupool_id,
                          void *as)
{
    int rc = 0;
    xc_interface *xci = xc_interface_open(NULL, NULL, 0);

    if (xci == NULL)
    {
        fprintf(stderr, "Could not open xenctrl interface!\n");
        return -1;
    }
    
    rc = xc_sched_arinc653_schedule_set(xci, 
                                        cpupool_id,
                                        (struct xen_sysctl_arinc653_schedule *)as);
    if (xc_interface_close(xci))
    {
        fprintf(stderr, "xc_interface_close() returned nonzero!\n");
    }

    return rc;
}

int main(int argc, char *argv[])
{
    int opt, longindex;
    static const struct option longopts[] = {
        {"help",        no_argument,        NULL, 'h'},
        {"pool",        required_argument,  NULL, 'p'},
        {NULL,          0,                  NULL,   0}
    };

    int i;
    int j;
    char *arg_str;
    char *last_str;
    int64_t maj_time = 0;

    uint32_t pool = 0;
    
    while ((opt = getopt_long(argc, argv, "hp:", longopts, &longindex)) != -1)
    {
        switch (opt)
        {
            case 'h':
                usage(argv[0], 0);
                break;
            case 'p':
                if (NULL == optarg)
                {
                    usage(argv[0], 0);
                }

		pool = atoi(optarg);
		if (pool < 0)
		{
                    usage(argv[0], 0);
		}
		break;
            default:
                usage(argv[0], 2);
                break;
        }
    }

    if ((optind >= argc) || (argc < 2))
    {
        usage(argv[0], 2);
    }
    else if ((argc - 1) >= ARINC653_MAX_DOMAINS_PER_SCHEDULE)
    {
      printf("Only %d domains are supported.  Given %d.\n", 
             ARINC653_MAX_DOMAINS_PER_SCHEDULE,
             (argc - 1));

      usage(argv[0], 2);
    }

    for (i = optind, j = 0; (i < argc); ++i, ++j)
    {
        last_str = argv[i];
        arg_str = strchr(last_str, ':');

        if (arg_str != NULL)
        {
            *arg_str = '\0';

            /* set partition name */
            strncpy((char *)sched.sched_entries[j].dom_handle,
                    last_str,
                    sizeof(sched.sched_entries[j].dom_handle));

            sched.sched_entries[j].vcpu_id = 0;
        }
        else
        {
            printf("Invalid argument (%s).\n", argv[i]);
            usage(argv[0], 2);
        }

        ++arg_str;
        sched.sched_entries[j].runtime = MILLISECS_TO_NANOSECS(atoi(arg_str));

        if (sched.sched_entries[j].runtime <= 0)
        {
            printf("Invalid run time (%llu).\n", (long long unsigned int) sched.sched_entries[j].runtime);
            usage(argv[0], 2);
        }

        maj_time += sched.sched_entries[j].runtime;
    }

    sched.major_frame = maj_time;
    sched.num_sched_entries = j;

    if (arinc653_schedule_set(pool, (void*)&sched) < 0)
    {
        printf("operation failed\n");
        return 1;
    }
    else
    {
        printf("operation succeeded\n");
        return 0;
    }
      
}
