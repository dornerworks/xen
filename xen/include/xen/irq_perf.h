/*
 * Copyright (c) 2017 DornerWorks
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __IRQ_PERF_H__
#define __IRQ_PERF_H__

#include <xen/types.h>

#define NUM_IRQ_SAMPLES 500
#define TARGET_CPU 3

struct irq_perf{
	uint64_t start;
	uint64_t end;
};
typedef struct irq_perf irq_perf_t;

#endif
