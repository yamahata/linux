/*  common code for MTRR (Memory Type Range Register) and
    PAT(Page Attribute Table)

    Copyright (C) 1997-2000  Richard Gooch
    Copyright (c) 2002	     Patrick Mochel

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public
    License along with this library; if not, write to the Free
    Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    Richard Gooch may be reached by email at  rgooch@atnf.csiro.au
    The postal address is:
      Richard Gooch, c/o ATNF, P. O. Box 76, Epping, N.S.W., 2121, Australia.

    Source: "Pentium Pro Family Developer's Manual, Volume 3:
    Operating System Writer's Guide" (Intel document number 242692),
    section 11.11.7

    This was cleaned and made readable by Patrick Mochel <mochel@osdl.org>
    on 6-7 March 2002.
    Source: Intel Architecture Software Developers Manual, Volume 3:
    System Programming Guide; Section 9.11. (1997 edition - PPro).

    This file was split from mtrr.c and generic.c for MTRR and PAT.
*/

#define DEBUG

#include <linux/stop_machine.h>

#include <asm/mtrr.h>
#include <asm/msr.h>
#include <asm/pat.h>

#include "mtrr.h"

static bool mtrr_pat_aps_delayed_init;

struct set_mtrr_data {
	unsigned long	smp_base;
	unsigned long	smp_size;
	unsigned int	smp_reg;
	mtrr_type	smp_type;
};

/**
 * mtrr_pat_rendezvous_handler - Work done in the synchronization handler. Executed
 * by all the CPUs.
 * @info: pointer to mtrr configuration data
 *
 * Returns nothing.
 */
static int mtrr_pat_rendezvous_handler(void *info)
{
	struct set_mtrr_data *data = info;

	/*
	 * We use this same function to initialize the mtrrs during boot,
	 * resume, runtime cpu online and on an explicit request to set a
	 * specific MTRR.
	 *
	 * During boot or suspend, the state of the boot cpu's mtrrs has been
	 * saved, and we want to replicate that across all the cpus that come
	 * online (either at the end of boot or resume or during a runtime cpu
	 * online). If we're doing that, @reg is set to something special and on
	 * all the cpu's we do mtrr_if->set_all() (On the logical cpu that
	 * started the boot/resume sequence, this might be a duplicate
	 * set_all()).
	 */
	if (data->smp_reg != ~0U) {
		mtrr_if->set(data->smp_reg, data->smp_base,
			     data->smp_size, data->smp_type);
	} else if (mtrr_pat_aps_delayed_init || !cpu_online(smp_processor_id())) {
		mtrr_if->set_all();
	}
	return 0;
}

/**
 * set_mtrr_pat - update mtrrs on all processors
 * @reg:	mtrr in question
 * @base:	mtrr base
 * @size:	mtrr size
 * @type:	mtrr type
 *
 * This is kinda tricky, but fortunately, Intel spelled it out for us cleanly:
 *
 * 1. Queue work to do the following on all processors:
 * 2. Disable Interrupts
 * 3. Wait for all procs to do so
 * 4. Enter no-fill cache mode
 * 5. Flush caches
 * 6. Clear PGE bit
 * 7. Flush all TLBs
 * 8. Disable all range registers
 * 9. Update the MTRRs
 * 10. Enable all range registers
 * 11. Flush all TLBs and caches again
 * 12. Enter normal cache mode and reenable caching
 * 13. Set PGE
 * 14. Wait for buddies to catch up
 * 15. Enable interrupts.
 *
 * What does that mean for us? Well, stop_machine() will ensure that
 * the rendezvous handler is started on each CPU. And in lockstep they
 * do the state transition of disabling interrupts, updating MTRR's
 * (the CPU vendors may each do it differently, so we call mtrr_if->set()
 * callback and let them take care of it.) and enabling interrupts.
 *
 * Note that the mechanism is the same for UP systems, too; all the SMP stuff
 * becomes nops.
 */
void
set_mtrr_pat(unsigned int reg, unsigned long base, unsigned long size, mtrr_type type)
{
	struct set_mtrr_data data = { .smp_reg = reg,
				      .smp_base = base,
				      .smp_size = size,
				      .smp_type = type
				    };

	stop_machine(mtrr_pat_rendezvous_handler, &data, cpu_online_mask);
}

void set_mtrr_pat_cpuslocked(unsigned int reg, unsigned long base,
                             unsigned long size, mtrr_type type)
{
	struct set_mtrr_data data = { .smp_reg = reg,
				      .smp_base = base,
				      .smp_size = size,
				      .smp_type = type
				    };

	stop_machine_cpuslocked(mtrr_pat_rendezvous_handler, &data, cpu_online_mask);
}

static void set_mtrr_pat_from_inactive_cpu(unsigned int reg, unsigned long base,
                                           unsigned long size, mtrr_type type)
{
	struct set_mtrr_data data = { .smp_reg = reg,
				      .smp_base = base,
				      .smp_size = size,
				      .smp_type = type
				    };

	stop_machine_from_inactive_cpu(mtrr_pat_rendezvous_handler, &data,
				       cpu_callout_mask);
}

void mtrr_pat_ap_init(void)
{
	if (!mtrr_enabled())
		return;

	if (!use_intel() || mtrr_pat_aps_delayed_init)
		return;

	rcu_cpu_starting(smp_processor_id());

	/*
	 * Ideally we should hold mtrr_mutex here to avoid mtrr entries
	 * changed, but this routine will be called in cpu boot time,
	 * holding the lock breaks it.
	 *
	 * This routine is called in two cases:
	 *
	 *   1. very earily time of software resume, when there absolutely
	 *      isn't mtrr entry changes;
	 *
	 *   2. cpu hotadd time. We let mtrr_add/del_page hold cpuhotplug
	 *      lock to prevent mtrr entry changes
	 */
	set_mtrr_pat_from_inactive_cpu(~0U, 0, 0, 0);
}

void set_mtrr_pat_aps_delayed_init(void)
{
	if (!mtrr_enabled())
		return;
	if (!use_intel())
		return;

	mtrr_pat_aps_delayed_init = true;
}

/*
 * Delayed MTRR initialization for all AP's
 */
void mtrr_pat_aps_init(void)
{
	if (!use_intel() || !mtrr_enabled())
		return;

	/*
	 * Check if someone has requested the delay of AP MTRR initialization,
	 * by doing set_mtrr_pat_aps_delayed_init(), prior to this point. If not,
	 * then we are done.
	 */
	if (!mtrr_pat_aps_delayed_init)
		return;

	set_mtrr_pat(~0U, 0, 0, 0);
	mtrr_pat_aps_delayed_init = false;
}

void mtrr_pat_bp_restore(void)
{
	if (!use_intel() || !mtrr_enabled())
		return;

	mtrr_if->set_all();
}
