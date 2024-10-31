#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/kfifo.h>
#include <linux/set_memory.h>
#include <linux/cc_platform.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <uapi/asm/kvm_para.h>
#include <asm/kvm_host.h>

static int vcpu = 0;
module_param(vcpu, int, 0444);
MODULE_PARM_DESC(vcpu, "vcpu to pin to");

struct shared_tsc_data *tscdata;

static void print_data(void)
{
	int i;

	for(i=0; i< TSC_MAX_ENTRIES; i++) {
		printk(KERN_ERR "vmeh [%d].r = %lld .o = %lld guestr = %lld"
				" delta=%lld\n", i, tscdata->vme[i].r,
				tscdata->vme[i].o, 
				tscdata->gr[i],
			tscdata->gr[i] -
			(tscdata->vme[i].r + tscdata->vme[i].o));

		printk(KERN_ERR "vmex [%d].r = %lld .o = %lld guestr = %lld"
				" delta=%lld\n", i, tscdata->vmex[i].r,
				tscdata->vmex[i].o, 
				tscdata->gr[i],
			(tscdata->vme[i].r + tscdata->vme[i].o) - 
			tscdata->gr[i]);

   }

}

static int __init init_mem(void)
{
        struct page *p;
        int r;

        p = alloc_pages(GFP_KERNEL, 0);
        if (!p) {
                printk(KERN_ERR "%s: failed to alloc %d pages", __func__, (1U << 0));
                return -ENOMEM;
        }

	tscdata = page_address(p);

        /*
         * hvclock is shared between the guest and the hypervisor, must
         * be mapped decrypted.
         */
        if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT)) {
                r = set_memory_decrypted((unsigned long) tscdata,
                                         1UL << 0);
                if (r) {
                        __free_pages(p, 0);
                        tscdata = NULL;
                        printk(KERN_ERR "tscdata: set_memory_decrypted() failed. Disabling\n");
                        return -ENOMEM;
                }
        }

        memset(tscdata, 0, PAGE_SIZE << 0);
	return 0;
}

static int tscdata_thread(void *arg)
{
	int i;

	wrmsrl(MSR_KVM_DEBUG_TDXTSC, __pa(tscdata) | 0x1);
	for (i = 0; i < TSC_MAX_ENTRIES; i++) {
		tscdata->gr[tscdata->i] = rdtsc_ordered();
		wrmsrl(MSR_KVM_DEBUG_TDXTSC, __pa(tscdata));
	}

	print_data();

        while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(1000));
		set_current_state(TASK_RUNNING);
        }

	wrmsrl(MSR_KVM_DEBUG_TDXTSC, 0);

        return 0;
}


struct task_struct *t;

static int __init example_init(void)
{
	int r;

	printk(KERN_ERR "running tscdata_thread on vcpu %d\n", vcpu);
	r = init_mem();
	if (r) {
		printk(KERN_ERR "init_mem returns %d\n", r);
		return r;
	}

	t = kthread_run_on_cpu(tscdata_thread, NULL, vcpu, "tscdata_thread");
	if (IS_ERR(t)) {
		printk(KERN_ERR "kthread_create returns %d\n", PTR_ERR_OR_ZERO(t));
		return PTR_ERR_OR_ZERO(t);
	}

	return 0;
}

static void __exit example_exit(void)
{
	kthread_stop(t);
}

module_init(example_init);
module_exit(example_exit);
MODULE_DESCRIPTION("Debug module for TDX TSC offset issue");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcelo Tosatti <mtosatti@redhat.com>");


