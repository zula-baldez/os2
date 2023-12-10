#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/ppp_channel.h>
#include <linux/tty.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/if_pppox.h>
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/ppp-ioctl.h>
#include <linux/ppp_channel.h>
#include <linux/ppp-comp.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/fs.h>

#define DEBUGFS_DIR "lab_info"
#define DEBUGFS_VM_FILE "vm"

struct ppp_file {
    enum {
        INTERFACE = 1, CHANNEL
    } kind;
    struct sk_buff_head xq;        /* pppd transmit queue */
    struct sk_buff_head rq;        /* receive queue for pppd */
    wait_queue_head_t rwait;    /* for poll on reading /dev/ppp */
    refcount_t refcnt;        /* # refs (incl /dev/ppp attached) */
    int hdrlen;        /* space to leave for headers */
    int index;        /* interface unit / channel number */
    int dead;        /* unit/channel has been shut down */
};


struct ppp_link_stats {
    u64 rx_packets;
    u64 tx_packets;
    u64 rx_bytes;
    u64 tx_bytes;
};


struct ppp {
    struct ppp_file file;        /* stuff for read/write/poll 0 */
    struct file *owner;        /* file that owns this unit 48 */
    struct list_head channels;    /* list of attached channels 4c */
    int n_channels;    /* how many channels are attached 54 */
    spinlock_t rlock;        /* lock for receive side 58 */
    spinlock_t wlock;        /* lock for transmit side 5c */
    int __percpu *xmit_recursion; /* xmit recursion detect */
    int mru;        /* max receive unit 60 */
    unsigned int flags;        /* control bits 64 */
    unsigned int xstate;        /* transmit state bits 68 */
    unsigned int rstate;        /* receive state bits 6c */
    int debug;        /* debug flags 70 */
    struct slcompress *vj;        /* state for VJ header compression */
    enum NPmode npmode[6];    /* what to do with each net proto 78 */
    struct sk_buff *xmit_pending;    /* a packet ready to go out 88 */
    struct compressor *xcomp;    /* transmit packet compressor 8c */
    void *xc_state;    /* its internal state 90 */
    struct compressor *rcomp;    /* receive decompressor 94 */
    void *rc_state;    /* its internal state 98 */
    unsigned long last_xmit;    /* jiffies when last pkt sent 9c */
    unsigned long last_recv;    /* jiffies when last pkt rcvd a0 */
    struct net_device *dev;        /* network interface device a4 */
    int closing;    /* is device closing down? a8 */
#ifdef CONFIG_PPP_MULTILINK
    int nxchan;        /* next channel to send something on */
    u32 nxseq;        /* next sequence number to send */
    int mrru;        /* MP: max reconst. receive unit */
    u32 nextseq;    /* MP: seq no of next packet */
    u32 minseq;        /* MP: min of most recent seqnos */
    struct sk_buff_head mrq;    /* MP: receive reconstruction queue */
#endif /* CONFIG_PPP_MULTILINK */
#ifdef CONFIG_PPP_FILTER
    struct bpf_prog *pass_filter;    /* filter for packets to pass */
    struct bpf_prog *active_filter; /* filter for pkts to reset idle */
#endif /* CONFIG_PPP_FILTER */
    struct net *ppp_net;    /* the net we belong to */
    struct ppp_link_stats stats64;    /* 64 bit network stats */
};

struct channel {
    struct ppp_file file;        /* stuff for read/write/poll */
    struct list_head list;        /* link in all/new_channels list */
    struct ppp_channel *chan;    /* public channel data structure */
    struct rw_semaphore chan_sem;    /* protects `chan' during chan ioctl */
    spinlock_t downl;        /* protects `chan', file.xq dequeue */
    struct ppp *ppp;        /* ppp unit we're connected to */
    struct net *chan_net;    /* the net channel belongs to */
    netns_tracker ns_tracker;
    struct list_head clist;        /* link in list of channels per unit */
    rwlock_t upl;        /* protects `ppp' and 'bridge' */
    struct channel __rcu *bridge;    /* "bridged" ppp channel */
#ifdef CONFIG_PPP_MULTILINK
    u8 avail;        /* flag used in multilink stuff */
    u8 had_frag;    /* >= 1 fragments have been sent */
    u32 lastseq;    /* MP: last sequence # received */
    int speed;        /* speed of the corresponding ppp channel*/
#endif /* CONFIG_PPP_MULTILINK */
};


static struct dentry *debugfs_dir;
static struct dentry *debugfs_vm_file;

static DEFINE_MUTEX(lock);

enum request_type {
    VM_AREA, PPP_CHAN
};

struct request {
    enum request_type type;
    union {
        int pid;
        int interface_num;
    };
    int index;
};

struct vm_area_struct_info {
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
    unsigned long vm_pgoff;
};

struct vm_area_struct_info_msg {
    int err;
    struct vm_area_struct_info vm_area_struct_info;
};

struct ppp_struct_info {
    int mtu;        /* max transmit packet size */
    int hdrlen;        /* amount of headroom channel needs */
    int speed;        /* transfer rate (bytes/second) */
    int latency;    /* overhead time in milliseconds */
};

struct ppp_chan_struct_info_msg {
    int err;
    struct ppp_struct_info ppp_struct_info;
};


struct request request;
int request_received = 0;


struct ppp_chan_struct_info_msg access_ppp_channel(struct net_device *dev) {
    struct ppp *ppp = netdev_priv(dev);
    if (ppp) {
        if (ppp->n_channels < 1) {
            pr_err(KERN_INFO "no channels in ppp\n");
            return (struct ppp_chan_struct_info_msg) {.err = -EINVAL};
        }
        struct channel *chan = (struct channel *) list_first_entry(&ppp->channels, struct channel, clist);
        return (struct ppp_chan_struct_info_msg) {
                0, chan->chan->mtu, chan->chan->hdrlen, chan->chan->speed, chan->chan->latency
        };
    } else {
        pr_err(KERN_INFO "PPP channel not found\n");
        return (struct ppp_chan_struct_info_msg) {.err = -EINVAL};
    }
}


static struct ppp_chan_struct_info_msg get_ppp_chan_struct_info_msg(void) {
    struct net_device *dev = NULL;
    char interface_name[100] = "ppp";
    sprintf(interface_name+3, "%d", request.interface_num);
    pr_err("Got interface %s\n", interface_name);
    dev = dev_get_by_name(&init_net, interface_name);
    if (dev) {
        return access_ppp_channel(dev);
    } else {
        pr_err("Failed to find network device %s\n", interface_name);
        return (struct ppp_chan_struct_info_msg) {.err = -EINVAL};
    }
}

static struct vm_area_struct_info_msg get_vm_area_struct_info(void) {
    struct task_struct *task;
    struct mm_struct *mm;
    task = pid_task(find_vpid(request.pid), PIDTYPE_PID);
    pr_info("Current process ID (PID): %d\n", request.pid);
    pr_info("Current vm index: %d\n", request.index);
    if (!task) {
        pr_err("Process not found\n");
        return (struct vm_area_struct_info_msg) {.err = -EINVAL};
    }
    mm = get_task_mm(task);
    if (!mm) {
        pr_err("Process has no mm_struct\n");
        return (struct vm_area_struct_info_msg) {.err = -EINVAL};
    }
    long bot = 0;
    long max = 0xFFFFFFFFFFFFFFF;
    struct vm_area_struct *vm_area_struct = mt_find(&mm->mm_mt, &bot, max);
    pr_info("%lu", vm_area_struct->vm_start);
    request.index -= 1;
    while (vm_area_struct != NULL && request.index > 0) {
        vm_area_struct = mt_find_after(&mm->mm_mt, &bot, max);
        request.index--;
    }
    if (vm_area_struct == NULL) {
        pr_err("index is beyond max index value\n");
        return (struct vm_area_struct_info_msg) {.err = -EINVAL};
    }
    return (struct vm_area_struct_info_msg) {
            .err = 0,
            .vm_area_struct_info = {
                    vm_area_struct->vm_start,
                    vm_area_struct->vm_end,
                    vm_area_struct->vm_flags,
                    vm_area_struct->vm_pgoff
            }
    };
}

static ssize_t read_from_debugfs(struct file *file, char __user *buffer, size_t count, loff_t *ppos) {
    mutex_lock(&lock);
    pr_info("READING...");
    if (!request_received) {
        mutex_unlock(&lock);
        return -EINVAL;
    }
    if (count < sizeof(struct request)) {
        mutex_unlock(&lock);
        return -EPERM;
    }
    if (request.type == VM_AREA) {
        struct vm_area_struct_info_msg vm_area_msg = get_vm_area_struct_info();
        ssize_t ans;
        if (vm_area_msg.err != 0) {
            ans = vm_area_msg.err;
        } else {
            ans = (ssize_t) copy_to_user(buffer, &vm_area_msg.vm_area_struct_info, sizeof(struct vm_area_struct_info));
        }
        mutex_unlock(&lock);
        return ans;
    }
    if (request.type == PPP_CHAN) {
        struct ppp_chan_struct_info_msg ppp = get_ppp_chan_struct_info_msg();
        ssize_t ans;
        if (ppp.err != 0) {
            ans = ppp.err;
        } else {
            ans = (ssize_t) copy_to_user(buffer, &ppp.ppp_struct_info, sizeof(struct ppp_struct_info));
        }
        mutex_unlock(&lock);
        return ans;
    }
    mutex_unlock(&lock);
    return 0;
}

static ssize_t write_to_debugfs(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    mutex_lock(&lock);
    pr_info("WRITING...");
    if (count != sizeof(struct request)) {
        mutex_unlock(&lock);
        return -EINVAL;
    }

    if (copy_from_user(&request, buffer, count)) {
        mutex_unlock(&lock);
        return -EFAULT;
    }
    request_received = 1;
    mutex_unlock(&lock);
    return count;
}

static const struct file_operations my_fops = {
        .read = read_from_debugfs,
        .write = write_to_debugfs,
};

static int __init vm_info_init(void) {
    debugfs_dir = debugfs_create_dir(DEBUGFS_DIR, NULL);
    if (!debugfs_dir) {
        pr_err("Failed to create debugfs directory\n");
        return -ENOMEM;
    }

    debugfs_vm_file = debugfs_create_file(DEBUGFS_VM_FILE, 0777, debugfs_dir, NULL, &my_fops);

    if (!debugfs_vm_file) {
        pr_err("Failed to create debugfs file\n");
        debugfs_remove(debugfs_dir);
        return -ENOMEM;
    }

    pr_info("my_vm_info loaded\n");
    return 0;
}

static void __exit vm_info_exit(void) {
    debugfs_remove_recursive(debugfs_dir);
    pr_info("my_vm_info unloaded\n");
}

module_init(vm_info_init);
module_exit(vm_info_exit);

MODULE_LICENSE("GPL");

MODULE_AUTHOR("Egor");

MODULE_DESCRIPTION("VM Area Information Module");
