#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
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

#define DEBUGFS_DIR "lab_info"
#define DEBUGFS_VM_FILE "vm"

static struct dentry *debugfs_dir;
static struct dentry *debugfs_vm_file;

// structures

enum request_type {
    VM_AREA, PPP_CHAN
};

struct request {
    enum request_type type;
    int pid;
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

struct ppp_area_struct_info_msg {
    int err;
    struct ppp_struct_info ppp_struct_info;
};


struct request request;
int request_received = 0;

static struct ppp_area_struct_info_msg check_in_net(struct net *net) {
    pr_info("checking net...");
    if (net == NULL) {
        pr_err("network not found\n");
        return (struct ppp_area_struct_info_msg) {.err = -EINVAL};
    }
    struct sock *sock = net->rtnl;
    if (sock && sock->sk_family == PF_PPPOX) {
        struct pppox_sock *pppox_sock = pppox_sk(sock);
        struct ppp_channel ppp = pppox_sock->chan;
        return (struct ppp_area_struct_info_msg) {
                ppp.mtu, ppp.hdrlen, ppp.speed, ppp.latency
        };
    }
    sock = net->diag_nlsk;
    if (sock && sock->sk_family == PF_PPPOX) {
        struct pppox_sock *pppox_sock = pppox_sk(sock);
        struct ppp_channel ppp = pppox_sock->chan;
        return (struct ppp_area_struct_info_msg) {
                ppp.mtu, ppp.hdrlen, ppp.speed, ppp.latency
        };
    }

    sock = net->crypto_nlsk;
    if (sock && sock->sk_family == PF_PPPOX) {
        struct pppox_sock *pppox_sock = pppox_sk(sock);
        struct ppp_channel ppp = pppox_sock->chan;
        return (struct ppp_area_struct_info_msg) {
                ppp.mtu, ppp.hdrlen, ppp.speed, ppp.latency
        };
    }

    sock = net->genl_sock;
    if (sock && sock->sk_family == PF_PPPOX) {
        struct pppox_sock *pppox_sock = pppox_sk(sock);
        struct ppp_channel ppp = pppox_sock->chan;
        return (struct ppp_area_struct_info_msg) {
                ppp.mtu, ppp.hdrlen, ppp.speed, ppp.latency
        };
    }
    return (struct ppp_area_struct_info_msg) {.err = -EINVAL};

}

static struct ppp_area_struct_info_msg get_ppp_area_struct_info_msg(void) {

    struct net *net = get_net_ns_by_pid(request.pid);
    struct ppp_area_struct_info_msg msg = check_in_net(net);
    if(msg.err == 0) {
        return msg;
    }
    for_each_net(net) {
        msg = check_in_net(net);
        if(msg.err == 0) {
            return msg;
        }
    }
    pr_err("wrong family\n");
    return (struct ppp_area_struct_info_msg) {.err = -EINVAL};

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
    pr_info("READING...");
    if (!request_received) {
        return -EINVAL;
    }
    if (count < sizeof(struct request)) {
        return -EPERM;
    }
    if (request.type == VM_AREA) {
        struct vm_area_struct_info_msg vm_area_msg = get_vm_area_struct_info();
        if (vm_area_msg.err != 0) {
            return vm_area_msg.err;
        } else {
            return (ssize_t) copy_to_user(buffer, &vm_area_msg.vm_area_struct_info, sizeof(struct vm_area_struct_info));
        }
    }
    if (request.type == PPP_CHAN) {
        struct ppp_area_struct_info_msg ppp = get_ppp_area_struct_info_msg();
        if(ppp.err != 0) {
            return ppp.err;
        } else {
            return (ssize_t) copy_to_user(buffer, &ppp.ppp_struct_info, sizeof(struct ppp_struct_info));
        }
    }
    return 0;
}

static ssize_t write_to_debugfs(struct file *file, const char __user *buffer, size_t count, loff_t *ppos) {
    pr_info("WRITING...");
    if (count != sizeof(struct request)) {
        return -EINVAL;
    }
    if (copy_from_user(&request, buffer, count)) {
        return -EFAULT;
    }
    request_received = 1;
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
