#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define DEBUGFS_VM_PATH "/sys/kernel/debug/lab_info/vm"

//PPP_CHANNEL -> ipw_network  static struct asyncppp *ap_get(struct tty_struct *tty)
// task->signal-> tty

//file -> sock_from_file -> sock->
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


int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s 1 <pid> <index> OR 2 <pid>\n", argv[0]);
        return 1;
    }
    int type = atoi(argv[1]);
    struct request req;
    int fd = open(DEBUGFS_VM_PATH, O_RDWR);
    if (fd == -1) {
        perror("Error opening debugfs file");
        return 1;
    }

    if(type == 1) {
        if(argc != 4) {
            return 1;
        }
        int pid = atoi(argv[2]);
        int index = atoi(argv[3]);
        req = (struct request) {
                VM_AREA, pid, index
        };
        ssize_t err = write(fd, &req, sizeof(struct request));
        if (err < 0) {
            fprintf(stderr, "Error while writing to file");
            close(fd);
            return 1;
        }
        struct vm_area_struct_info info;
        ssize_t bytesRead = read(fd, &info, sizeof(struct vm_area_struct_info));
        if (bytesRead == 0) {
            printf("Got info!\n");
            printf("data of vm area are:");
            printf("vm_start: %lu\n vm_end: %lu\n vm_flags: %lu\n vm_pgoff: %lu\n",
                   info.vm_start, info.vm_end, info.vm_flags, info.vm_pgoff);
        } else {
            perror("Error reading from debugfs file");
            close(fd);
            return 1;
        }
    }
    if(type == 2) {
        int pid = atoi(argv[2]);
        req = (struct request) {
                PPP_CHAN, pid
        };
        ssize_t err = write(fd, &req, sizeof(struct request));
        if (err < 0) {
            fprintf(stderr, "Error while writing to file");
            return 1;
        }
        struct ppp_struct_info info;
        ssize_t bytesRead = read(fd, &info, sizeof(struct ppp_struct_info));
        if (bytesRead == 0) {
            printf("Got info!\n");
            printf("data of ppp channel are:");
            printf("latency: %d\n speed: %d\n hdrlen: %d\n mtu: %d\n",
                   info.latency, info.speed, info.hdrlen, info.mtu);
        } else {
            perror("Error reading from debugfs file");
            close(fd);
            return 1;
        }


    }
    close(fd);

    return 0;
}
