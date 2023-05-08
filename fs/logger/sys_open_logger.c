// draft - to be used to synch the print of the logs in a file
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/mutex.h>

#define SYS_OPEN_LOG_PROC_FILE "sys_open_log"
#define SYS_OPEN_LOG_BUF_SIZE 4096

char *sys_open_log_buf;
size_t sys_open_log_buf_size;
DEFINE_MUTEX(sys_open_log_mutex);

static int sys_open_log_proc_show(struct seq_file *m, void *v) {
    seq_printf(m, "%s", sys_open_log_buf);
    return 0;
}

static int sys_open_log_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, sys_open_log_proc_show, NULL);
}

static const struct file_operations sys_open_log_proc_fops = {
    .owner = THIS_MODULE,
    .open = sys_open_log_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static int __init sys_open_log_init(void) {
    sys_open_log_buf = kzalloc(SYS_OPEN_LOG_BUF_SIZE, GFP_KERNEL);
    if (!sys_open_log_buf)
        return -ENOMEM;

    sys_open_log_buf_size = 0;

    proc_create(SYS_OPEN_LOG_PROC_FILE, 0, NULL, &sys_open_log_proc_fops);

    return 0;
}

static void __exit sys_open_log_exit(void) {
    remove_proc_entry(SYS_OPEN_LOG_PROC_FILE, NULL);
    kfree(sys_open_log_buf);
}

module_init(sys_open_log_init);
module_exit(sys_open_log_exit);
