#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/slab.h>

asmlinkage long my_do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode) {
    // Add a printk message
    printk(KERN_INFO "Lici Entering my_do_sys_open\n");

    // Call the original do_sys_open
    long ret = do_sys_open(dfd, filename, flags, mode);

    if (ret >= 0) {
        // Get the current task's file descriptor table
        struct files_struct *files = current->files;
        struct file *file = fcheck_files(files, ret);

        if (file) {
            char *buf = kmalloc(PATH_MAX, GFP_KERNEL);
            if (buf) {
                // Get the file path and output the tracing
                if (dentry_path_raw(file->f_path.dentry, buf, PATH_MAX) != NULL) {
                    printk(KERN_INFO "Open Lici: %s\n", buf);
                }
                kfree(buf);
            }
        }
    }

    return ret;
}

