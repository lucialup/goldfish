#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fdtable.h>  // for files_fdtable()
#include <linux/path.h>  // for struct path
#include <linux/dcache.h>  // for d_path()
#include <linux/uaccess.h>  // for copy_from_user()

#include "hook.h"

DEFINE_PER_CPU(bool, logging_allowed) = true;

#define SYS_OPEN_LOG_BUF_SIZE 4096


// the logging is skipped for the syscalls whose path/filename contains at least one of the predefined strings
// !!! 'socket' is used for interprocess communication
const char* log_skip_strings[] = {"prebuilts", "goldfish", "init", "dev", "proc", "sys", "anon_inode", "socket"};	

bool isLogSkipped(const char* token) {
    int i, strNr;
    strNr = sizeof(log_skip_strings) / sizeof(*log_skip_strings);
    for (i = 0; i < strNr; i++) 
        if (strstr(token, log_skip_strings[i]) != NULL) 
            return true;
    return false;
}

void hook(const char *syscall_name, const char *arg_types, ...) {
    static char prev_buffer[SYS_OPEN_LOG_BUF_SIZE] = {0};
    va_list args;
    char *buffer;
    int buffer_pos = 0;
    int i;
    struct file *file = NULL;
    bool has_filename_arg = strchr(arg_types, 'n') || strchr(arg_types, 'p');
    char real_path[256];
    pid_t pid; 
    int fd; 
    size_t count = 0;

    buffer = kmalloc(SYS_OPEN_LOG_BUF_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate memory for hook logger buffer\n");
        return;
    }
    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, "Syscall: %s", syscall_name);

    va_start(args, arg_types);

    for (i = 0; arg_types[i] != '\0'; i++) {
        switch (arg_types[i]) {
            case 'd':
                {
                    fd = va_arg(args, int);
                    if(fd == 0 || fd == 1)
                        goto cleanup;
                    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", File descriptor: %d", fd);

                    if (!has_filename_arg) {
                        file = fcheck_files(current->files, fd);
                        if (file) {
                            struct path *path = &file->f_path;
                            char *pathname = d_path(path, real_path, 256);

                            if (isLogSkipped(pathname)) {
                                goto cleanup;
                            }
                            else {
                                buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", Path: %s", pathname);
                            }
                        }
                    }
                }
                break;
            case 'n':
                {
                    const char *filename = va_arg(args, const char *);
                    if (isLogSkipped(filename)) {
                        goto cleanup;
                    }
                    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", Filename: %s", filename);
                }
                break;
            case 'p':
                {
                    const char *path = va_arg(args, const char *);
                    if (isLogSkipped(path)) {
                        goto cleanup;
                    }
                    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", Path: %s", path);
                }
                break;
            case 'f':
                {
                    int flags = va_arg(args, int);
                    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", Flags: %d", flags);
                }
                break;
            case 'c':
                {
                    count = va_arg(args, int);
                    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", Count: %zu", count);
                }
                break;
            case 'b':
                {
                    char __user *user_buf = va_arg(args, char __user *);
                    char buf_copy[16];
                    unsigned long copied;

                    size_t to_copy = min(count, sizeof(buf_copy) - 1);

                    copied = copy_from_user(buf_copy, user_buf, to_copy);

                    if (copied == 0) {
                        buf_copy[to_copy] = '\0';
                        buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", Buf: \"%s\"", buf_copy);
                    } else {
                        printk(KERN_ERR "Failed to copy user buffer in hook: %lu bytes not copied\n", copied);
                    }
                }
                break;
            default:
                printk(KERN_ERR "Unknown argument type in hook: %c\n", arg_types[i]);
                break;
        }
    }

    pid = current->pid;
    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", Process ID: %d", pid);

    if (strcmp(buffer, prev_buffer) == 0) {
        goto cleanup;
    }

    strncpy(prev_buffer, buffer, SYS_OPEN_LOG_BUF_SIZE);

    if (this_cpu_read(logging_allowed)) {
	    this_cpu_write(logging_allowed, false);
	    printk(KERN_INFO "%s\n", buffer);
	    this_cpu_write(logging_allowed, true);
    }

cleanup:
    va_end(args);
    kfree(buffer);
}

