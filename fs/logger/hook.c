#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fdtable.h>  // for files_fdtable()
#include <linux/path.h>  // for struct path
#include <linux/dcache.h>  // for d_path()
#include <linux/uaccess.h>  // for copy_from_user()
#include <linux/timer.h>
#include <linux/percpu.h>
#include <linux/mutex.h>

#include "hook.h"

#define LOG_BUF_SIZE 4096
#define NUM_LOG_BUFFERS 2048
#define LOG_FLUSH_INTERVAL_MS 500


static DEFINE_MUTEX(buf_init_lock);
static bool initialized_buffers = false;

struct log_buffer {
    char buffers[NUM_LOG_BUFFERS][LOG_BUF_SIZE];
    int index;
    struct timer_list flush_timer;
    struct mutex buffer_lock;
};

DEFINE_PER_CPU(bool, logging_allowed) = true;
DEFINE_PER_CPU(struct log_buffer, log_buffers);
DEFINE_PER_CPU(struct timer_list, log_flush_timer);

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

void log_flush_callback(unsigned long data) {
    int cpu = (int)data;
    struct log_buffer *log_buf = per_cpu_ptr(&log_buffers, cpu);
    int i;

    if (this_cpu_read(logging_allowed)) {
        this_cpu_write(logging_allowed, false);
        for (i = 0; i < log_buf->index; i++) {
            printk(KERN_INFO "%s\n", log_buf->buffers[i]);
        }
        this_cpu_write(logging_allowed, true);
    }

    log_buf->index = 0;
    mod_timer(&log_buf->flush_timer, jiffies + msecs_to_jiffies(LOG_FLUSH_INTERVAL_MS));
}

void setup_log_buffers(void) {
    int cpu;
    for_each_possible_cpu(cpu) {
        struct log_buffer *log_buf = per_cpu_ptr(&log_buffers, cpu);
        log_buf->index = 0;
        setup_timer(&log_buf->flush_timer, log_flush_callback, cpu);
        mod_timer(&log_buf->flush_timer, jiffies + msecs_to_jiffies(LOG_FLUSH_INTERVAL_MS));
        mutex_init(&log_buf->buffer_lock);
    }
}


void hook(const char *syscall_name, const char *arg_types, ...) {
    static char prev_buffer[LOG_BUF_SIZE] = {0};
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
    int cpu;

    get_cpu();
    cpu = smp_processor_id();
    struct log_buffer *log_buf = per_cpu_ptr(&log_buffers, cpu);

    if (!initialized_buffers) {
        mutex_lock(&buf_init_lock);
        if (!initialized_buffers) {
            setup_log_buffers();
            initialized_buffers = true;
        }
        mutex_unlock(&buf_init_lock);
    }

    buffer = kmalloc(LOG_BUF_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate memory for hook logger buffer\n");
        goto cleanup;
    }
    buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, "Syscall: %s", syscall_name);

    va_start(args, arg_types);

    for (i = 0; arg_types[i] != '\0'; i++) {
        switch (arg_types[i]) {
            case 'd':
                {
                    fd = va_arg(args, int);
                    if(fd == 0 || fd == 1)
                        goto cleanup;
                    buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, ", File descriptor: %d", fd);

                    if (!has_filename_arg) {
                        file = fcheck_files(current->files, fd);
                        if (file) {
                            struct path *path = &file->f_path;
                            char *pathname = d_path(path, real_path, 256);

                            if (isLogSkipped(pathname)) {
                                goto cleanup;
                            }
                            else {
                                buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, ", Path: %s", pathname);
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
                    buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, ", Filename: %s", filename);
                }
                break;
            case 'p':
                {
                    const char *path = va_arg(args, const char *);
                    if (isLogSkipped(path)) {
                        goto cleanup;
                    }
                    buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, ", Path: %s", path);
                }
                break;
            case 'f':
                {
                    int flags = va_arg(args, int);
                    buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, ", Flags: %d", flags);
                }
                break;
            case 'c':
                {
                    count = va_arg(args, int);
                    buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, ", Count: %zu", count);
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
                        buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, ", Buf: \"%s\"", buf_copy);
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
    buffer_pos += snprintf(buffer + buffer_pos, LOG_BUF_SIZE - buffer_pos, ", Process ID: %d", pid);

    if (strcmp(buffer, prev_buffer) == 0) {
        goto cleanup;
    }

    strncpy(prev_buffer, buffer, LOG_BUF_SIZE);

    mutex_lock(&log_buf->buffer_lock);
    if (log_buf->index < NUM_LOG_BUFFERS) {
        strncpy(log_buf->buffers[log_buf->index], buffer, LOG_BUF_SIZE);
        log_buf->index++;
    } else {
        printk(KERN_ERR "Log buffer for CPU %d full, skipping log message", cpu);
    }
    mutex_unlock(&log_buf->buffer_lock);

cleanup:
    va_end(args);
    kfree(buffer);
    put_cpu();
}