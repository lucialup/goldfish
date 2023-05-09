#include <linux/slab.h>
#include <linux/string.h>

#include "hook.h"

DEFINE_PER_CPU(bool, logging_allowed) = true;

#define SYS_OPEN_LOG_BUF_SIZE 4096


// the logging is skipped for the syscalls whose path/filename contains at least one of the predefined strings
const char* log_skip_strings[] = {"/proc/net/", "/system/", "prebuilts", "sys", "dev", "kmsg", "goldfish"};	

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

    buffer = kmalloc(SYS_OPEN_LOG_BUF_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate memory for hook logger buffer\n");
        return;
    }

    va_start(args, arg_types);

    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, "Syscall: %s", syscall_name);

    for (i = 0; arg_types[i] != '\0'; i++) {
        switch (arg_types[i]) {
            case 'd':
                {
                    int fd = va_arg(args, int);
                    buffer_pos += snprintf(buffer + buffer_pos, SYS_OPEN_LOG_BUF_SIZE - buffer_pos, ", File descriptor: %d", fd);
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
            
            default:
                printk(KERN_ERR "Unknown argument type in hook: %c\n", arg_types[i]);
                break;
        }
    }

    if (strcmp(buffer, prev_buffer) == 0) {
        goto cleanup;
    }

    strncpy(prev_buffer, buffer, SYS_OPEN_LOG_BUF_SIZE);

    if(strstr(buffer, "openat") != NULL)
        printk(KERN_INFO "%s\n", buffer);
    else {
        if (this_cpu_read(logging_allowed)) {
		    this_cpu_write(logging_allowed, false);
		    printk(KERN_INFO "%s\n", buffer);
		    this_cpu_write(logging_allowed, true);
	    }
    }

cleanup:
    va_end(args);
    kfree(buffer);
}

