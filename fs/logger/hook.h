#ifndef HOOK_H
#define HOOK_H

#include <linux/mutex.h>
#include <linux/percpu.h>

DECLARE_PER_CPU(bool, logging_allowed);

void hook(const char *syscall_name, const char *arg_types, ...);

#endif // HOOK_H

