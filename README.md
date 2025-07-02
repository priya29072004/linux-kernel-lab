# linux-kernel-lab

## Browsing and searching the kernel source code

## Kernel version
uname -r
6.8.0-generic
##Located Kernel Source Code
ls /usr/src

#command used to explore the fork()

grep -rnw . -e 'fork'

## output

/* Sucks! We need to fork list. :-( */
./samples/bpf/tracex6_user.c:83: pid[i] = fork();
./samples/bpf/trace_event_user.c:337: pid = fork();
./samples/bpf/map_perf_test_user.c:354: pid[i] = fork();
./samples/bpf/test_lru_dist.c:243: pid[i] = fork();
./samples/bpf/test_overhead_user.c:114: pid[i] = fork();
./samples/seccomp/user-trap.c:211: worker = fork();
./samples/seccomp/user-trap.c:213: perror("fork");
./samples/seccomp/user-trap.c:282: tracer = fork();
./samples/seccomp/user-trap.c:284: perror("fork");
./security/selinux/include/classmap.h:54: { "fork", "transition", "sigchld", "sigkill",
./init/Kconfig:1086: cgroup. Any attempt to fork more processes than is allowed in the
./init/Kconfig:1095: since the PIDs limit only affects a process's ability to fork, not to

#command used to explore the task_struct()

grep -rnw include/ -e 'task_struct'

## output

include/trace/events/sched.h:610: TP_PROTO(struct task_struct *src_tsk, int src_cpu,
include/trace/events/sched.h:611: struct task_struct *dst_tsk, int dst_cpu),
include/trace/events/sched.h:650: TP_PROTO(struct task_struct *src_tsk, int src_cpu,
include/trace/events/sched.h:651: struct task_struct *dst_tsk, int dst_cpu),
include/trace/events/sched.h:658: TP_PROTO(struct task_struct *src_tsk, int src_cpu,
include/trace/events/sched.h:659: struct task_struct *dst_tsk, int dst_cpu),
include/trace/events/sched.h:788: TP_PROTO(struct task_struct *p, int dst_cpu, unsigned long energy,
include/trace/events/oom.h:12: TP_PROTO(struct task_struct *task),
include/trace/events/signal.h:40: * @task: pointer to struct task_struct
include/trace/events/signal.h:52: TP_PROTO(int sig, struct kernel_siginfo *info, struct task_struct *task,
include/trace/events/osnoise.h:11: TP_PROTO(struct task_struct *t, u64 start, u64 duration),
include/trace/events/rseq.h:13: TP_PROTO(struct task_struct *t),
include/trace/events/task.h:11: TP_PROTO(struct task_struct *task, unsigned long clone_flags),
include/trace/events/task.h:36: TP_PROTO(struct task_struct *task, const char *comm),
include/trace/events/cgroup.h:123: struct task_struct *task, bool threadgroup),
include/trace/events/cgroup.h:153: struct task_struct *task, bool threadgroup),
include/trace/events/cgroup.h:161: struct task_struct *task, bool threadgroup),
include/trace/syscall.h:38:static inline void syscall_tracepoint_update(struct task_struct *p)
include/trace/syscall.h:46:static inline void syscall_tracepoint_update(struct task_struct *p)
include/misc/cxl.h:116: struct task_struct *task);
include/misc/cxllib.h:95: * task: task_struct for the context of the translation
include/misc/cxllib.h:109:int cxllib_get_PE_attributes(struct task_struct *task,

##command used to explore the task_struct()

grep -rnw . -e 'kmalloc'

#output

/security/integrity/platform_certs/load_uefi.c:82: db = kmalloc(lsize, GFP_KERNEL);
./security/integrity/platform_certs/load_powerpc.c:25: * - a pointer to a kmalloc'd buffer containing the cert list on success
./security/integrity/platform_certs/load_powerpc.c:41: db = kmalloc(*size, GFP_KERNEL);
./security/safesetid/securityfs.c:121: nrule = kmalloc(sizeof(struct setid_rule), GFP_KERNEL);
./security/safesetid/securityfs.c:146: pol = kmalloc(sizeof(struct setid_ruleset), GFP_KERNEL);
./security/safesetid/securityfs.c:175: rule = kmalloc(sizeof(struct setid_rule), GFP_KERNEL);
./security/yama/yama_lsm.c:94: info = kmalloc(sizeof(*info), GFP_ATOMIC);
./security/yama/yama_lsm.c:147: added = kmalloc(sizeof(*added), GFP_KERNEL);
./security/tomoyo/realpath.c:251: buf = kmalloc(buf_len, GFP_NOFS);
./security/tomoyo/audit.c:147: * This function uses kmalloc(), so caller must kfree() if this function
./security/tomoyo/audit.c:156: char *buffer = kmalloc(tomoyo_buffer_len, GFP_NOFS);
./security/tomoyo/common.c:2023: buffer = kmalloc(len, GFP_NOFS);
./init/initramfs.c:99: q = kmalloc(sizeof(struct hash), GFP_KERNEL);
./init/initramfs.c:149: de = kmalloc(sizeof(struct dir_entry) + nlen, GFP_KERNEL);
./init/initramfs.c:505: header_buf = kmalloc(110, GFP_KERNEL);
./init/initramfs.c:506: symlink_buf = kmalloc(PATH_MAX + N_ALIGN(PATH_MAX) + 1, GFP_KERNEL);
./init/initramfs.c:507: name_buf = kmalloc(N_ALIGN(PATH_MAX), GFP_KERNEL);
./init/do_mounts_rd.c:72: buf = kmalloc(size, GFP_KERNEL);
./init/do_mounts_rd.c:241: buf = kmalloc(BLOCK_SIZE, GFP_KERNEL);


