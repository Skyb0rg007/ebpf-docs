---
title: "KFunc 'bpf_path_d_path'"
description: "This page documents the 'bpf_path_d_path' eBPF kfunc, including its definition, usage, program types that can use it, and examples."
---
# KFunc `bpf_path_d_path`

<!-- [FEATURE_TAG](bpf_path_d_path) -->
[:octicons-tag-24: v6.12](https://github.com/torvalds/linux/commit/d08e2045ebf0f5f2a97ad22cc7dae398b35354ba)
<!-- [/FEATURE_TAG] -->

This function resolve the path name for the supplied path.

## Definition

Resolve the path name for the supplied `path` and store it in `buf`. This BPF kfunc is the safer variant of the legacy [`bpf_d_path`](../helper-function/bpf_d_path.md) helper and should be used in place of [`bpf_d_path`](../helper-function/bpf_d_path.md) whenever possible. It enforces `KF_TRUSTED_ARGS` semantics, meaning that the supplied `path` must itself hold a valid reference, or else the BPF program will be outright rejected by the BPF verifier.

**Parameters**

`path`: path to resolve the pathname for

`buf`: buffer to return the resolved path name in

`buf__sz`: length of the supplied buffer

**Returns**

A positive integer corresponding to the length of the resolved path name in `buf`, including the `NULL` termination character. On error, a negative integer is returned.


**Signature**

<!-- [KFUNC_DEF] -->
`#!c int bpf_path_d_path(const struct path *path, char *buf, size_t buf__sz)`
<!-- [/KFUNC_DEF] -->

## Usage

`bpf_path_d_path` resolves kernel `struct path` (dentry+ mount) into a full pathname. It's most commonly paired with `bpf_get_task_exe_file()` or `bpf_get_file_xattr()` style kfuncs: those return a struct file *, and `bpf_path_d_path` is then called on `&file->f_path` to get the actual path string.

### Program types

The following program types can make use of this kfunc:

<!-- [KFUNC_PROG_REF] -->
- [`BPF_PROG_TYPE_LSM`](../program-type/BPF_PROG_TYPE_LSM.md)
- [`BPF_PROG_TYPE_PERF_EVENT`](../program-type/BPF_PROG_TYPE_PERF_EVENT.md) [:octicons-tag-24: v6.12](https://github.com/torvalds/linux/commit/bc638d8cb5be813d4eeb9f63cce52caaa18f3960) - 
- [`BPF_PROG_TYPE_STRUCT_OPS`](../program-type/BPF_PROG_TYPE_STRUCT_OPS.md) [:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/7bddf0e9f1081935d11d01d9344dbe7c3fda07f6) - 
- [`BPF_PROG_TYPE_TRACEPOINT`](../program-type/BPF_PROG_TYPE_TRACEPOINT.md) [:octicons-tag-24: v6.12](https://github.com/torvalds/linux/commit/bc638d8cb5be813d4eeb9f63cce52caaa18f3960) - 
- [`BPF_PROG_TYPE_TRACING`](../program-type/BPF_PROG_TYPE_TRACING.md)
<!-- [/KFUNC_PROG_REF] -->

### Example


```c 
SEC("lsm/task_kill")
int BPF_PROG(log_kill_target, struct task_struct *p,
             struct kernel_siginfo *info, int sig,
             const struct cred *cred)
{
	struct file *exe_file;
	char path_buf[128];
	int ret;

	exe_file = bpf_get_task_exe_file(p);
	if (!exe_file)
		return 0;

	ret = bpf_path_d_path(&exe_file->f_path, path_buf,
			      sizeof(path_buf));
	if (ret > 0)
		bpf_printk("kill target exe: %s\n", path_buf);

	bpf_put_file(exe_file);
	return 0;
}
```
