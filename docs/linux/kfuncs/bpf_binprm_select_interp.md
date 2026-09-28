---
title: "KFunc 'bpf_binprm_select_interp'"
description: "This page documents the 'bpf_binprm_select_interp' eBPF kfunc, including its definition, usage, program types that can use it, and examples."
---
# KFunc `bpf_binprm_select_interp`

<!-- [FEATURE_TAG](bpf_binprm_select_interp) -->
[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/6ec7c96bee30a7d9f3982951aa19f712feb14f6a)
<!-- [/FEATURE_TAG] -->

Select, by name, one of the interpreters that the binfmt_misc entry bound at registration time.

## Definition

Select the interpreter bound under `name` to the binfmt_misc entry that matched the binary. An entry binds its interpreters before it is enabled, with one `+<name> <path>` write per interpreter to the entry file. Each interpreter is opened by the write that binds it, so nothing is resolved at exec time. The exec runs a clone of the file that was opened, and no mount namespace, `chroot`, or later change to the path can redirect it. See [binding interpreters](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#binding-interpreters).

The interpreter runs under the path it was bound under. Calling this kfunc again replaces the selection. So does calling [`bpf_binprm_set_interp`](bpf_binprm_set_interp.md), and calling this kfunc replaces a selection made by [`bpf_binprm_set_interp`](bpf_binprm_set_interp.md).

**Parameters**

`bprm`: the binary that is being executed, as passed to the [`load`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#load) program.

`name`: the name the interpreter was bound under. Must be non-empty and `NULL`-terminated within `name__sz` bytes.

`name__sz`: size of the `name` buffer, including the terminating `NULL` byte.

**Returns**

`0` on success, or a negative error code on failure:

* `-EINVAL`: `name__sz` is zero, `name` is empty, or `name` is not `NULL`-terminated within `name__sz` bytes.
* `-ENOENT`: the matched entry did not bind an interpreter under `name`. A name longer than 32 characters, the longest name an entry can bind, also gives `-ENOENT`.
* `-ENOMEM`: the kernel could not allocate memory for the selection.

**Signature**

<!-- [KFUNC_DEF] -->
`#!c int bpf_binprm_select_interp(struct linux_binprm *bprm, const char *name, size_t name__sz)`

!!! note
    This function may sleep, and therefore can only be used from [sleepable programs](../syscall/BPF_PROG_LOAD.md/#bpf_f_sleepable).
<!-- [/KFUNC_DEF] -->

## Usage

This kfunc can only be called from the [`load`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#load) program of a [`binfmt_misc_ops`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md) handler. The verifier rejects it in any other program, including the handler's own `match` program.

Interpreters are selected by name so the program and the entry configuration don't have to agree on an order, and so the program does not depend on where a distribution installs its interpreters. The program can act on `-ENOENT`, for example by falling back to another name, or return it to fail the exec.

!!! note
    `name` is a sized memory argument, and the verifier rejects a read-only buffer such as a string literal in `.rodata` for it. Copy the name to the stack or to a map value first.

### Program types

The following program types can make use of this kfunc:

<!-- [KFUNC_PROG_REF] -->
- [`BPF_PROG_TYPE_STRUCT_OPS`](../program-type/BPF_PROG_TYPE_STRUCT_OPS.md)
<!-- [/KFUNC_PROG_REF] -->

### Example

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * binfmt_misc_ops handler for the selftest's bound-interpreter case: one
 * handler, one entry, an interpreter per guest architecture - each bound to
 * a file when the entry was registered rather than to a path resolved at
 * exec time. The load program names the one it wants; a name the entry did
 * not bind fails the exec, which the harness checks too.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define EI_CLASS	4
#define ELFCLASS64	2
#define E_MACHINE_OFF	18
#define EM_ARM		40
#define EM_AARCH64	183
#define EM_RISCV	243

extern int bpf_binprm_select_interp(struct linux_binprm *bprm,
				    const char *name, size_t name__sz) __ksym;

/* The guest architecture of a 64-bit ELF, or zero if it is not one. */
static __u16 elf_machine(struct linux_binprm *bprm)
{
	if (bprm->buf[0] != 0x7f || bprm->buf[1] != 'E' ||
	    bprm->buf[2] != 'L' || bprm->buf[3] != 'F' ||
	    bprm->buf[EI_CLASS] != ELFCLASS64)
		return 0;

	/* Little-endian 16-bit field, read byte-wise for the verifier. */
	return (__u8)bprm->buf[E_MACHINE_OFF] |
	       ((__u16)(__u8)bprm->buf[E_MACHINE_OFF + 1] << 8);
}

SEC("struct_ops.s/match")
bool BPF_PROG(interp_bind_match, struct linux_binprm *bprm)
{
	__u16 machine = elf_machine(bprm);

	return machine == EM_AARCH64 || machine == EM_RISCV ||
	       machine == EM_ARM;
}

SEC("struct_ops.s/load")
int BPF_PROG(interp_bind_load, struct linux_binprm *bprm)
{
	/*
	 * Names, not paths: each one selects a file the entry pre-opened, so
	 * nothing is resolved here or later, in any namespace. The buffers
	 * are on the stack because the verifier rejects .rodata for a sized
	 * memory argument.
	 */
	char first[] = "first";
	char second[] = "second";
	char unbound[] = "unbound";

	switch (elf_machine(bprm)) {
	case EM_AARCH64:
		return bpf_binprm_select_interp(bprm, first, sizeof(first));
	case EM_RISCV:
		return bpf_binprm_select_interp(bprm, second, sizeof(second));
	}

	/* The entry bound nothing under this name: -ENOENT fails the exec. */
	return bpf_binprm_select_interp(bprm, unbound, sizeof(unbound));
}

SEC(".struct_ops.link")
struct binfmt_misc_ops interp_bind = {
	.match	= (void *)interp_bind_match,
	.load	= (void *)interp_bind_load,
	.name	= "interp_bind",
};
```

This example is taken from the kernel self-tests: [`tools/testing/selftests/exec/interp_bind.bpf.c`](https://github.com/torvalds/linux/blob/v7.3-rc5/tools/testing/selftests/exec/interp_bind.bpf.c). The entry that uses this handler is registered disabled, given its interpreters, and then enabled:

```sh
echo ':interp_bind:B::::interp_bind:D' > /proc/sys/fs/binfmt_misc/register
echo '+first /path/to/first-interpreter' > /proc/sys/fs/binfmt_misc/interp_bind
echo '+second /path/to/second-interpreter' > /proc/sys/fs/binfmt_misc/interp_bind
echo 1 > /proc/sys/fs/binfmt_misc/interp_bind
```
