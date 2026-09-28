---
title: "KFunc 'bpf_binprm_set_interp'"
description: "This page documents the 'bpf_binprm_set_interp' eBPF kfunc, including its definition, usage, program types that can use it, and examples."
---
# KFunc `bpf_binprm_set_interp`

<!-- [FEATURE_TAG](bpf_binprm_set_interp) -->
[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)
<!-- [/FEATURE_TAG] -->

Select the interpreter for the current exec by absolute path.

## Definition

Stage `path` as the interpreter that the binary being executed will be run with. The kernel copies the path, so the buffer can be reused as soon as the kfunc returns. The path is not opened by this kfunc. It is opened after the program returns, with the credentials of the task doing the exec, the same way binfmt_misc opens a statically registered interpreter that does not have the `F` flag. The path is resolved in the mount namespace and root of that task.

Calling this kfunc again replaces the selection. So does calling [`bpf_binprm_select_interp`](bpf_binprm_select_interp.md), and calling this kfunc replaces a selection made by [`bpf_binprm_select_interp`](bpf_binprm_select_interp.md).

**Parameters**

`bprm`: the binary that is being executed, as passed to the [`load`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#load) program.

`path`: absolute path to the interpreter. Must be `NULL`-terminated within `path__sz` bytes and start with `/`.

`path__sz`: size of the `path` buffer, including the terminating `NULL` byte.

**Returns**

`0` on success, or a negative error code on failure:

* `-EINVAL`: `path__sz` is zero, `path` is not `NULL`-terminated within `path__sz` bytes, or the path is not absolute.
* `-ENAMETOOLONG`: the path is `PATH_MAX` bytes or longer.
* `-ENOMEM`: the kernel could not allocate its copy of the path.

**Signature**

<!-- [KFUNC_DEF] -->
`#!c int bpf_binprm_set_interp(struct linux_binprm *bprm, const char *path, size_t path__sz)`

!!! note
    This function may sleep, and therefore can only be used from [sleepable programs](../syscall/BPF_PROG_LOAD.md/#bpf_f_sleepable).
<!-- [/KFUNC_DEF] -->

## Usage

This kfunc can only be called from the [`load`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#load) program of a [`binfmt_misc_ops`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md) handler. The verifier rejects it in any other program, including the handler's own `match` program.

The `load` program selects the interpreter and then returns `0` to commit the exec to it. A common pattern is to return the result of this kfunc directly, so a failure to stage the interpreter fails the exec.

Since the path is resolved when the binary is executed, whoever runs the binary controls what it resolves to, for example through a mount namespace or `chroot`. An entry that binds its interpreters at registration time, with [`bpf_binprm_select_interp`](bpf_binprm_select_interp.md) selecting between them, does not have this problem.

!!! note
    `path` is a sized memory argument, and the verifier rejects a read-only buffer such as a string literal in `.rodata` for it. Copy the path to the stack or to a map value first.

### Program types

The following program types can make use of this kfunc:

<!-- [KFUNC_PROG_REF] -->
- [`BPF_PROG_TYPE_STRUCT_OPS`](../program-type/BPF_PROG_TYPE_STRUCT_OPS.md)
<!-- [/KFUNC_PROG_REF] -->

### Example

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * binfmt_misc_ops handler for the selftest's fixed-interpreter case: match a
 * 64-bit aarch64 ELF header from the prefetched buffer and route it to a fixed
 * interpreter chosen by the program. This is the portable, self-contained
 * equivalent of routing a foreign binary to an emulator: it matches
 * programmatically and computes the interpreter, but points at a test binary
 * the harness installs rather than a system emulator.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define EI_CLASS	4
#define ELFCLASS64	2
#define EM_AARCH64	183

extern int bpf_binprm_set_interp(struct linux_binprm *bprm, const char *path,
				 size_t path__sz) __ksym;

/*
 * A magic-style decision needs nothing beyond the prefetched bprm->buf,
 * even though the match program could read the file.
 */
SEC("struct_ops.s/match")
bool BPF_PROG(bpf_interp_match, struct linux_binprm *bprm)
{
	__u16 machine;

	if (bprm->buf[0] != 0x7f || bprm->buf[1] != 'E' ||
	    bprm->buf[2] != 'L' || bprm->buf[3] != 'F' ||
	    bprm->buf[EI_CLASS] != ELFCLASS64)
		return false;

	/* e_machine is a 16-bit little-endian field at offset 18. */
	machine = (__u8)bprm->buf[18] | ((__u16)(__u8)bprm->buf[19] << 8);
	return machine == EM_AARCH64;
}

SEC("struct_ops.s/load")
int BPF_PROG(bpf_interp_load, struct linux_binprm *bprm)
{
	/*
	 * Keep the path on the (writable) stack: bpf_binprm_set_interp() takes
	 * a sized memory arg and the verifier rejects a read-only .rodata
	 * buffer for it. The harness installs the interpreter at this path.
	 */
	char interp[] = "/tmp/binfmt_bpf_interp";

	/* @path__sz includes the terminating NUL; 0 commits the selection. */
	return bpf_binprm_set_interp(bprm, interp, sizeof(interp));
}

SEC(".struct_ops.link")
struct binfmt_misc_ops bpf_interp = {
	.match = (void *)bpf_interp_match,
	.load = (void *)bpf_interp_load,
	.name = "bpf_interp",
};
```

This example is taken from the kernel self-tests: [`tools/testing/selftests/exec/bpf_interp.bpf.c`](https://github.com/torvalds/linux/blob/v7.3-rc5/tools/testing/selftests/exec/bpf_interp.bpf.c). The self-tests also contain a larger handler, [`nix_origin.bpf.c`](https://github.com/torvalds/linux/blob/v7.3-rc5/tools/testing/selftests/exec/nix_origin.bpf.c), which builds the path at exec time by resolving a `$ORIGIN`-relative `PT_INTERP` against the location of the binary.
