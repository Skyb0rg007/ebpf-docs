---
title: "KFunc 'bpf_binprm_set_flags'"
description: "This page documents the 'bpf_binprm_set_flags' eBPF kfunc, including its definition, usage, program types that can use it, and examples."
---
# KFunc `bpf_binprm_set_flags`

<!-- [FEATURE_TAG](bpf_binprm_set_flags) -->
[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)
<!-- [/FEATURE_TAG] -->

Choose the interpreter invocation flags for the current exec.

## Definition

A static binfmt_misc entry fixes how its interpreter is invoked at registration time, with the `P`, `C`, `O`, `T` and `L` flags. A [`binfmt_misc_ops`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md) handler makes the same choices for each exec by calling this kfunc from its `load` program. Calling this kfunc again replaces the flags, and passing `0` clears them.

**Parameters**

`bprm`: the binary that is being executed, as passed to the [`load`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#load) program.

`flags`: a bitwise OR of zero or more of the values of `enum bpf_binprm_flags`.

**Returns**

`0` on success, or `-EINVAL` if `flags` contains an unknown bit or an invalid combination.

**Signature**

<!-- [KFUNC_DEF] -->
`#!c int bpf_binprm_set_flags(struct linux_binprm *bprm, enum bpf_binprm_flags flags)`

!!! note
    This function may sleep, and therefore can only be used from [sleepable programs](../syscall/BPF_PROG_LOAD.md/#bpf_f_sleepable).
<!-- [/KFUNC_DEF] -->

### Flags

```c
enum bpf_binprm_flags {
	BPF_BINPRM_PRESERVE_ARGV0	= (1ULL << 0),
	BPF_BINPRM_CREDENTIALS		= (1ULL << 1),
	BPF_BINPRM_EXECFD		= (1ULL << 2),
	BPF_BINPRM_TRANSPARENT		= (1ULL << 3),
	BPF_BINPRM_LOADER		= (1ULL << 4),
};
```

#### `BPF_BINPRM_PRESERVE_ARGV0`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)

Keep the caller's `argv[0]`, the same as the `P` flag. By default, binfmt_misc replaces `argv[0]` with the path to the binary. With this flag, the path to the binary is inserted as an extra argument and the original `argv[0]` follows it.

#### `BPF_BINPRM_CREDENTIALS`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)

Compute the credentials and security context of the new process from the binary instead of from the interpreter, the same as the `C` flag. Implies `BPF_BINPRM_EXECFD`. As with any setuid exec, this only takes effect in user namespaces that map the owner of the binary.

!!! warning
    With this flag the interpreter runs with the privileges of a setuid binary, so only use it with interpreters you trust.

#### `BPF_BINPRM_EXECFD`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)

Open the binary on behalf of the interpreter and pass the file descriptor in the `AT_EXECFD` auxiliary vector entry, the same as the `O` flag. This lets the interpreter run binaries it could not open by path, such as binaries that are not readable.

#### `BPF_BINPRM_TRANSPARENT`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/21e04378e0b1b2a9bdf34f2458d4950716b14b2e)

Run the interpreter transparently, the same as the `T` flag. The binary is passed through `AT_EXECFD` like with `BPF_BINPRM_EXECFD`, and the argument vector is left exactly as the caller built it. The kernel also sets `/proc/pid/exe` to the binary instead of the interpreter. The interpreter must be written for this: it finds `AT_FLAGS_TRANSPARENT_INTERP` set in the `AT_FLAGS` auxiliary vector entry and loads the binary from `AT_EXECFD`.

This flag also lets a handler run a binary passed to `execveat()` as a file descriptor with `O_CLOEXEC`, which the interpreter would have no path to open otherwise.

Can't be combined with `BPF_BINPRM_PRESERVE_ARGV0`, since the full argument vector is already preserved. The exec fails with `-EINVAL` if an argument was staged with [`bpf_binprm_set_interp_arg`](bpf_binprm_set_interp_arg.md).

#### `BPF_BINPRM_LOADER`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/375e8a31a8b069bf0ebf6398815057660fe059b1)

Substitute the selected interpreter for the loader in the binary's `PT_INTERP`, and run the binary itself as a native exec, the same as the `L` flag. The argument vector is left untouched, the credentials are computed from the binary, and there is no `AT_EXECFD`. A standard dynamic loader works as the substitute without changes.

The substitution only applies if the binary is an ELF with a `PT_INTERP`. An ELF without one runs natively, and a file handled by another binary format, such as a `#!` script, is handled as if the handler had not matched.

Can't be combined with any other flag. The exec fails with `-EINVAL` if an argument was staged with [`bpf_binprm_set_interp_arg`](bpf_binprm_set_interp_arg.md).

## Usage

This kfunc can only be called from the [`load`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#load) program of a [`binfmt_misc_ops`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md) handler. The verifier rejects it in any other program, including the handler's own `match` program.

Because the flags are chosen per exec, a single handler can invoke different binaries in different ways. For example, it can use `BPF_BINPRM_LOADER` for native ELF binaries and run an emulator for binaries of other architectures.

### Program types

The following program types can make use of this kfunc:

<!-- [KFUNC_PROG_REF] -->
- [`BPF_PROG_TYPE_STRUCT_OPS`](../program-type/BPF_PROG_TYPE_STRUCT_OPS.md)
<!-- [/KFUNC_PROG_REF] -->

### Example

```c
// SPDX-License-Identifier: GPL-2.0
/*
 * binfmt_misc_ops handler for the loader-substitution case: match the
 * marker the harness poked into the payload's e_ident padding and ask for
 * the selected interpreter to be substituted for the binary's PT_INTERP,
 * so the binary itself runs as a fully native exec.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define EI_CLASS	4
#define EI_PAD		9
#define ELFCLASS64	2

extern int bpf_binprm_set_interp(struct linux_binprm *bprm, const char *path,
				 size_t path__sz) __ksym;
extern int bpf_binprm_set_flags(struct linux_binprm *bprm,
				enum bpf_binprm_flags flags) __ksym;

SEC("struct_ops.s/match")
bool BPF_PROG(loader_match, struct linux_binprm *bprm)
{
	if (bprm->buf[0] != 0x7f || bprm->buf[1] != 'E' ||
	    bprm->buf[2] != 'L' || bprm->buf[3] != 'F' ||
	    bprm->buf[EI_CLASS] != ELFCLASS64)
		return false;

	/* The harness marks the payload with "LDRTST" at EI_PAD. */
	return bprm->buf[EI_PAD + 0] == 'L' && bprm->buf[EI_PAD + 1] == 'D' &&
	       bprm->buf[EI_PAD + 2] == 'R' && bprm->buf[EI_PAD + 3] == 'T' &&
	       bprm->buf[EI_PAD + 4] == 'S' && bprm->buf[EI_PAD + 5] == 'T';
}

SEC("struct_ops.s/load")
int BPF_PROG(loader_load, struct linux_binprm *bprm)
{
	char interp[] = "/tmp/binfmt_loader_interp";
	int err;

	err = bpf_binprm_set_flags(bprm, BPF_BINPRM_LOADER);
	if (err)
		return err;

	/* @path__sz includes the terminating NUL; 0 commits the selection. */
	return bpf_binprm_set_interp(bprm, interp, sizeof(interp));
}

SEC(".struct_ops.link")
struct binfmt_misc_ops loader = {
	.match = (void *)loader_match,
	.load = (void *)loader_load,
	.name = "loader",
};
```

This example is taken from the kernel self-tests: [`tools/testing/selftests/exec/loader.bpf.c`](https://github.com/torvalds/linux/blob/v7.3-rc5/tools/testing/selftests/exec/loader.bpf.c).
