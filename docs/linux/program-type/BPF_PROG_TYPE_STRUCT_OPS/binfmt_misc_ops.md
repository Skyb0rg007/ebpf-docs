---
title: "Struct ops 'binfmt_misc_ops'"
description: "This page documents the 'binfmt_misc_ops' struct ops, its semantics, capabilities, and limitations."
---
# Struct ops `binfmt_misc_ops`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)

The `binfmt_misc_ops` struct ops lets BPF programs implement [binfmt_misc](https://docs.kernel.org/admin-guide/binfmt-misc.html) binary type handlers. A normal binfmt_misc entry recognizes a binary by a fixed magic byte sequence or by its filename extension, and always runs it with the same interpreter. A BPF handler decides with a program whether a binary is one it handles, and selects the interpreter and how to invoke it separately for each exec.

## Usage

Some use cases are:

* Routing binaries of other architectures to the right emulator by inspecting ELF headers, with a single handler for all architectures.
* Relocatable binaries, whose dynamic loader is found relative to the binary itself instead of at a fixed path. For example, an ELF binary with a `PT_INTERP` of `$ORIGIN/../lib/ld-linux-x86-64.so.2`.
* Running some binaries with a different dynamic loader than the one in their `PT_INTERP`, chosen per binary.

The kernel must be built with `CONFIG_BINFMT_MISC_BPF`, which requires binfmt_misc to be built into the kernel (`CONFIG_BINFMT_MISC=y`), as well as `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, and `CONFIG_DEBUG_INFO_BTF`.

### Registering a handler

Using a handler is a two-step process. First, load and attach the `binfmt_misc_ops` struct ops. This makes the handler available under its [`name`](#name) in the user namespace of the process that attached it. For example, with bpftool:

```sh
bpftool struct_ops register handler.bpf.o /sys/fs/bpf
```

Second, activate the handler with a binfmt_misc entry of type `B`. The `interpreter` field of the register string contains the name of the handler, and the `offset`, `magic`, and `mask` fields must be empty. The handler is looked up when the entry is registered, so registering the entry fails with `-ENOENT` if the handler is not attached yet:

```sh
echo ':my-entry:B::::my_handler:' > /proc/sys/fs/binfmt_misc/register
```

A handler is only visible in the user namespace it was registered in, and is not inherited by child user namespaces. So an entry can only use a handler registered in the same user namespace as its binfmt_misc instance. Two handlers in the same user namespace can't have the same name.

Once an entry uses a handler, the entry keeps the handler alive. Detaching or deleting the struct ops only prevents new entries from using the handler. To stop using a handler, remove the entry by writing `-1` to its file.

### Binding interpreters

The [`load`](#load) program can select an interpreter by path with the [`bpf_binprm_set_interp`](../../kfuncs/bpf_binprm_set_interp.md) kfunc. A path is resolved every time a binary is executed, in the mount namespace and root of the task executing it. That task controls what the path resolves to.

Alternatively, the entry can bind a set of interpreters when it is registered. The `load` program then selects one of them by name with the [`bpf_binprm_select_interp`](../../kfuncs/bpf_binprm_select_interp.md) kfunc. To do this, register the entry with the `D` flag so it starts disabled. Then bind each interpreter with a `+<name> <path>` write to the entry file, and enable the entry:

```sh
echo ':qemu:B::::my_handler:D' > /proc/sys/fs/binfmt_misc/register
echo '+aarch64 /usr/bin/qemu-aarch64' > /proc/sys/fs/binfmt_misc/qemu
echo '+arm /usr/bin/qemu-arm' > /proc/sys/fs/binfmt_misc/qemu
echo 1 > /proc/sys/fs/binfmt_misc/qemu
```

Each path must be absolute. It is opened during the write that binds it, with the credentials the entry file was opened with, the same way the `F` flag opens the interpreter of a static entry. Every exec runs a clone of the opened file, and the path is never resolved again.

Some limits apply:

* A name is a single word of printable ASCII characters, at most 32 characters long. Binding a name twice fails with `-EEXIST`.
* An entry can bind at most 100 interpreters. Every bound interpreter also counts toward the `/proc/sys/user/max_binfmt_misc_interpreters` limit. A write past either limit fails with `-ENOSPC`.
* An entry can't bind interpreters once it has been enabled. After an entry is enabled for the first time, `+` writes fail with `-EBUSY`. An entry registered without `D` can never bind interpreters.

Reading the entry file shows the handler and the bound interpreters. The path shown is the one the interpreter was bound under, and it may no longer point to the same file:

```
$ cat /proc/sys/fs/binfmt_misc/qemu
enabled
bpf my_handler
bpf-interpreter aarch64 /usr/bin/qemu-aarch64
bpf-interpreter arm /usr/bin/qemu-arm
flags:
```

### Invocation flags

A `B` entry can't have the `P`, `O`, `C`, `T`, `L`, or `F` flags in its register string. Instead, the `load` program chooses the equivalent of `P`, `O`, `C`, `T`, and `L` separately for each exec with the [`bpf_binprm_set_flags`](../../kfuncs/bpf_binprm_set_flags.md) kfunc. `F` isn't needed, since bound interpreters are already opened at registration. The `D` flag is the one flag that is allowed, since it controls how the entry is registered rather than how the interpreter is invoked.

## Fields and ops

```c
struct binfmt_misc_ops {
	bool (*[match](#match))(struct linux_binprm *bprm);
	int (*[load](#load))(struct linux_binprm *bprm);
	char [name](#name)[BINFMT_MISC_OPS_NAME_MAX];
};
```

Both [`match`](#match) and [`load`](#load) are required, and both must be sleepable programs, in the `struct_ops.s` section. Sleeping lets the programs read the file being executed, for example with [`bpf_dynptr_from_file`](../../kfuncs/bpf_dynptr_from_file.md).

Both programs receive a pointer to the `struct linux_binprm` of the binary being executed. Useful fields are `bprm->buf`, which contains the first bytes of the file, `bprm->file`, and `bprm->filename`.

### `match`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)

`#!c bool (*match)(struct linux_binprm *bprm)`

This program decides whether the handler handles the binary being executed. Return `true` to handle it, or `false` to let binfmt_misc continue with the remaining entries.

The `match` program is called while binfmt_misc looks for an entry for the binary, in the same order as the magic and extension matching of static entries, and the first entry that matches is used. It is called for every exec while the entry is enabled, so it should decide quickly for binaries it does not handle. For example, check the magic bytes in `bprm->buf` before reading more of the file.

Unlike static matching, the program is not limited to the first bytes of the file in `bprm->buf`. It can read the entire file, for example to find the ELF program headers.

The `match` program can only make the decision. The verifier rejects calls to the interpreter selection kfuncs from it.

### `load`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)

`#!c int (*load)(struct linux_binprm *bprm)`

This program is called when the handler's [`match`](#match) program returned `true`. It must select an interpreter and return `0`. It selects the interpreter with one of these kfuncs:

* [`bpf_binprm_set_interp`](../../kfuncs/bpf_binprm_set_interp.md) selects an interpreter by absolute path.
* [`bpf_binprm_select_interp`](../../kfuncs/bpf_binprm_select_interp.md) selects an interpreter the entry [bound](#binding-interpreters), by name.

It can also call these kfuncs:

* [`bpf_binprm_set_interp_arg`](../../kfuncs/bpf_binprm_set_interp_arg.md) sets an argument to pass to the interpreter before the binary.
* [`bpf_binprm_set_flags`](../../kfuncs/bpf_binprm_set_flags.md) chooses how the interpreter is invoked.

Once `match` returned `true`, the exec is committed to this handler. If `load` returns an error, the exec fails with that error, and binfmt_misc does not try the remaining entries. The exception is `-ENOEXEC`, which lets the kernel try the remaining binary formats, such as the ELF loader. `-ENOEXEC` is also the result if `load` returns `0` without selecting an interpreter, or returns a value that is not a valid error code.

### `name`

[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)

`#!c char name[BINFMT_MISC_OPS_NAME_MAX];`

The name that `B` entries use to refer to the handler. It must not be empty, it may only contain alphanumeric characters, `_` and `.`, and it may be at most 15 characters long (`BINFMT_MISC_OPS_NAME_MAX` is `16`, including the terminating `NULL` byte).

## Kfuncs

Only the [`load`](#load) program can call the following kfuncs:

* [`bpf_binprm_set_interp`](../../kfuncs/bpf_binprm_set_interp.md)
* [`bpf_binprm_select_interp`](../../kfuncs/bpf_binprm_select_interp.md)
* [`bpf_binprm_set_interp_arg`](../../kfuncs/bpf_binprm_set_interp_arg.md)
* [`bpf_binprm_set_flags`](../../kfuncs/bpf_binprm_set_flags.md)

Both programs can call the following file system kfuncs, which are not available to other struct ops. [:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/7bddf0e9f1081935d11d01d9344dbe7c3fda07f6)

* [`bpf_get_task_exe_file`](../../kfuncs/bpf_get_task_exe_file.md)
* [`bpf_put_file`](../../kfuncs/bpf_put_file.md)
* [`bpf_path_d_path`](../../kfuncs/bpf_path_d_path.md)
* [`bpf_get_dentry_xattr`](../../kfuncs/bpf_get_dentry_xattr.md)
* [`bpf_get_file_xattr`](../../kfuncs/bpf_get_file_xattr.md)
* [`bpf_real_data_inode`](../../kfuncs/bpf_real_data_inode.md)

## Example

The following handler routes 64-bit ELF binaries of other architectures to an interpreter for each architecture. The entry binds the interpreters under the names `first` and `second`, as shown in [binding interpreters](#binding-interpreters).

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

This example is taken from the kernel self-tests: [`tools/testing/selftests/exec/interp_bind.bpf.c`](https://github.com/torvalds/linux/blob/v7.3-rc5/tools/testing/selftests/exec/interp_bind.bpf.c). The same directory contains more handlers:

* [`nix_origin.bpf.c`](https://github.com/torvalds/linux/blob/v7.3-rc5/tools/testing/selftests/exec/nix_origin.bpf.c) runs ELF binaries whose `PT_INTERP` starts with `$ORIGIN/`, resolving the loader relative to the directory of the binary. It reads the program headers with [`bpf_dynptr_from_file`](../../kfuncs/bpf_dynptr_from_file.md) and finds the path of the binary with [`bpf_path_d_path`](../../kfuncs/bpf_path_d_path.md).
* [`transparent.bpf.c`](https://github.com/torvalds/linux/blob/v7.3-rc5/tools/testing/selftests/exec/transparent.bpf.c) runs the interpreter with `BPF_BINPRM_TRANSPARENT`.
* [`loader.bpf.c`](https://github.com/torvalds/linux/blob/v7.3-rc5/tools/testing/selftests/exec/loader.bpf.c) substitutes the loader with `BPF_BINPRM_LOADER`.
