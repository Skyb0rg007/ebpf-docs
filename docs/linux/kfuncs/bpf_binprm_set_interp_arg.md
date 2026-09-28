---
title: "KFunc 'bpf_binprm_set_interp_arg'"
description: "This page documents the 'bpf_binprm_set_interp_arg' eBPF kfunc, including its definition, usage, program types that can use it, and examples."
---
# KFunc `bpf_binprm_set_interp_arg`

<!-- [FEATURE_TAG](bpf_binprm_set_interp_arg) -->
[:octicons-tag-24: v7.3](https://github.com/torvalds/linux/commit/b4bfe2f6b0117f3d8de6430bdaee10094383e97a)
<!-- [/FEATURE_TAG] -->

Set a single argument to pass to the interpreter.

## Definition

Stage `arg` as an argument for the interpreter selected with [`bpf_binprm_set_interp`](bpf_binprm_set_interp.md) or [`bpf_binprm_select_interp`](bpf_binprm_select_interp.md). The argument is inserted between the interpreter and the binary in the argument vector, the same as the single optional argument on a `#!` interpreter line. The kernel copies the argument, so the buffer can be reused as soon as the kfunc returns. Calling this kfunc again replaces the argument.

**Parameters**

`bprm`: the binary that is being executed, as passed to the [`load`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#load) program.

`arg`: the argument to pass. Must be non-empty and `NULL`-terminated within `arg__sz` bytes.

`arg__sz`: size of the `arg` buffer, including the terminating `NULL` byte.

**Returns**

`0` on success, or a negative error code on failure:

* `-EINVAL`: `arg__sz` is zero, `arg` is empty, or `arg` is not `NULL`-terminated within `arg__sz` bytes.
* `-ENOMEM`: the kernel could not allocate its copy of the argument.

**Signature**

<!-- [KFUNC_DEF] -->
`#!c int bpf_binprm_set_interp_arg(struct linux_binprm *bprm, const char *arg, size_t arg__sz)`

!!! note
    This function may sleep, and therefore can only be used from [sleepable programs](../syscall/BPF_PROG_LOAD.md/#bpf_f_sleepable).
<!-- [/KFUNC_DEF] -->

## Usage

This kfunc can only be called from the [`load`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md#load) program of a [`binfmt_misc_ops`](../program-type/BPF_PROG_TYPE_STRUCT_OPS/binfmt_misc_ops.md) handler. The verifier rejects it in any other program, including the handler's own `match` program.

One use is a handler that rewrites the interpreter of `#!` scripts, for example to resolve an `$ORIGIN`-relative interpreter path. Such a handler can use this kfunc to keep the argument that followed the interpreter on the `#!` line.

The staged argument conflicts with the `BPF_BINPRM_TRANSPARENT` and `BPF_BINPRM_LOADER` flags of [`bpf_binprm_set_flags`](bpf_binprm_set_flags.md), since those leave the argument vector untouched. The exec fails if the load program stages an argument and sets either of those flags.

!!! note
    `arg` is a sized memory argument, and the verifier rejects a read-only buffer such as a string literal in `.rodata` for it. Copy the argument to the stack or to a map value first.

### Program types

The following program types can make use of this kfunc:

<!-- [KFUNC_PROG_REF] -->
- [`BPF_PROG_TYPE_STRUCT_OPS`](../program-type/BPF_PROG_TYPE_STRUCT_OPS.md)
<!-- [/KFUNC_PROG_REF] -->

### Example

!!! example "Docs could be improved"
    This part of the docs is incomplete, contributions are very welcome
