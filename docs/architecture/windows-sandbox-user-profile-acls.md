# Windows Sandbox User Profile ACLs

## What This Is

The Windows sandbox runs commands as a local sandbox user. Before that user can
run a command, Codex grants it access to the needed files.

On Windows, those grants are real filesystem ACLs. A grant on a directory can
inherit to child files. macOS and Linux use process sandboxes instead, so they do
not write new ACLs onto the user's files.

## The Risk

The user profile root is too broad to use as an ACL root:

```text
C:\Users\alben
```

A grant there can inherit into:

```text
C:\Users\alben\.ssh\config
C:\Users\alben\.tsh
C:\Users\alben\Documents
```

OpenSSH on Windows checks the ACL on `~/.ssh/config` and private key files. A
write-capable grant to another local user or group can make OpenSSH reject the
file outside Codex too.

## Paths That Reach SSH

These roots can reach `~/.ssh`:

```text
command_cwd = C:\Users\alben
writable_roots = [C:\Users\alben]
readable_roots = [C:\Users\alben]
```

They reach SSH because `.ssh` is under the profile root.

These roots reach SSH directly:

```text
command_cwd = C:\Users\alben\.ssh
writable_roots = [C:\Users\alben\.ssh]
readable_roots = [C:\Users\alben\.ssh]
```

## Paths That Do Not Reach SSH

A normal project directory does not reach SSH:

```text
command_cwd = C:\Users\alben\repo
```

That grant applies to the repo and its children. It does not apply to the
sibling path:

```text
C:\Users\alben\.ssh
```

A projectless output directory has the same shape:

```text
command_cwd = C:\Users\alben\Documents\Codex\2026-04-17-some-chat
```

## Current Fix

Before Codex sends roots to the elevated Windows setup helper, it removes the
user profile root from write roots. It expands the user profile root in read
roots to the profile's top-level children.

The write rule is:

```text
If root == USERPROFILE:
  drop it

If root == USERPROFILE\some-project:
  keep it
```

The read rule is:

```text
If root == USERPROFILE:
  replace it with visible top-level profile children

If child name starts with ".":
  skip it

If child has the Windows hidden attribute:
  skip it
```

This preserves broad read access for normal profile folders without writing an
ACL onto the profile root itself. It also skips hidden profile entries such as
`.ssh`, `.tsh`, `.aws`, `.kube`, and entries marked hidden by Windows. Write
access stays narrower because granting write to every child would still grant
write to sensitive folders.
