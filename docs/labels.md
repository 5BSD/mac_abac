# vLabel Labels

Labels are key-value pairs stored in extended attributes. Rules match process labels against file labels.

## Format

```
type=trusted,domain=system,name=nginx
```

Any keys work - `type`, `domain`, `name`, `level` are conventions, not requirements.

## Setting Labels

```sh
vlabelctl label set /path/to/file "type=trusted,domain=web"
vlabelctl label get /path/to/file
vlabelctl label remove /path/to/file
```

**Do not use `getfmac`/`setfmac`** - they don't work on ZFS.

## Process Labels

When a process executes a binary:

1. **Transition rule matches** → process gets `newlabel` from rule
2. **No transition, file has label** → process inherits file's label
3. **No transition, file unlabeled** → process keeps parent's label

Default label for unlabeled files/processes: `type=unlabeled`

## Pattern Matching

| Pattern | Matches |
|---------|---------|
| `type=app` | Labels with `type=app` |
| `type=app,domain=web` | Labels with both (AND) |
| `*` or `{}` | Any label |
| `!type=untrusted` | Labels without `type=untrusted` |

## Limits

| Limit | Value |
|-------|-------|
| Label size | 4 KB |
| Key length | 64 bytes |
| Value length | 256 bytes |
| Key-value pairs | 16 per label |
