# External Hardcore Redteam Evidence

Date: 2026-06-08

Scope: external Windows-only hardcore filesystem redteam pressure test.

Source file:

```text
<EXTERNAL_REDTEAM_PATH>\reeeal hardcore.py
```

This evidence records an exploratory external redteam run. It is not the release gate. The purpose was to distinguish silent escape from under-classified autopsy mechanisms.

## Result Summary

```text
10 tests collected and executed after Windows ctypes harness fixes.

5 passed
5 failed
```

Interpretation:

```text
exact mechanism passed:       5
caught but under-classified:  4
environment/harness blocked:  1
confirmed silent escape:      0
```

The important finding is that the failing mechanism assertions did not demonstrate silent passage. In the under-classified cases, the scanner still observed mutation or scope pressure sufficient to send the action to HOLD / review.

## Failure Classification

### 1. mtime spoof with content tamper

Expected mechanism label:

```text
MTIME_SPOOFED
```

Observed labels:

```text
HASH_MUTATED
SCOPE_VIOLATION
```

Classification:

```text
caught but under-classified
```

Meaning: the content mutation was observed. The missing work is finer mtime spoof labeling, not primary detection.

### 2. hardlink cross-directory alias escape

Expected mechanism label:

```text
HARD_LINK_ALIAS
```

Observed labels:

```text
HASH_MUTATED
SCOPE_VIOLATION
```

Classification:

```text
caught but under-classified
```

Meaning: the mutation/scope pressure was observed. The missing work is finer file identity / nlink alias labeling.

### 3. junction point path redirection

Expected mechanism label:

```text
JUNCTION_PATH_REDIRECTED
```

Observed failure:

```text
OSError / DeviceIoControl(FSCTL_SET_REPARSE_POINT)
```

Classification:

```text
environment/harness blocked
```

Meaning: the attack setup did not complete cleanly on this Windows host / WinAPI harness path. This result is not evidence of PUB silent escape.

### 4. rename swap atomic metadata masquerade

Expected mechanism label:

```text
ATOMIC_SWAP_DETECTED
```

Observed labels:

```text
HASH_MUTATED
SCOPE_VIOLATION
```

Classification:

```text
caught but under-classified
```

Meaning: the mutated protected state was observed. The missing work is finer rename/identity trajectory labeling.

### 5. compound hardlink + mtime + ADS chain

Expected mechanism labels included:

```text
HARD_LINK_ALIAS
MTIME_SPOOFED
ADS_STREAM_CREATED
```

Observed labels:

```text
ADS_STREAM_CREATED
HASH_MUTATED
SCOPE_VIOLATION
```

Classification:

```text
caught but under-classified
```

Meaning: ADS and mutation were observed. The missing work is finer hardlink and mtime labeling inside a compound chain.

## Boundary Decision

This redteam run supports the v0.14 boundary distinction:

```text
HASH_MUTATED / SCOPE_VIOLATION / ADS_STREAM_CREATED
=> observed movement
=> send to HOLD / review

missing MTIME_SPOOFED / HARD_LINK_ALIAS / ATOMIC_SWAP_DETECTED
=> autopsy precision gap
=> not a silent escape when primary mutation was observed
```

## Follow-Up Work

Mechanism precision should improve through X-ray physical fields:

```text
file_id / inode
nlink
raw path vs resolved path
reparse / junction target
mtime / ctime grid
metadata vector hash
SceneSeed host capability flags
SceneReplayGuard surrounding protection
```

This evidence should be read as:

```text
0 confirmed silent escapes.
4 caught but under-classified mechanism labels.
1 environment/harness blocked attack setup.
```
