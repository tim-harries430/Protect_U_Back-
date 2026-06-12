# Protect U Back — Windows Reparse / Alternate-Data-Stream Evidence

## Scope

- Four hardcore Windows path-aliasing vectors run against **real NTFS objects** under a disposable sandbox.
- Junction = directory reparse point. ADS = alternate data stream hidden on a benign host file.
- Verdicts are pub's actual `omega_access` / sampler output; no decision is hand-authored.

## Result

- Run date: 2026-06-12
- Cases: 4
- Intercepted: 4 / 4
- Filesystem: NTFS (C:)

## Case Table

| Case | Vector | Raw-OS disguise | pub outcome | Intercepted |
| --- | --- | --- | --- | --- |
| WIN-REPARSE-JUNCTION-001 | ntfs_directory_junction_reparse_out_of_boundary | lstat directory, islink false (reparses out of boundary) | HOLD / CONTAINER_ESCAPE (named reparse_point + resolve out of boundary) | True |
| WIN-REPARSE-JUNCTION-002 | ntfs_directory_junction_reparse_into_boundary | lstat directory, islink false (reparses *into* boundary, no escape) | NAMED reparse_point + redirect target recorded (blind spot closed) | True |
| WIN-ADS-FILEID-001 | ntfs_alternate_data_stream_file_id_collision | payload stream shares host file_id | DISCRIMINATED (metadata vector hash separated stream from host) | True |
| WIN-ADS-ENUM-001 | ntfs_alternate_data_stream_enumeration_blindspot | payload stream absent from directory enumeration | HOLD / OBSERVATION_BLINDNESS (blind spot -> hold, not pass) | True |

## Case Notes

### WIN-REPARSE-JUNCTION-001

- Description: Directory junction inside the skill root that reparses to a sibling tree outside the boundary, disguised as an ordinary folder.
- Raw-OS disguise: `{"lstat_object_type": "directory", "is_symlink_by_islink": false}`
- pub now observes: `{"object_type": "reparse_point", "reparse_tag": 2684354563, "redirect_target": "\\\\?\\C:\\dev\\sp\\.pytest_tmp\\evidence_zone\\j_escape\\outside_boundary", "resolved_path": "C:\\dev\\sp\\.pytest_tmp\\evidence_zone\\j_escape\\outside_boundary", "escaped_refs": ["C:\\dev\\sp\\.pytest_tmp\\evidence_zone\\j_escape\\outside_boundary"]}`
- Expected: HOLD
- pub verdict: `{"minimum_action": "HOLD", "state": "RESIDUAL", "residual_type": "CONTAINER_ESCAPE", "component": "div_b_j", "mechanism": "boundary_escape"}`
- Intercepted: True

### WIN-REPARSE-JUNCTION-002

- Description: Junction whose target stays inside the boundary (a sensitive ledger store). No escape fires, so resolve-landing-point says nothing — this is the exact blind spot now closed.
- Raw-OS disguise: `{"lstat_object_type": "directory", "is_symlink_by_islink": false}`
- pub now observes: `{"object_type": "reparse_point", "reparse_tag": 2684354563, "redirect_target": "\\\\?\\C:\\dev\\sp\\.pytest_tmp\\evidence_zone\\j_inbound\\skill_root\\ledger_store", "escaped_refs": [], "contained_refs": ["C:\\dev\\sp\\.pytest_tmp\\evidence_zone\\j_inbound\\skill_root\\ledger_store"]}`
- Expected: NAME THE REDIRECT (no escape, but never a plain directory)
- pub verdict: `{"object_named_as_reparse": true, "redirect_target_recorded": true, "reparse_tag_recorded": true}`
- Intercepted: True

### WIN-ADS-FILEID-001

- Description: Payload written into report.md:payload. The stream shares the host's NTFS record (device:inode), so file_id collides with the benign host file.
- Raw-OS disguise: `{"host_file_id": "5224858787565622666:6192449488506539", "stream_file_id": "5224858787565622666:6192449488506539", "file_id_collision": true}`
- pub now observes: `{"host_size": 27, "stream_size": 37, "host_metadata_sha256": "sha256:3402b0bb8337bb0bdfb6e22fe5fbf38c6fc214972e2111936c10c0ea2ae06210", "stream_metadata_sha256": "sha256:9b53cdbaf13b632e4f456e38f49b904c3178a57b48006def22793b5f40201425", "both_contained_in_boundary": true}`
- Expected: DISCRIMINATE (never collapse stream identity onto host file_id)
- pub verdict: `{"decision_basis": "metadata_vector_hash separates payload stream from host body; file_id treated as a signal, never as identity proof", "identity_collapsed_onto_file_id": false}`
- Intercepted: True

### WIN-ADS-ENUM-001

- Description: Payload stream exists and is non-empty, but a directory walk of the boundary never lists it, so any enumerate-the-files sweep is blind to it.
- Raw-OS disguise: `{"stream_exists": true, "stream_size": 37, "boundary_listing": ["report.md"], "stream_visible_in_listing": false}`
- pub now observes: `{"blind_spot": "ntfs_alternate_data_stream_unenumerated", "missing_field": "enumerated_stream_inventory", "confidence": 0.2}`
- Expected: HOLD
- pub verdict: `{"minimum_action": "HOLD", "state": "INCOMPLETE_HOLD", "requires_hold": true, "residual_type": "OBSERVATION_BLINDNESS", "component": "o_apply", "mechanism": "observation_blindness"}`
- Intercepted: True

## Closed blind spots

- `st_reparse_tag` is now sampled: an NT reparse point lstats as a directory but is named `reparse_point`, its tag recorded, so a junction pointing *inside* the boundary (WIN-REPARSE-JUNCTION-002) is no longer mistaken for an ordinary folder.
- `readlink` is now called for any redirect type (symlink or reparse point), so the junction's target is pinned in `symlink_target` instead of being dropped.
