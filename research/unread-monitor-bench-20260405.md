# mail3 unread monitor benchmark

Date: 2026-04-05

Context:
- Enabled accounts: `1411`, `ms2`
- Current `ms2` INBOX unread UIDs: `4109` (`Low balance alert`), `4110` (`Your OpenRouter, Inc receipt [#1658-4079]`)
- Existing slon command: `./mail3 sync --get-unread --unique`

## What each command means

| Command | Meaning | Correct for "is there unread mail in inbox right now?" | Returns message details |
| --- | --- | --- | --- |
| `mail3 check -inbox-only` | Ask server for unread counts only | Yes | No |
| `mail3 check` | Ask server for unread counts across all synced mailboxes | No for Gmail, because labels like `[Gmail]/Important` duplicate the same mail | No |
| `mail3 peek -inbox-only -limit 10 -strategy unseen` | Search unread UIDs in INBOX, fetch headers for newest unread | Yes | Yes |
| `mail3 peek -inbox-only -limit 10 -strategy unseen -count-first` | Same as above, but skip deeper work when `STATUS UNSEEN` is zero | Yes | Yes |
| `mail3 peek -inbox-only -limit 10 -strategy window` | Fetch only the last 10 UIDs in INBOX and show unread among them | Usually, but approximate | Yes |
| `mail3 sync --get-unread --unique` | Sync bodies locally, then print unread fetched in this run | No | Sometimes, but wrong semantics for monitoring |

## Five-run timing summary

All timings are wall clock milliseconds across both enabled accounts.

| Command | Avg ms | Min ms | Max ms |
| --- | ---: | ---: | ---: |
| `mail3 check -inbox-only` | 2888.2 | 1728 | 6949 |
| `mail3 check` | 4633.0 | 3859 | 5903 |
| `mail3 peek -inbox-only -limit 10 -strategy unseen` | 2602.0 | 2215 | 3287 |
| `mail3 peek -inbox-only -limit 10 -strategy unseen -count-first` | 2336.6 | 2250 | 2488 |
| `mail3 peek -inbox-only -limit 10 -strategy window` | 2079.6 | 1941 | 2205 |
| `mail3 sync --get-unread --unique` | 7745.0 | 7333 | 8728 |

Raw samples:

```tsv
check_inbox_only	1	1836
check_inbox_only	2	2112
check_inbox_only	3	1728
check_inbox_only	4	6949
check_inbox_only	5	1816
check_all_mailboxes	1	3859
check_all_mailboxes	2	4081
check_all_mailboxes	3	5903
check_all_mailboxes	4	4235
check_all_mailboxes	5	5087
peek_unseen	1	2672
peek_unseen	2	2474
peek_unseen	3	2362
peek_unseen	4	3287
peek_unseen	5	2215
peek_unseen_count_first	1	2291
peek_unseen_count_first	2	2275
peek_unseen_count_first	3	2379
peek_unseen_count_first	4	2488
peek_unseen_count_first	5	2250
peek_window_10	1	2067
peek_window_10	2	1941
peek_window_10	3	2205
peek_window_10	4	2068
peek_window_10	5	2117
sync_get_unread_unique	1	8728
sync_get_unread_unique	2	7333
sync_get_unread_unique	3	7601
sync_get_unread_unique	4	7630
sync_get_unread_unique	5	7433
```

## Findings

- `sync --get-unread --unique` is the wrong monitoring primitive. It is much slower than the read-only probes and it misses unread mail that was fetched in an earlier run.
- `check` without `-inbox-only` is also the wrong monitor for Gmail inbox signal. It counted `ms2 [Gmail]/Important 4` in addition to `ms2 INBOX 2`, which is label duplication rather than six distinct unread emails.
- The precise header-listing strategy was not expensive. `peek ... -strategy unseen -count-first` averaged about `2.34s`, only about `0.26s` slower than the approximate last-10-UID window.
- The approximate window strategy was the fastest tested option and it did return both current unread inbox messages in the present state. It can still miss an older unread if it falls outside the last N UIDs.
- The extra `STATUS` request in `peek ... -count-first` did not make it slower here. It was slightly faster and much more stable than `check -inbox-only` in this sample.

## Recommended shape

Best single command if one command should answer both "any unread?" and "which ones?":

```sh
mail3 peek -inbox-only -limit 10 -strategy unseen -count-first
```

Two-step design if you want the absolute cheapest no-detail poll:

1. `mail3 check -inbox-only -binary`
2. If that returns `1`, run `mail3 peek -inbox-only -limit 10 -strategy unseen -count-first`

Approximate but slightly faster option:

```sh
mail3 peek -inbox-only -limit 10 -strategy window
```

This is acceptable if "older unread pushed outside the window" is genuinely rare enough for your workflow.
