# Use cross-platform service-account wording

Keychain-centric messages misdirect Windows users whose credentials use DPAPI. Source is upstream #7 (`cd2c911 6b19666 0ea5bb4`).

1. Reapply credential-store wording in `src/auth.ts` error paths, `src/cli.ts` service-account help and `skills/2password/SKILL.md` forget guidance.
2. Preserve platform-specific setup hints and the existing flags and exit behavior. Inspect service-account help if repeated vault flags have landed.

Acceptance: CLI help and simulated storage failures describe the local credential store correctly. Existing fake service-account tests pass across platforms.

Branch `rlp/wording`. Base `integration/rlp`. PR title “Use cross-platform service-account wording”.
