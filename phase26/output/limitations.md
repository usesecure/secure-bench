# Phase 26 limitations

Phase 26 is post-open, additive, and retrospective. It cannot restore blind
holdout or one-shot validity and does not reinterpret or replace the failed
Phase 22 Semgrep lane. The frozen Phase 25 Python verifier did not pass; Phase
25 correctly closed fail-closed. This successor certification is the authority
only for the additive Phase 26 conclusion.

The prohibition on opening the 112 source files means Phase 26 validates raw
finding paths and offsets against frozen manifest paths and byte bounds, but
does not independently map every line/column pair back to source bytes. The
source files remain bound by the previously frozen corpus commitments and Git
tree. No scanner was run to regenerate observations.

Zero historical network use is supported by the exact `--unshare-net` command,
cleared environment, resource evidence with zero socket messages, and frozen
provenance. A retrospective verifier cannot observe past network activity
directly. Phase 26 itself performs no network operations.

The certified comparison is only OpenGrep Phase 22 versus Semgrep CE Phase 25
in the capability-normalized lane. Secure Engine/native evidence is excluded,
and no overall three-scanner winner is declared.
