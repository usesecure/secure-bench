# Phase 23 experiment matrix

Every diagnostic row changes one declared variable relative to its control.
Exact commands, streams, JSON, durations, GNU time resources, hashes, and
terminal stages are retained under `output/`.

## Primary matrix

| ID | Changed variable | Result | Max RSS KiB |
|---|---|---:|---:|
| baseline-16-auto | control: AS 4 GiB, nproc 64, auto jobs | SIGSEGV | 101624 |
| targets-8/4/2/1-auto | target count only | all SIGSEGV | 101420–102212 |
| jobs-1 | jobs=1 | complete | 101628 |
| jobs-2 | jobs=2 | complete | 101332 |
| jobs-4/8/16 | jobs only | all SIGSEGV | 101260–102172 |
| no-process-limit | nproc unlimited | SIGSEGV | 101880 |
| process-limit-128 | nproc 128 | SIGSEGV | 102304 |
| no-address-space-limit | AS unlimited | complete | 111160 |
| address-space-8g | AS 8 GiB | SIGSEGV | 101636 |
| open-files-64 | nofile 64 | SIGSEGV | 101680 |
| stack-64m | stack 64 MiB | complete | 112160 |

## Threshold matrix

| Changed variable | Result |
|---|---:|
| stack 8, 16, 32, 64, 128 MiB | all complete |
| stack 256, 512 MiB, 1 GiB | all SIGSEGV |
| AS 16, 32 GiB | both complete |
| jobs=3 | SIGSEGV |
| jobs=2 confirmation | complete |

The diagnostic and threshold ledgers are independent. Raw attempt directories
share `output/diagnostic/attempts` because the diagnostic recorder freezes one
canonical evidence path; IDs are unique and no attempt is overwritten.

