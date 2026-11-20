# Firmroot — Progress Log

Working memory for the phased build. Check boxes as steps complete; log
decisions, breakage, and fixes here.

## Environment

- Host: Windows + WSL Ubuntu (Python 3.14, binwalk, unsquashfs, readelf,
  nm, strings all present in WSL). Pipeline runs inside WSL at
  `/mnt/r/ai/firmroot`.
- Code: `src/firmroot/` (extract, services, symbols, gemini_client, scan).
- Samples in `samples/`:
  - `EDS5000_2.3.0.0R7.rom` — primary ground-truth target (ARM64, UBI+SQFS)
  - `JWNR2000v3_...img` — D-Link router, LZMA+SQFS @ offset
  - `XR1000-V1.0.64.18_5.0.19.chk` — D-Link router, UBI+SQFS
- `environment/.env` holds GEMINI_API_KEY (gitignored).

## Phase 1 — local validation pipeline

- [x] 1.1 Extraction — `extract.py`: direct SQFS/CRAMFS magic carve,
  UBI PEB-run reconstruction (data_offset from EC header, per-PEB data
  stream), binwalk fallback. EDS5000 ROM -> 2 SQFS volumes extracted.
- [x] 1.2 Service enumeration — `services.py`: init.d/rc.d/inittab/
  rc.local/etc-config parsing, shell var expansion, command-position
  binary detection, privilege notes.
- [x] 1.3 Symbol mapping — `symbols.py`: readelf/nm dynsym imports,
  4 buckets (network_input, file_write, auth, priv_drop), root+net+write
  -no-auth-no-drop heuristic, supplementary strings/version checks.
- [x] 1.4 Gemini structured triage — `gemini_client.py` uses
  `gemini-3-flash-preview` (available model) via google-generativeai
  library. Returns all 7 fields: title, explanation, priority,
  attack_scenario, permanent_fix, immediate_mitigation,
  compromise_indicators. JSON parser handles trailing commas.
- [x] 1.5 Ground-truth validation — COMPLETE:
  - EDS5000: 28 services / 28 binaries / 5 findings. F005 = dsrcts_server
    flagged High with real content: "accept/bind/listen/socket +
    fopen/fwrite, no auth/drop, root via sysinit". Gemini produced
    specific attack scenario (crafted TCP payload → root file write),
    permanent fix (auth handshake + O_NOFOLLOW), immediate mitigation
    (iptables restrict port), compromise indicators (/var/run/slave_dsrcts_*
    patterns). Not boilerplate.
  - JWNR: 3 services / 1 finding (pc) High — differentiated output.
  - XR1000: 23 services / 8 findings with varied priorities (High/Medium/
    Low) — not overfit, real differentiation.
  - Phase 1 exit criterion MET.

## Decisions log

- 2026-11-20: Synology .sa.bin dropped from samples — proprietary
  sectioned/encrypted update format, not worth reversing for Phase 1.
  XR1000 .chk used as third sample instead (same stripped-UBI layout as
  EDS5000, exercises the UBI path on a second device).
- 2026-11-20: EDS5000's UBI VID headers are scrub/blank — extractor treats
  PEB data area (data_offset..next PEB) as a raw stream and rescans for
  filesystem magics rather than parsing volumes/UBIFS.
- 2026-11-20: Service binary detection prefers "command position" paths
  (procd command params, exec lines, `&` background lines) with shell
  VAR=/path expansion; falls back to any executable absolute path.
  Eliminated cert-helper false positives (openssl/px5g under uhttpd).
- 2026-11-20: Shared objects (.so) excluded from service binaries;
  K* rc.d scripts skipped; generic script names (sysinit/boot) inherit
  the binary's name for readability.

## Breakage log

- binwalk (Windows pip) broken; Docker daemon off; no gcloud. Resolved by
  running everything inside WSL Ubuntu which has the full toolchain.
- `unsquashfs -o offset` does not work; carve SQFS by `hsqs`/`sqsh` magic +
  superblock bytes_used instead.
- readelf --dyn-syms fails on section-header-less binaries; nm -D fallback
  in symbols.py covers it (dsrcts_server is one).
- WSL `bash -c '...$VAR...'` eats `$VAR` — use literal paths or heredoc
  python in shell commands.
