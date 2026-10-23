# Endacopia – Lesemodus mit Layout-Fix v1.0 (source/review kit)

**Purpose:** Security review and reproducibility of the modified Windows executable included in the optional German translation mod. This package contains **no original Endacopia.exe**, no original game archives, and **no nested ZIP files**.

## Why the uploaded player ZIP contains an EXE

The modified AGS 3.6.0.55 PE32 engine combines an optional manual-advance dialogue mode and layout adjustments. Both features intercept the same speech routine; the supplied Python sources implement and verify the shared hook chain. It operates as a local game executable launched from the installed game directory. The launch CMD does not install services or download anything. The source code intentionally applies byte-level modifications to an existing executable, so a scan or manual moderation review is appropriate.

**Technical scope:** Lesemodus v0.3.3, DeutschLayout v0.32, optional German.tra v7.45u. The translation file is not part of the engine build and is not needed to reproduce the EXE. This does not claim that VirusTotal has passed, and it does not certify absence of malicious content.

## Rebuilding (Python 3.10+; standard library only)

1. Obtain the legally installed, **unmodified** Steam Endacopia Windows game (Steam build **24625223**, dated **8 August 2026**).
2. Extract this source package to a working folder. Do **not** copy the original EXE into the source archive or a public repository.
3. Run in a terminal with your local game path, for example on Windows:

   `py -3 build_for_review.py "C:\Program Files (x86)\Steam\steamapps\common\Endacopia\Windows\Endacopia.exe" --output "Lesemodus-mit-Layout-fix.exe"`

   The example game path may differ. The tool reads only the first 3,279,360 bytes of the original executable, and refuses to patch if the source hash is different. It never overwrites the input file. Any existing output file is also refused.
4. Expected output: 3,316,224 bytes, SHA-256:

   `41472082d91dc0c30a6930564fe8e3873b31177e9fe844573efc812ad72782f6`

## File index

- `build_for_review.py`: reproducible build entry point (no hardcoded workspace paths).
- `build_v033_patch.py`: source implementing the Lesemodus hook and two timing gates.
- `merge_runtime.py`: source for layout PE reconstruction, collision handling and combined speech routing.
- `data/patch_manifest_v032.json`: exact location/expected-byte manifest and hashes.
- `data/dlay_autopilot_v032.bin`: **project-authored compiled** x86 layout routine/data, NOT original game content; provided so the build exactly matches the released executable.
- `reference/layout_v032_build_original.py`, `reference/pixel_font_widths_v032.json`, `reference/AutoLayout_757_PIXELKALIBRIERT_v032.tsv`: layout-generation source and inputs used during the original project; the historical generator refers to additional development/test inputs and is not standalone.
- `reference/build_lesemodus_layout_v10_original.py`, `reference/verify_lesemodus_layout_v10_original.py`: archived original developer scripts containing historical, absolute workspace paths; use `build_for_review.py` instead.
- `manifest_v1.0.json`, `reference/Technischer_Pruefbericht.md`: original hashes and independent offline verification report.

## Review and limitations

The compiled `dlay_autopilot_v032.bin` embeds our patch runtime and lookup table; its entire PE patch process and source methodology are documented here, but rebuilding that blob from the *historical* layout generator requires earlier intermediate data. It is not represented as fresh source-compiled assembly.

The output was independently checked at the PE, x86 call-routing, table and hash level. The **combined EXE has not been validated in a real Windows game playthrough**; no claim of functional or malware-free certification is made.

**Copyright:** The resulting EXE contains original AGS/game-engine bytes. Possession of this build kit does not grant distribution rights for the original game or engine. Nexus Mods may require a patch-only distribution or permission from the copyright owner. This source package is for review of the code/patch methodology, not a claim of redistribution permission.
