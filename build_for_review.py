#!/usr/bin/env python3
"""Deterministically reconstruct Endacopia's combined read-mode and layout PE patch.
Requires a legally obtained Steam game installation, same target build.
Does not download, install, execute or alter the original game.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path
from build_v033_patch import build as build_readmode
from merge_runtime import reconstruct_layout,build_merge

ROOT=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
EXPECTED_PREFIX='42e1f511cdc1cd7886f0b55666056e27ee09d3d2dacc64eb51c6f634796482c4'
EXPECTED_COMBINED='41472082d91dc0c30a6930564fe8e3873b31177e9fe844573efc812ad72782f6'

def main():
    parser=argparse.ArgumentParser(description='Rebuild patched engine for review from a legally installed copy of Endacopia')
    parser.add_argument('original_exe',type=Path,help='Your original (unmodified) Endacopia.exe from Steam build 24625223')
    parser.add_argument('--output',type=Path,default=ROOT/'Lesemodus-mit-Layout-fix.exe',help='New output path (must not exist)')
    args=parser.parse_args()
    out=args.output.resolve()
    if out.exists():
        raise SystemExit('Refusing to overwrite output: '+str(out))
    with args.original_exe.open('rb') as f:
        original=f.read(3279360)
    if len(original)!=3279360 or sha(original)!=EXPECTED_PREFIX:
        raise SystemExit('Original engine prefix SHA-256 mismatch; do not patch this build')
    readmode,reader_manifest=build_readmode(original)
    if sha(readmode)!='43c55d0042cfd41ce2c9dba0036e3ae6efaa0f8eb156eeb4a05b9f974fb5d8af':
        raise SystemExit('Read-mode reconstruction mismatch')
    manifest=json.loads((ROOT/'data/patch_manifest_v032.json').read_text(encoding='utf-8'))
    var=manifest['variant']['autopilot']
    blob=(ROOT/'data/dlay_autopilot_v032.bin').read_bytes()
    if sha(blob)!=var['blob_sha256']:
        raise SystemExit('Layout runtime SHA-256 mismatch')
    standalone=reconstruct_layout(original,blob,var)
    if sha(standalone)!=var['expected_patched_sha256']:
        raise SystemExit('Standalone layout reconstruction mismatch')
    combined,quiet_blob,changed=build_merge(original,readmode,reader_manifest,standalone,manifest,var,blob)
    if sha(combined)!=EXPECTED_COMBINED:
        raise SystemExit('Combined engine SHA-256 mismatch')
    out.write_bytes(combined)
    print('PASS - deterministic rebuild successful')
    print('output:',out)
    print('file size:',len(combined))
    print('sha256:',sha(combined))
    print('changed byte positions in original engine prefix:',changed)
    print('Note: PE checks only, not a Windows gameplay validation.')

if __name__=='__main__':main()
