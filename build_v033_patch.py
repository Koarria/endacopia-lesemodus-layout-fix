#!/usr/bin/env python3
"""Deterministic x86 PE patch creator for Endacopia original AGS 3.6.0.55.

Original binaries are never distributed. This script is supplied for the audit
of precise instruction changes and may be run on a locally-owned original PE.
"""
from __future__ import annotations
import hashlib
import json
import struct
from pathlib import Path
from dataclasses import dataclass

ENGINE_LEN = 3_279_360
ORIGINAL_SHA = "42e1f511cdc1cd7886f0b55666056e27ee09d3d2dacc64eb51c6f634796482c4"
V032_SHA = "cc3abbe7db1aec251d67ae01cdff9cbf7d1cd9f28809e26585e8059af6fd6bf3"
# Windows PE layout specific to this verified original engine.
IMAGE_BASE = 0x400000
TEXT_RAW_START = 0x400
TEXT_RVA = 0x1000
TEXT_START_VA = IMAGE_BASE + TEXT_RVA
CODE_CAVE_OFF = 0x27FCD0  # .text tail, explicitly extended VirtualSize; was zero-initialized slack
CODE_CAVE_VA = TEXT_START_VA + CODE_CAVE_OFF - TEXT_RAW_START
ROOM_GLOBAL_VA = 0x6F8E70  # displayed_room (independent global, two -10 assignments verified)
SKIP_FLAGS_VA = 0x733DFC # GameState::cant_skip_speech
FLAG_VA = 0x74A360 # first unallocated DWORD immediately after .data VirtualSize
SAYAT_CALL_OFF = 0x0DEEB
SAYAT_CALL_VA = 0x40EAEB
SAYAT_RETURN_VA = 0x40EAF0
DISPLAY_SPEECH_AT_VA = 0x40C8F0
FIRST_TIMER_OFF = 0x678EA
SECOND_TIMER_OFF = 0x10C4C0
BRANCH1 = 0x678FA
BRANCH2 = 0x10C4C7
TEXT_SECTION_HEADER = 0x238
DATA_SECTION_HEADER = 0x288


def le32(val: int)->bytes: return struct.pack('<I',val)
def rel32(src_after: int, dest:int)->bytes: return struct.pack('<i',dest-src_after)

class X86:
    def __init__(self,base_va:int):
        self.base=base_va;self.buf=bytearray();self.labels={};self.fixups=[]
    def pc(self):return self.base+len(self.buf)
    def emit(self,b:bytes):self.buf.extend(b)
    def label(self,l:str):
        assert l not in self.labels
        self.labels[l]=self.pc()
    def cond8(self,opcode:int,l:str):
        self.emit(bytes([opcode,0]));self.fixups.append(('r8',self.pc()-1,l))
    def jmp32(self,dest:int):
        addr=self.pc();self.emit(bytes([0xE9])+rel32(addr+5,dest))
    def imm32_label(self,l:str):
        self.fixups.append(('abs32',self.pc(),l));self.emit(b'\0'*4)
    def get(self):
        for typ,addr,target in self.fixups:
            dst=self.labels[target]
            ix=addr-self.base
            if typ=='r8':
                delta=dst-(addr+1)
                assert -128<=delta<=127,(target,delta)
                self.buf[ix]=delta & 255
            else:self.buf[ix:ix+4]=le32(dst)
        return bytes(self.buf)


def build(base:bytes):
    assert len(base)==ENGINE_LEN
    assert hashlib.sha256(base).hexdigest()==ORIGINAL_SHA, 'Unknown game executable/engine build'
    assert base[CODE_CAVE_OFF:CODE_CAVE_OFF+180]==bytes(180), 'code cave not empty'
    assert base[SAYAT_CALL_OFF:SAYAT_CALL_OFF+5]==bytes.fromhex('e8 00 de ff ff')
    assert base[FIRST_TIMER_OFF:FIRST_TIMER_OFF+7]==bytes.fromhex('f6 05 fc 3d 73 00 01')
    assert base[SECOND_TIMER_OFF:SECOND_TIMER_OFF+7]==bytes.fromhex('f6 05 fc 3d 73 00 01')
    assert base[BRANCH1:BRANCH1+2]==bytes.fromhex('74 0e')
    assert base[BRANCH2:BRANCH2+2]==bytes.fromhex('74 2f')
    assert struct.unpack_from('<I',base,TEXT_SECTION_HEADER+8)[0]==0x27F8AA
    assert struct.unpack_from('<I',base,DATA_SECTION_HEADER+8)[0]==0x53360
    assert base[0x6A3F8:0x6A402]==bytes.fromhex('c7 05 70 8e 6f 00 f6 ff ff ff')
    assert base[0x100910:0x10091A]==bytes.fromhex('c7 05 70 8e 6f 00 f6 ff ff ff')
    assert struct.unpack_from('<I',base,0x174)[0] == 0x400000, 'PE ImageBase unexpected' # optional PE header offset 0x158+0x1c=0x174

    a=X86(CODE_CAVE_VA)
    a.label('timer_classifier')
    # If ONLY AUTOTIMER=1 in skip flags, ZF=1. (turtle must remain automatic.)
    a.emit(bytes.fromhex('80 3D')+le32(SKIP_FLAGS_VA)+b'\x01')
    a.cond8(0x74,'allowed_ret')
    # Else allow timer exclusively during the guarded, scripted film SayAt call.
    a.emit(bytes.fromhex('80 3D')+le32(FLAG_VA)+b'\x01')
    a.label('allowed_ret')
    a.emit(b'\xc3')
    a.label('sayat_wrapper')
    # Preserve all registers, existing args, and mouse flags. Only test flags.
    a.emit(bytes.fromhex('83 3D')+le32(ROOM_GLOBAL_VA)+b'\x1b')
    a.cond8(0x75,'sayat_fallback')
    # Only override when the game ALSO requested an original timed auto-skip.
    a.emit(bytes.fromhex('F6 05')+le32(SKIP_FLAGS_VA)+b'\x01')
    a.cond8(0x74,'sayat_fallback')
    a.emit(bytes.fromhex('C6 05')+le32(FLAG_VA)+b'\x01')
    # We entered this wrapper with CALL: [esp] is original return address.
    # Divert only the post-SayAt return to the cleanup stub, without pushing
    # a second return address that would corrupt DisplaySpeechAt's parameters.
    a.emit(bytes.fromhex('C7 04 24'))
    a.imm32_label('after_sayat')
    a.label('sayat_fallback')
    a.jmp32(DISPLAY_SPEECH_AT_VA)
    a.label('after_sayat')
    a.emit(bytes.fromhex('C6 05')+le32(FLAG_VA)+b'\x00')
    a.jmp32(SAYAT_RETURN_VA)
    stub=a.get()
    assert len(stub)<180
    assert stub[0]==0x80
    assert a.labels['after_sayat'] < a.base + len(stub)
    assert a.labels['timer_classifier'] != a.labels['sayat_wrapper']
    # Code tail remains inside original raw section, before the next RVA.
    new_text_vsize=(CODE_CAVE_OFF + len(stub) - TEXT_RAW_START + TEXT_RVA) - TEXT_RVA
    assert 0x27F8AA < new_text_vsize <= 0x27FA00

    changes=[]
    out=bytearray(base)
    def mod(offset:int,old:bytes,new:bytes,why:str):
        assert len(old)==len(new)
        assert bytes(out[offset:offset+len(old)])==old,(hex(offset),old.hex(),bytes(out[offset:offset+len(old)]).hex())
        out[offset:offset+len(new)]=new
        changes.append({'file_offset':f'0x{offset:x}','expected_old_hex':old.hex(),'new_hex':new.hex(),'purpose':why})
    mod(CODE_CAVE_OFF, bytes(len(stub)), stub,'Validated executable code cave: guarded room27 SayAt hook and timeout classifier')
    mod(TEXT_SECTION_HEADER+8,le32(0x27F8AA),le32(new_text_vsize),'Expose injected instructions inside existing executable .text section')
    mod(DATA_SECTION_HEADER+8,le32(0x53360),le32(0x53364),'Reserve one DWORD as zero-initialized private timer override flag in existing .data section')
    # Calls classifier at two original timeout gates; same conditional branch lengths.
    for idx,why in [(FIRST_TIMER_OFF,'initial speech timer setup'),(SECOND_TIMER_OFF,'speech overlay timeout tick')]:
        old=bytes.fromhex('f6 05 fc 3d 73 00 01')
        site_va=TEXT_START_VA+(idx-TEXT_RAW_START)
        new=b'\xe8'+rel32(site_va+5,a.labels['timer_classifier'])+b'\x90\x90'
        mod(idx,old,new,why+': predicate (skip_flags==1) OR (projector_timer_override==1)')
    mod(BRANCH1,b'\x74',b'\x75','same branch target, invert skip check because classifier returns ZF=1 for allowed')
    mod(BRANCH2,b'\x74',b'\x75','same branch target, invert skip check because classifier returns ZF=1 for allowed')
    new_call=b'\xe8'+rel32(SAYAT_CALL_VA+5,a.labels['sayat_wrapper'])
    mod(SAYAT_CALL_OFF,bytes.fromhex('e8 00 de ff ff'),new_call,'Guard every Character::SayAt in room27 and restore override flag at return')
    assert len(out)==len(base)
    return bytes(out), {'code_cave_va':f'0x{CODE_CAVE_VA:x}', 'code_cave_offset':f'0x{CODE_CAVE_OFF:x}',
                'code_len':len(stub),'timer_classifier_va':f"0x{a.labels['timer_classifier']:x}",
                'sayat_wrapper_va':f"0x{a.labels['sayat_wrapper']:x}",
                'after_sayat_va':f"0x{a.labels['after_sayat']:x}",
                'timer_override_va':f'0x{FLAG_VA:x}', 'guarded_room':27,
                'new_text_virtual_size':new_text_vsize, 'new_data_virtual_size':0x53364,
                'changes':changes,'stub_hex':stub.hex()}


def main():
    import argparse
    parser=argparse.ArgumentParser(description="Audit / deterministic build of the original AGS 3.6.0.55 PE patch")
    parser.add_argument('original',type=Path,help='Personally owned Endacopia.exe or its PE prefix')
    parser.add_argument('--output',type=Path,required=True,help='New PE output path (never overwrites existing)')
    parser.add_argument('--manifest',type=Path,help='Write manifest JSON (optional)')
    args=parser.parse_args()
    with args.original.open('rb') as stream:
        base=stream.read(ENGINE_LEN)
    new, manifest=build(base)
    sha=hashlib.sha256(new).hexdigest()
    manifest.update({'name':'Endacopia optional Lesemodus v0.3.3', 'engine':'AGS 3.6.0.55',
        'original_prefix_length':ENGINE_LEN,'source_sha256':ORIGINAL_SHA,'v032_sha256':V032_SHA,
        'expected_patched_sha256':sha,'target_filename':'Endacopia_Lesemodus_360_v033.exe',
        'rules': 'Time expiry iff skip flags ==1, OR room27 Character.SayAt currently active with AUTOTIMER bit set; otherwise manual speech. Original mouse/keyboard handlers untouched.',
        'preserve':'Original EXE, German.tra, resource assets, configuration, savegames, existing mod EXEs; do not distribute game files.',
        'windows_test':'NOT performed. Film slideshow and turtle need user regression test.'})
    if args.output.exists():
        raise SystemExit(f'Refuse overwriting: {args.output}')
    args.output.write_bytes(new)
    if args.manifest:
        if args.manifest.exists():
            raise SystemExit(f'Refuse overwriting manifest: {args.manifest}')
        args.manifest.write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print('v0.3.3 engine SHA-256:',sha)
    print('Injected at VA',manifest['code_cave_va'],'len',manifest['code_len'])
    print('timer classifier:', manifest['timer_classifier_va'],'SayAt wrapper:',manifest['sayat_wrapper_va'],'after:',manifest['after_sayat_va'])
    print('new .text VS',hex(manifest['new_text_virtual_size']))
    print('Patches',len(manifest['changes']))
    print('Changed byte offsets:',sum(1 for x,y in zip(base,new) if x!=y))
    assert new != base
    allowed=set()
    for c in manifest['changes']:
        i=int(c['file_offset'],16)
        allowed.update(range(i,i+len(bytes.fromhex(c['new_hex']))))
    altered={i for i,(x,y) in enumerate(zip(base,new)) if x!=y}
    assert altered <= allowed

if __name__=='__main__': main()
