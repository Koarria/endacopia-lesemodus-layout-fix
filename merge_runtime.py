#!/usr/bin/env python3
"""The verified PE merge routines; independent of the original developer workspace."""
from __future__ import annotations
import struct
le32=lambda v:struct.pack('<I',v)
rel32=lambda src_after,dest:struct.pack('<i',dest-src_after)

def reconstruct_layout(src:bytes, blob:bytes, var:dict)->bytes:
    n=var['new_section_raw_length']
    assert len(src)==3279360 and len(blob)==36700 and n==36864
    out=bytearray(src)+bytearray(blob)+bytearray(n-len(blob))
    for change in var['changes']:
        off=int(change['file_offset'],16)
        old=bytes.fromhex(change['expected_old_hex'])
        new=bytes.fromhex(change['new_hex'])
        assert len(old)==len(new) and out[off:off+len(old)]==old,(hex(off),old.hex(),out[off:off+len(old)].hex())
        out[off:off+len(new)]=new
    assert len(out)==var['patched_file_length']
    return bytes(out)

def build_merge(original,readmode,reader_manifest,standalone_layout,layout_manifest,var,blob):
    # Suppress the v0.32 testing-only file logger; geometry writes at 0x770196...0x7701BA
    # precede the logger. All no-match branches independently jump to epilogue 0x770BD5.
    entry_va=0x770000
    logger_start=0x1BC
    epilogue=0xBD5
    assert blob[logger_start:logger_start+5]==bytes.fromhex('88 5c 24 3f 89')
    assert blob[epilogue:epilogue+11]==bytes.fromhex('81 c4 0c 03 00 00 5e 5f 5b 5d c3')
    quiet_blob=bytearray(blob)
    quiet_blob[logger_start:logger_start+5]=b'\xe9'+rel32(entry_va+logger_start+5,entry_va+epilogue)
    quiet_blob=bytes(quiet_blob)
    assert len(quiet_blob)==len(blob)
    assert quiet_blob[:0x1BC]==blob[:0x1BC]
    assert quiet_blob[0x1C1:]==blob[0x1C1:]
    # Preserve ALL original readmode edits (including its SayAt intercept), and all
    # layout PE-header edits except the one conflicting intercept.
    out=bytearray(readmode)+bytearray(quiet_blob)+bytearray(var['new_section_raw_length']-len(quiet_blob))
    ignored=[]
    for change in var['changes']:
        off=int(change['file_offset'],16)
        old=bytes.fromhex(change['expected_old_hex'])
        new=bytes.fromhex(change['new_hex'])
        if off==0xDEEB:
            # A direct layout call would overwrite the room27-scoped Lesemodus hook.
            assert out[off:off+5]==readmode[off:off+5]==bytes.fromhex('e8 f1 1d 27 00')
            ignored.append(off)
            continue
        assert bytes(out[off:off+len(old)])==old, (hex(off),old.hex(),bytes(out[off:off+len(old)]).hex())
        out[off:off+len(new)]=new
    assert ignored==[0xDEEB]
    # v033 room27 hook originally fell back to DisplaySpeechAt (0x40C8F0).
    # Tail-chain to .dlay instead: .dlay updates x/y/w then tail-jumps to the
    # SAME original DisplaySpeechAt, preserving return address/stack/skip bits.
    wrapper_jmp_fileoff=0x27FD01
    wrapper_jmp_va=0x680901
    next_va=wrapper_jmp_va+5
    assert bytes(out[wrapper_jmp_fileoff:wrapper_jmp_fileoff+5])==b'\xe9'+rel32(next_va,0x40C8F0)
    bridge=b'\xe9'+rel32(next_va,entry_va)
    out[wrapper_jmp_fileoff:wrapper_jmp_fileoff+5]=bridge
    combined=bytes(out)
    assert len(combined)==var['patched_file_length']==3316224
    # All approved code changes from either parent are present, accounting for
    # the two controlled deviations (bridge and no logger).
    for c in reader_manifest['changes']:
        p=int(c['file_offset'],16)
        v=bytes.fromhex(c['new_hex'])
        if p==0x27FCD0:
            expected=bytearray(v)
            start=wrapper_jmp_fileoff-p
            expected[start:start+5]=bridge
            v=bytes(expected)
        assert combined[p:p+len(v)]==v,hex(p)
    for c in var['changes']:
        p=int(c['file_offset'],16)
        if p==0xDEEB:continue
        v=bytes.fromhex(c['new_hex'])
        assert combined[p:p+len(v)]==v,hex(p)
    assert combined[3279360:3279360+logger_start]==blob[:logger_start]
    assert combined[3279360+logger_start:3279360+logger_start+5]==quiet_blob[logger_start:logger_start+5]
    assert combined[3279360+logger_start+5:3279360+len(blob)]==blob[logger_start+5:]
    # PE32-header sanity for both parents. .text/.data virtual sizes and .dlay
    # section count remain valid; reserve in .text/.data is not overwritten.
    assert struct.unpack_from('<H',combined,0x146)[0]==7
    assert struct.unpack_from('<I',combined,0x240)[0]==0x27F912
    assert struct.unpack_from('<I',combined,0x290)[0]==0x53364
    assert struct.unpack_from('<I',combined,0x15c)[0]==0x288a00
    assert struct.unpack_from('<I',combined,0x190)[0]==0x379000
    assert combined[0x328:0x32d]==b'.dlay'
    assert struct.unpack_from('<I',combined,0x174)[0]==0x400000
    assert combined[0xDEEB:0xDEF0]==b'\xe8'+rel32(0x40EAF0,0x6808E1)
    assert combined[wrapper_jmp_fileoff:wrapper_jmp_fileoff+5]==b'\xe9'+rel32(0x680906,0x770000)
    # room27 cleanup at 0x680906 still clears the BSS flag and jumps back
    # to original Sc_Character_SayAt continuation (VA 0x40EAF0).
    cleanup_fileoff=0x27FCD0+(0x680906-0x6808D0)
    assert combined[cleanup_fileoff:cleanup_fileoff+7]==bytes.fromhex('c6 05 60 a3 74 00 00')
    assert combined[cleanup_fileoff+7:cleanup_fileoff+12]==b'\xe9'+rel32(0x680912,0x40EAF0)
    # Every changed byte in original prefix must be in an approved region.
    allowed=set()
    for c in reader_manifest['changes']+var['changes']:
        p=int(c['file_offset'],16)
        allowed.update(range(p,p+len(bytes.fromhex(c['new_hex']))))
    diff_prefix={i for i,(a,b) in enumerate(zip(original,combined[:len(original)])) if a!=b}
    assert diff_prefix <= allowed
    # Layout runtime tables are identical to v0.32 starting at offset 0xC18.
    assert combined[3279360+0xC18:3279360+len(blob)]==standalone_layout[3279360+0xC18:3279360+len(blob)]
    return combined, quiet_blob, len(diff_prefix)
