#!/usr/bin/env python3
"""Generate AOB signatures for every game address DSCSModLoader uses.

Input : a Steamless-unpacked copy of `Digimon Story CS.exe` (the shipped exe is
        SteamStub-encrypted on disk, so its .text cannot be scanned offline).
Output: src/signatures.inc (X-macro table compiled into the loader) and
        tools/signatures.json (human-readable report incl. the original RVAs).

Every signature is verified to match exactly once in .text and to resolve back to
the expected RVA. Run:

    python tools/gen_signatures.py <path-to-unpacked-exe>

Requires: pip install pefile capstone
"""
from __future__ import annotations

import bisect
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

import capstone
import pefile
from capstone import x86

BASE_HINT = 0x140000000
MIN_LEN = 12
MAX_LEN = 96
MAX_BACK_INSNS = 6

# --------------------------------------------------------------------------- #
#  Manifest: every address the loader uses, by symbolic name.
#  kind:
#    func      - address is an instruction start (function or patch site)
#    data      - address is a global, resolved through a RIP-relative reference
#    import    - IAT slot, resolved at runtime from the PE import directory
# --------------------------------------------------------------------------- #
FUNCS = {
    # GameInterface.cpp
    "GetSeenData": 0x1A4740, "GetGameContext": 0x1A70D0, "GetDigisterMap": 0x2CCB20,
    "GetSoundStruct": 0x2BB6D0, "SetScanData": 0x19AA60, "GetTimeDelta": 0x5030D0,
    "UseTargetDelta": 0x51C8C0, "GetTargetFPS": 0x51C8B0, "GetSaveDirPath": 0x2B9F00,
    "CreateSaveDir": 0x2BA570, "EncryptSaveFile": 0x2CFCF0, "DecryptSaveFile": 0x2CFF70,
    "EndThread": 0x8344C8, "GetResourceDirCStr": 0x4F8F60, "GetResourceDirString": 0x5F70F0,
    "AddArchiveOverride": 0x4FD150,
    "VfsDeleteFile": 0x5F6FA0, "VfsCreateFile": 0x5F6E70, "VfsWriteFile": 0x5F6D30,
    "VfsReadFile": 0x5F6C10,
    # DSCSModLoader.cpp
    "ResourceManagerUpdate": 0x500EC0, "GetControllerType": 0x57BFF0,
    "BaseUpdate": 0x52B6D0, "SetMaxFPS": 0x27B150,
    "CreateSave": 0x288990, "WriteSaveFile": 0x2BAB20, "LoadSave": 0x289BB0,
    "ReadSaveFile": 0x2BAE90,
    "Strtoul": 0x82D8F0,
    # patch / hook sites (instruction starts)
    "Site_VSyncSwapInterval": 0x2786EA,     # mov ecx,1 ; imm patched to 0
    "Site_KeyboardStrtolCall": 0x2D0232,    # call strtol -> strtoul
    "Site_FrameDeltaRead1": 0x582CED,       # movss xmm2,[rip+X] -> g_FrameDelta
    "Site_FrameDeltaRead2": 0x22A37B,       # movss xmm3,[rip+X] -> g_FrameDeltaHalf
    "Site_FrameDeltaRead3": 0x2290EF,       # movss xmm3,[rip+X] -> g_FrameDeltaHalf
    "Site_SquirrelInitTail": 0x1FA7AE,      # tail jmp, replaced by jmp _squirrelInit
    "Site_ArchiveListInit": 0x2CF1BA,       # 12-byte call + jmp to the skip target
    "Site_ArchiveListInitEnd": 0x2CF2F1,    # first insn after the vanilla list init
}

DATA = {
    "AppContext": 0xF208A0, "ResourceManagerContext": 0xC09188, "GameSaveData": 0xF20758,
    "FrameDelta": 0xC3AA58, "MaxFPS": 0xBF5F4C, "WindowDC": 0xC365A8,
    # FrameDeltaHalf (0xC3AA5C) is NOT listed: it is the otherwise unused upper dword of the
    # 8-byte slot at FrameDelta and has no code references. The loader derives it as FrameDelta+4.
    "ArchiveCount": 0xF20770, "ArchiveList": 0xF219C0, "ArchiveTable": 0xF229C0,
    "ArchiveIsInit": 0xF20656,
}

IMPORTS = {
    "IAT_wglGetProcAddress": ("opengl32.dll", "wglGetProcAddress", 0x8BFC48),
    "IAT_SteamAPI_Init": ("steam_api64.dll", "SteamAPI_Init", 0x8C09D0),
}


# Squirrel 2.2 API (from upstream src/squirrel.cpp; sq_setparamscheck corrected from the
# mid-instruction 0x6080D0 to the function start 0x6080B0).
SQUIRREL = {
    "sq_open": 0x607140, "sq_newthread": 0x606FF0, "sq_seterrorhandler": 0x607EF0,
    "sq_getprintfunc": 0x6068C0, "sq_wakeupvm": 0x608510, "sq_getvmstate": 0x606C00,
    "sq_compile": 0x605F40, "sq_compilebuffer": 0x606060, "sq_enabledebuginfo": 0x606190,
    "sq_setcompilererrorhandler": 0x607CE0, "sq_push": 0x607240, "sq_pop": 0x616990,
    "sq_poptop": 0x616930, "sq_remove": 0x616B40, "sq_gettop": 0x606A50,
    "sq_settop": 0x608330, "sq_move": 0x606CD0, "sq_newuserdata": 0x6070C0,
    "sq_newtable": 0x606F50, "sq_newclosure": 0x606D20, "sq_setparamscheck": 0x6080B0,
    "sq_bindenv": 0x605B20, "sq_pushstring": 0x607410, "sq_pushfloat": 0x6072E0,
    "sq_pushinteger": 0x607330, "sq_pushbool": 0x607280, "sq_pushnull": 0x607380,
    "sq_gettype": 0x606A60, "sq_getsize": 0x6068E0, "sq_tostring": 0x608480,
    "sq_tobool": 0x608430, "sq_getstring": 0x6069A0, "sq_getinteger": 0x6066F0,
    "sq_getfloat": 0x6065C0, "sq_getbool": 0x6063C0, "sq_getuserpointer": 0x606B50,
    "sq_getuserdata": 0x606A90, "sq_setreleasehook": 0x608220, "sq_getscratchpad": 0x6068D0,
    "sq_setnativeclosurename": 0x607FE0, "sq_setinstanceup": 0x607F80, "sq_getinstanceup": 0x606630,
    "sq_createinstance": 0x6060A0, "sq_setattributes": 0x607B10, "sq_getattributes": 0x606270,
    "sq_getclass": 0x606410, "sq_weakref": 0x608730, "sq_pushroottable": 0x607400,
    "sq_pushregistrytable": 0x6073F0, "sq_setroottable": 0x6082A0, "sq_setconsttable": 0x607CF0,
    "sq_newslot": 0x606E60, "sq_get": 0x6061C0, "sq_rawget": 0x607620,
    "sq_rawset": 0x620B80, "sq_rawdeleteslot": 0x607490, "sq_arrayappend": 0x605710,
    "sq_arraypop": 0x605800, "sq_setdelegate": 0x607E00, "sq_getdelegate": 0x606500,
    "sq_getweakrefval": 0x606C20, "sq_clear": 0x605E20, "sq_call": 0x605D30,
    "sq_getlocal": 0x606760, "sq_throwerror": 0x6083A0, "sq_getlasterror": 0x606750,
    "sq_getstackobj": 0x606960, "sq_pushobject": 0x607390, "sq_addref": 0x6056F0,
    "sq_release": 0x607A70, "sq_resetobject": 0x607B00, "sq_collectgarbage": 0x605F30,
    "sq_readclosure": 0x607990, "sq_malloc": 0x608E70, "sq_realloc": 0x608E80,
    "sq_free": 0x608E60, "sq_stackinfos": 0x608D60, "sq_setdebughook": 0x607D70,
}


# --------------------------------------------------------------------------- #
@dataclass
class Image:
    pe: pefile.PE
    mem: bytes
    text_lo: int
    text_hi: int
    func_starts: list = field(default_factory=list)
    func_ranges: list = field(default_factory=list)

    @property
    def text(self) -> bytes:
        return self.mem[self.text_lo:self.text_hi]


def load(path: str) -> Image:
    pe = pefile.PE(path)
    mem = pe.get_memory_mapped_image()
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    lo = text.VirtualAddress
    hi = lo + text.Misc_VirtualSize
    rf = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
    return Image(pe, mem, lo, hi, [b for b, _ in rf], rf)


MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True


def insn_mask(ins) -> list[bool]:
    """True = byte is stable; False = wildcard (address-dependent)."""
    mask = [True] * ins.size
    rel_branch = ins.group(x86.X86_GRP_JUMP) or ins.group(x86.X86_GRP_CALL)
    for op in ins.operands:
        if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP and ins.disp_size:
            for i in range(ins.disp_offset, ins.disp_offset + ins.disp_size):
                mask[i] = False
        if op.type == x86.X86_OP_IMM and rel_branch and ins.imm_size == 4:
            for i in range(ins.imm_offset, ins.imm_offset + 4):
                mask[i] = False
        # absolute 64-bit addresses (movabs) are relocated too
        if op.type == x86.X86_OP_IMM and ins.imm_size == 8 and op.imm >= BASE_HINT:
            for i in range(ins.imm_offset, ins.imm_offset + 8):
                mask[i] = False
    return mask


def decode_from(img: Image, rva: int, limit: int = MAX_LEN + 32):
    return list(MD.disasm(img.mem[rva:rva + limit], BASE_HINT + rva))


def func_insns(img: Image, rva: int):
    i = bisect.bisect_right(img.func_starts, rva) - 1
    if i < 0:
        return None
    b, e = img.func_ranges[i]
    if not (b <= rva < e):
        return None
    return list(MD.disasm(img.mem[b:e], BASE_HINT + b))


def to_pattern(data: bytes, mask: list[bool]) -> str:
    return " ".join(f"{b:02X}" if m else "??" for b, m in zip(data, mask))


def to_regex(data: bytes, mask: list[bool]) -> re.Pattern:
    # Lookahead so finditer also reports OVERLAPPING matches (a plain regex skips a second
    # occurrence that starts inside the first one, which falsely reports a pattern unique).
    body = b"".join(re.escape(bytes([b])) if m else b"." for b, m in zip(data, mask))
    return re.compile(b"(?=" + body + b")", re.DOTALL)


def count_matches(img: Image, data: bytes, mask: list[bool], cap: int = 2) -> list[int]:
    rx = to_regex(data, mask)
    hits = []
    for m in rx.finditer(img.text):
        hits.append(img.text_lo + m.start())
        if len(hits) >= cap:
            break
    return hits


def unique_sig_at(img: Image, start: int):
    """Grow a pattern from instruction start `start` until unique. -> (pattern, data, mask) | None"""
    data, mask = b"", []
    for ins in decode_from(img, start):
        data += bytes(ins.bytes)
        mask += insn_mask(ins)
        if len(data) < MIN_LEN or sum(mask) < 8:
            continue
        if len(data) > MAX_LEN:
            return None
        hits = count_matches(img, data, mask)
        if len(hits) == 1 and hits[0] == start:
            return to_pattern(data, mask), data, mask
    return None


def best_sig_for(img: Image, rva: int):
    """Try anchoring at rva, then up to MAX_BACK_INSNS earlier instructions. -> (pattern, offset)"""
    candidates = []
    r = unique_sig_at(img, rva)
    if r:
        candidates.append((r[0], 0))
    insns = func_insns(img, rva)
    if insns:
        addrs = [i.address - BASE_HINT for i in insns]
        if rva in addrs:
            k = addrs.index(rva)
            for back in range(1, MAX_BACK_INSNS + 1):
                if k - back < 0:
                    break
                s = addrs[k - back]
                r = unique_sig_at(img, s)
                if r:
                    candidates.append((r[0], rva - s))
    if not candidates:
        return None
    return min(candidates, key=lambda c: len(c[0]))


def rip_refs_all(img: Image, targets: set[int]) -> dict[int, list]:
    """One sweep: target -> [(insn_rva, insn_len, disp_offset)] for RIP-relative refs."""
    out: dict[int, list] = {t: [] for t in targets}
    for b, e in img.func_ranges:
        for ins in MD.disasm(img.mem[b:e], BASE_HINT + b):
            if ins.disp_size != 4:
                continue
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp - BASE_HINT
                    if t in out:
                        out[t].append((ins.address - BASE_HINT, ins.size, ins.disp_offset))
    return out


def is_insn_start(img: Image, rva: int) -> bool | None:
    insns = func_insns(img, rva)
    if insns is None:
        return None  # no unwind info (leaf/thunk) - cannot check
    return any(i.address - BASE_HINT == rva for i in insns)


def call_sites_to(img: Image, target: int, limit=40):
    """Direct `call rel32` sites to target (scan for E8 + rel32)."""
    out = []
    t = img.text
    for m in re.finditer(b"\xE8", t):
        pos = img.text_lo + m.start()
        rel = struct.unpack_from("<i", img.mem, pos + 1)[0]
        if pos + 5 + rel == target:
            out.append(pos)
            if len(out) >= limit:
                break
    return out


def import_slot(img: Image, dll: str, func: str):
    for entry in img.pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll.decode().lower() != dll.lower():
            continue
        for imp in entry.imports:
            if imp.name and imp.name.decode() == func:
                return imp.address - img.pe.OPTIONAL_HEADER.ImageBase
    return None


# --------------------------------------------------------------------------- #
def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    repo = Path(__file__).resolve().parents[1]
    img = load(sys.argv[1])
    funcs = dict(FUNCS)
    funcs.update(SQUIRREL)

    report, inc, failures = [], [], []

    for name, rva in funcs.items():
        if is_insn_start(img, rva) is False:
            failures.append(f"{name} (0x{rva:X} is not an instruction start)")
            continue
        sig = best_sig_for(img, rva)
        if sig:
            pat, off = sig
            report.append(dict(name=name, kind="code", rva=hex(rva), pattern=pat, offset=off))
            inc.append(f'SIG_CODE({name}, "{pat}", {off}, 0x{rva:X})')
            continue
        # fallback: resolve via a unique direct call site
        done = False
        for site in call_sites_to(img, rva):
            s = best_sig_for(img, site)
            if s:
                pat, off = s
                report.append(dict(name=name, kind="calltarget", rva=hex(rva), pattern=pat, offset=off))
                inc.append(f'SIG_CALLTARGET({name}, "{pat}", {off}, 0x{rva:X})')
                done = True
                break
        if not done:
            failures.append(name)

    refs = rip_refs_all(img, set(DATA.values()))
    for name, rva in DATA.items():
        best = None
        for irva, ilen, doff in refs[rva][:25]:
            s = best_sig_for(img, irva)
            if s and (best is None or len(s[0]) < len(best[0])):
                best = (s[0], s[1], doff, ilen)
        if best is None:
            failures.append(name)
            continue
        pat, off, doff, ilen = best
        report.append(dict(name=name, kind="data", rva=hex(rva), pattern=pat, offset=off,
                           disp_offset=doff, insn_len=ilen))
        inc.append(f'SIG_RIPREL({name}, "{pat}", {off}, {doff}, {ilen}, 0x{rva:X})')

    for name, (dll, fn, rva) in IMPORTS.items():
        slot = import_slot(img, dll, fn)
        if slot != rva:
            failures.append(f"{name} (import slot {slot!r} != expected 0x{rva:X})")
            continue
        report.append(dict(name=name, kind="import", rva=hex(rva), dll=dll, function=fn))
        inc.append(f'SIG_IMPORT({name}, "{dll}", "{fn}", 0x{rva:X})')

    header = [
        "// GENERATED by tools/gen_signatures.py - do not edit by hand.",
        "// SIG_CODE(name, pattern, offsetFromMatch, expectedRva)",
        "// SIG_CALLTARGET(name, pattern, offsetToCallInsn, expectedRva)",
        "// SIG_RIPREL(name, pattern, offsetToInsn, dispOffsetInInsn, insnLength, expectedRva)",
        "// SIG_IMPORT(name, dll, function, expectedRva)",
        "",
    ]
    (repo / "include" / "dscs" / "signatures.inc").write_text("\n".join(header + inc) + "\n", encoding="utf-8")
    (repo / "tools" / "signatures.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    kinds = {}
    for r in report:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print(f"generated {len(report)} signatures {kinds}; failures: {failures}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
