from __future__ import annotations
from typing import List, Dict, Tuple
from enum import Enum


# ======================
# Basic SIMD / FPU types
# ======================

class XMMREGISTER:
    Low: int
    High: int


class YMMREGISTER:
    Low: XMMREGISTER
    High: XMMREGISTER


class X87FPU:
    ControlWord: int
    StatusWord: int
    TagWord: int
    ErrorOffset: int
    ErrorSelector: int
    DataOffset: int
    DataSelector: int
    Cr0NpxState: int


class X87FPUREGISTER:
    data: bytes
    st_value: int
    tag: int

# ======================
# Flags / Bitfields
# ======================

class FLAGS:
    c: bool
    p: bool
    a: bool
    z: bool
    s: bool
    t: bool
    i: bool
    d: bool
    o: bool


class MXCSRFIELDS:
    FZ: bool
    PM: bool
    UM: bool
    OM: bool
    ZM: bool
    IM: bool
    DM: bool
    DAZ: bool
    PE: bool
    UE: bool
    OE: bool
    ZE: bool
    DE: bool
    IE: bool
    RC: int


class X87STATUSWORDFIELDS:
    B: bool
    C3: bool
    C2: bool
    C1: bool
    C0: bool
    ES: bool
    SF: bool
    P: bool
    U: bool
    O: bool
    Z: bool
    D: bool
    I: bool
    TOP: int


class X87CONTROLWORDFIELDS:
    IC: bool
    IEM: bool
    PM: bool
    UM: bool
    OM: bool
    ZM: bool
    DM: bool
    IM: bool
    RC: int
    PC: int


class LASTERROR:
    code: int
    name: str


# ======================
# Register Context
# ======================

class REGISTERCONTEXT32:
    cax: int
    ccx: int
    cdx: int
    cbx: int
    csp: int
    cbp: int
    csi: int
    cdi: int
    cip: int
    eflags: int

    gs: int
    fs: int
    es: int
    ds: int
    cs: int
    ss: int

    dr0: int
    dr1: int
    dr2: int
    dr3: int
    dr6: int
    dr7: int

    RegisterArea: bytes
    x87fpu: X87FPU
    MxCsr: int
    XmmRegisters: List[XMMREGISTER]
    YmmRegisters: List[YMMREGISTER]


class REGISTERCONTEXT64:
    cax: int
    ccx: int
    cdx: int
    cbx: int
    csp: int
    cbp: int
    csi: int
    cdi: int

    r8: int
    r9: int
    r10: int
    r11: int
    r12: int
    r13: int
    r14: int
    r15: int

    cip: int
    eflags: int

    gs: int
    fs: int
    es: int
    ds: int
    cs: int
    ss: int

    dr0: int
    dr1: int
    dr2: int
    dr3: int
    dr6: int
    dr7: int

    RegisterArea: bytes
    x87fpu: X87FPU
    MxCsr: int
    XmmRegisters: List[XMMREGISTER]
    YmmRegisters: List[YMMREGISTER]


# ======================
# Trace Reg Dump
# ======================

class TraceRegDump32:
    regcontext: REGISTERCONTEXT32
    flags: FLAGS
    x87FPURegisters: List[X87FPUREGISTER]
    mmx: List[int]
    MxCsrFields: MXCSRFIELDS
    x87StatusWordFields: X87STATUSWORDFIELDS
    x87ControlWordFields: X87CONTROLWORDFIELDS
    lastError: LASTERROR


class TraceRegDump64:
    regcontext: REGISTERCONTEXT64
    flags: FLAGS
    x87FPURegisters: List[X87FPUREGISTER]
    mmx: List[int]
    MxCsrFields: MXCSRFIELDS
    x87StatusWordFields: X87STATUSWORDFIELDS
    x87ControlWordFields: X87CONTROLWORDFIELDS
    lastError: LASTERROR


# ======================
# Enums
# ======================

class TraceDataArch(Enum):
    X86_32 = ...
    X86_64 = ...


class AccessType(Enum):
    READ = ...
    WRITE = ...


class ThreadWaitReason(Enum):
    _Executive = ...
    _FreePage = ...
    _PageIn = ...
    _PoolAllocation = ...
    _DelayExecution = ...
    _Suspended = ...
    _UserRequest = ...
    _WrExecutive = ...
    _WrFreePage = ...
    _WrPageIn = ...
    _WrPoolAllocation = ...
    _WrDelayExecution = ...
    _WrSuspended = ...
    _WrUserRequest = ...
    _WrEventPair = ...
    _WrQueue = ...
    _WrLpcReceive = ...
    _WrLpcReply = ...
    _WrVirtualMemory = ...
    _WrPageOut = ...
    _WrRendezvous = ...
    _Spare2 = ...
    _Spare3 = ...
    _Spare4 = ...
    _Spare5 = ...
    _WrCalloutStack = ...
    _WrKernel = ...
    _WrResource = ...
    _WrPushLock = ...
    _WrMutex = ...
    _WrQuantumEnd = ...
    _WrDispatchInt = ...
    _WrPreempted = ...
    _WrYieldExecution = ...
    _WrFastMutex = ...
    _WrGuardedMutex = ...
    _WrRundown = ...


class ThreadPriority(Enum):
    _PriorityIdle = ...
    _PriorityAboveNormal = ...
    _PriorityBelowNormal = ...
    _PriorityHighest = ...
    _PriorityLowest = ...
    _PriorityNormal = ...
    _PriorityTimeCritical = ...
    _PriorityUnknown = ...


class SymbolType(Enum):
    Function = ...
    Import = ...
    Export = ...


# ======================
# Instruction / Memory
# ======================

class MemoryAccessRecord:
    type: AccessType
    read_and_write: bool
    overwritten_or_identical: bool
    acc_size: int
    acc_address: int
    old_data: int
    new_data: int


class InstructionRecord:
    ins_address: int
    bytes: bytes

    reg_dump32: TraceRegDump32
    reg_dump64: TraceRegDump64

    mem_accs: List[MemoryAccessRecord]
    reg_changes: Dict[int, Tuple[int, int]]
    thread_id: int
    id: int
    dbg_id: int


# ======================
# Metadata / Trace
# ======================

class TraceJsonMetadata:
    arch: str
    filepath: str
    hashAlgorithm: str
    hash: str
    compression: str
    version: int


class UserInfo:
    meta: MetaBlock


class TraceData:
    def ARCHMASK(self) -> int: ...

    trace_filename: str
    meta: TraceJsonMetadata
    ptr_size: int
    arch: TraceDataArch
    record: List[InstructionRecord]
    user: UserInfo


def parse_x64dbg_trace(filename: str) -> TraceData: ...


# ======================
# MetaBlock
# ======================

class ThreadInfoTime:
    user: int
    kernel: int
    creation: int


class ThreadInfo:
    id: int
    handle: int
    teb: int
    entry: int
    cip: int
    suspendCount: int
    waitReason: ThreadWaitReason
    priority: ThreadPriority
    lastError: int
    time: ThreadInfoTime
    cycles: int
    name: str


class SymbolInfo:
    mod: str
    name: str
    type: SymbolType
    rva: int
    va: int


class MemoryMapInfoAllocation:
    base: int
    protect: int


class MemoryMapInfo:
    addr: int
    size: int
    protect: int
    state: int
    type: int
    allocation: MemoryMapInfoAllocation
    dataValid: bool
    data: bytes


class ModuleSectionInfo:
    name: str
    addr: int
    size: int


class ModuleInfo:
    name: str
    path: str
    base: int
    size: int
    entry: int
    sectionCount: int
    sections: List[ModuleSectionInfo]
    isMainModule: bool


class SupertraceMeta:
    version: int
    createTimeStamp: int


class ProcessInfo:
    id: int
    handle: int
    peb: int


class MetaBlock:
    supertrace: SupertraceMeta
    exeBuf: bytes
    process: ProcessInfo
    threads: List[ThreadInfo]
    symbols: List[SymbolInfo]
    memoryMaps: List[MemoryMapInfo]
    modules: List[ModuleInfo]
