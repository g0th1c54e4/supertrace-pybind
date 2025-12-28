#ifndef LITEX64DBGDEF_H
#define LITEX64DBGDEF_H

#include <Windows.h>

typedef struct DECLSPEC_ALIGN(16) _XMMREGISTER {
    ULONGLONG Low;
    LONGLONG High;
} XMMREGISTER;

typedef struct {
    XMMREGISTER Low; //XMM/SSE part
    XMMREGISTER High; //AVX part
} YMMREGISTER;

typedef struct {
    WORD   ControlWord;
    WORD   StatusWord;
    WORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    DWORD   Cr0NpxState;
} X87FPU;

typedef struct {
    unsigned long cax;
    unsigned long ccx;
    unsigned long cdx;
    unsigned long cbx;
    unsigned long csp;
    unsigned long cbp;
    unsigned long csi;
    unsigned long cdi;
    unsigned long cip;
    unsigned long eflags;
    unsigned short gs;
    unsigned short fs;
    unsigned short es;
    unsigned short ds;
    unsigned short cs;
    unsigned short ss;
    unsigned long dr0;
    unsigned long dr1;
    unsigned long dr2;
    unsigned long dr3;
    unsigned long dr6;
    unsigned long dr7;
    BYTE RegisterArea[80];
    X87FPU x87fpu;
    DWORD MxCsr;
    XMMREGISTER XmmRegisters[8];
    YMMREGISTER YmmRegisters[8];
} REGISTERCONTEXT32;

typedef struct {
    unsigned __int64 cax;
    unsigned __int64 ccx;
    unsigned __int64 cdx;
    unsigned __int64 cbx;
    unsigned __int64 csp;
    unsigned __int64 cbp;
    unsigned __int64 csi;
    unsigned __int64 cdi;
    unsigned __int64 r8;
    unsigned __int64 r9;
    unsigned __int64 r10;
    unsigned __int64 r11;
    unsigned __int64 r12;
    unsigned __int64 r13;
    unsigned __int64 r14;
    unsigned __int64 r15;
    unsigned __int64 cip;
    unsigned __int64 eflags;
    unsigned short gs;
    unsigned short fs;
    unsigned short es;
    unsigned short ds;
    unsigned short cs;
    unsigned short ss;
    unsigned __int64 dr0;
    unsigned __int64 dr1;
    unsigned __int64 dr2;
    unsigned __int64 dr3;
    unsigned __int64 dr6;
    unsigned __int64 dr7;
    BYTE RegisterArea[80];
    X87FPU x87fpu;
    DWORD MxCsr;
    XMMREGISTER XmmRegisters[16];
    YMMREGISTER YmmRegisters[16];
} REGISTERCONTEXT64;

typedef struct {
    bool c;
    bool p;
    bool a;
    bool z;
    bool s;
    bool t;
    bool i;
    bool d;
    bool o;
} FLAGS;

typedef struct {
    BYTE    data[10];
    int     st_value;
    int     tag;
} X87FPUREGISTER;

typedef struct {
    bool FZ;
    bool PM;
    bool UM;
    bool OM;
    bool ZM;
    bool IM;
    bool DM;
    bool DAZ;
    bool PE;
    bool UE;
    bool OE;
    bool ZE;
    bool DE;
    bool IE;

    unsigned short RC;
} MXCSRFIELDS;

typedef struct {
    bool B;
    bool C3;
    bool C2;
    bool C1;
    bool C0;
    bool ES;
    bool SF;
    bool P;
    bool U;
    bool O;
    bool Z;
    bool D;
    bool I;

    unsigned short TOP;

} X87STATUSWORDFIELDS;

typedef struct {
    bool IC;
    bool IEM;
    bool PM;
    bool UM;
    bool OM;
    bool ZM;
    bool DM;
    bool IM;

    unsigned short RC;
    unsigned short PC;

} X87CONTROLWORDFIELDS;

typedef struct {
    DWORD code;
    char name[128];
} LASTERROR;

#endif