#pragma once

#include <Windows.h>
#include <vector>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>

#pragma region HookEntries
enum MODE {
    MODE_NONE,
    MODE_EMLIN,
    MODE_VEH,
    MODE_TRUSTEDMODULE
};

struct HookEntry {
    MODE iMode = MODE_NONE;
    PVOID* oFunc;

    // VEH
    PVOID pHkFunc; 
    PVOID pVTable;
    INT16 iIndex;
    const char* sName = "";
    HookEntry(PVOID hkfunc, PVOID vtable, INT16 index, const char* name, PVOID* ofunc) {
        pHkFunc = hkfunc; pVTable = vtable; iIndex = index; sName = name; iMode = MODE_VEH; oFunc = ofunc;
    }

    // TRUSTEDMODULE
    const char* cModuleName;
    void* pVirtualTable;
    void* pTargetFunction;
    size_t iInd;
    HookEntry(const char* modulename, void* vtable, void* targetfunc, size_t index, PVOID* ofunc) {
        cModuleName = modulename; pVirtualTable = vtable; pTargetFunction = targetfunc; iInd = index; iMode = MODE_TRUSTEDMODULE; oFunc = ofunc;
    }

    // EMLIN
    char* psrc;
    char* pdst;
    short ilen;
    HookEntry(char* src, char* dst, short len, PVOID* ofunc) {
        psrc = src; pdst = dst; ilen = len; iMode = MODE_EMLIN; oFunc = ofunc;
    }
};

#pragma endregion

#define NOT_FOUND -1
#define SIZE 7

// init our handler outside of class
LONG WINAPI VEHHandler(EXCEPTION_POINTERS* pExceptionInfo);

struct HookStatus {
    HookStatus() { pBaseFnc = NULL; pHkAddr = nullptr; iIndex = NULL; }
    uintptr_t pBaseFnc;
    PVOID pHkAddr;
    INT   iIndex;
    MODE iMode;
};

struct CodeCave {
    uintptr_t pAddr;
    size_t iSize;
};

class HookLib {
    // vars
private:
    std::vector<HookEntry> hookEntries;

    // VEH
    std::vector<const char*> pName;
    std::vector<PVOID>       pHkFnc;
    std::vector<uintptr_t>   pBaseFnc;
    std::vector<uintptr_t>   pPointerDestructor;
    std::vector<uintptr_t>   pOrigFncAddr;
    std::vector<INT16>       nIndex;
    std::vector<CodeCave>    cCodeCaves;
    PVOID                    pVEHHandle;
    PVOID                    pVTableAddr;
    INT                      iCounter;
    BOOL                     bVehInit;

    // AC 
    BOOL                     bACHooksOverwritten;
    BYTE                     wOrigBytes[5];

    // prototypes
    using tVirtualQuery = SIZE_T(__stdcall*)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
    using tGetProcAddress = FARPROC(__stdcall*)(HMODULE, LPCSTR);
    using tRtlAddVectoredHandler = PVOID(NTAPI*)(IN ULONG FirstHandler, IN PVECTORED_EXCEPTION_HANDLER VectoredHandler);

    HANDLE hProc;
    tGetProcAddress oGetProcAddress;
    tRtlAddVectoredHandler RtlAddVectoredHandler;

    // global vars
public:
    tVirtualQuery oVirtualQuery;

public:
    // needs to stay exposed
#pragma region ExposedFunctions
    INT _GetCounter() { return iCounter; }     // get icounter for the handler
    PVOID _GetHkFnc(int index) { return pHkFnc.at(index); }    // get hooked function addr at index i for the handler
    PVOID _GetPointerDestructor(int index) { return reinterpret_cast<PVOID>(pPointerDestructor.at(index)); } // get destructed pointer at index i for the handler
    PVOID _GetBasePointer(int index) { return reinterpret_cast<PVOID>(pOrigFncAddr.at(index)); }// get base fnc pointer at index i for the handler
    BOOL _GetACHookStatus() { return bACHooksOverwritten; }
    int _GetCodeCaveSize() {
        return cCodeCaves.size();
    }
    uintptr_t _GetCodeCaveAddr(int index) {
        return cCodeCaves.at(index).pAddr;
    }
#pragma endregion

    HookLib() { 
        iCounter = 0; 
        bVehInit = false; 
        pVEHHandle = NULL; 
        pVTableAddr = NULL; 
        RtlAddVectoredHandler = reinterpret_cast<tRtlAddVectoredHandler>(GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlAddVectoredExceptionHandler"));
        hProc = GetCurrentProcess();
    } // constructor

    // If hooking where an ac is present, call this BEFORE hooking everything
    BOOL OverrideACHooks();
    // If hooking where an ac is present, call this AFTER hooking everything 
    BOOL RestoreACHooks();

    // Convenience Wrapper functions
    void AddHook(HookEntry entry) {
        // maybe do some logging (?)
        hookEntries.push_back(entry);
    }

    // Enable all hooks
    BOOL EnableAll();

    // Disable all hooks
    BOOL DisableAll() { return true; };

private:
    BOOL DestroyPointers(int index = NOT_FOUND);

    // VEH Hook Call
    void* AddHook(PVOID pHkFunc, PVOID pVTable, INT16 iIndex, const char* sName = "");
    // For TrustedModule
    void* AddHook(const char* cModuleName, void* pVTable, void* pTargetFunction, size_t iIndex);
    // For TrampHook
    void* AddHook(char* src, char* dst, short len);

#pragma region TrampHook
    // hooks function and returns pointer to the original function, works on all functions
    VOID Patch(char* dst, char* src, SIZE_T len);
    BOOL Hook(char* src, char* dst, SIZE_T len);
#pragma endregion Hook using inline patching
#pragma region TrustedModule
    MODULEINFO GetModuleInfo(const char* szModule) {
        MODULEINFO modInfo = { 0 };
        HMODULE hModule = GetModuleHandle(szModule);
        if (hModule == 0)
            return modInfo;

        GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
        return modInfo;
    }

    uintptr_t FindCodeCave(const char* cModuleName, size_t iSize);
#pragma endregion
    /*NOT FULLY IMPLEMENTED YET FOR x86*/
#pragma region EmlinHook
    uintptr_t EmlinHook(uintptr_t target, uintptr_t trampoline, size_t iSize, bool* enabled);
#pragma endregion
};

extern HookLib g_HookLib;