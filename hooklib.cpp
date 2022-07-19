#include "hooklib.h"
#include "csgocheat/Syscalls.h"

HookLib g_HookLib{ };

namespace hkFunctions {
    SIZE_T __stdcall hkVirtualQuery(LPCVOID lpAddr, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T lpSize) {
        SIZE_T sReturnVal = g_HookLib.oVirtualQuery(lpAddr, lpBuffer, lpSize);
        bool bTamper = false;

        // we finished hooking, or havent started yet
        if (!g_HookLib._GetACHookStatus())
            return sReturnVal;

        // tamper with return vals only if function has been hooked by us
        for (int i = 0; i < g_HookLib._GetCounter(); i++) {
            if (lpAddr == g_HookLib._GetBasePointer(i))
                bTamper = true;
        }
        for (int i = 0; i < g_HookLib._GetCodeCaveSize(); i++) {
            if (lpAddr == (void*)g_HookLib._GetCodeCaveAddr(i))
                bTamper = true;
        }

        if (lpBuffer && bTamper) {
            lpBuffer->AllocationProtect = PAGE_READWRITE;
            lpBuffer->Protect = PAGE_READWRITE;
        }

        return sReturnVal;
    }
}
// The API to interact with the lib
#pragma region HookLibAPI
BOOL HookLib::EnableAll() {
    for (auto entry : hookEntries) {
        switch (entry.iMode) {
        case MODE_NONE:
            // someone pushed back an empty struct :(
            return false;
            break;
        case MODE_VEH:
            // we have a VEH Entry, init the handler once
            if (!pVEHHandle)
                pVEHHandle = RtlAddVectoredHandler(true, VEHHandler);
            *entry.oFunc = AddHook(entry.pHkFunc, entry.pVTable, entry.iIndex, entry.sName);
            break;
        case MODE_TRUSTEDMODULE:
            *entry.oFunc = AddHook(entry.cModuleName, entry.pVirtualTable, entry.pTargetFunction, entry.iInd);
            break;
        case MODE_EMLIN:
            *entry.oFunc = AddHook(entry.psrc, entry.pdst, entry.ilen);
            break;
        default:
            return false;
        }
    }
    return true;
}
#pragma endregion

#pragma region VEHHandler
LONG __stdcall VEHHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    DWORD dwAddr = NOT_FOUND;
    PVOID pExceptAddr = pExceptionInfo->ExceptionRecord->ExceptionAddress;

    // Find the address that triggered the error
    for (int i = 0; i < g_HookLib._GetCounter(); i++) {
        if (g_HookLib._GetPointerDestructor(i) == pExceptAddr) {
            dwAddr = (DWORD)g_HookLib._GetHkFnc(i);
            break;
        }
    }

    // check if we found an exception at a hooked address, if we do change eip and continue execution
    if (dwAddr != -1 && pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        pExceptionInfo->ContextRecord->Eip = dwAddr;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // if we arrive here, there was no excpetion at a hook, so we let the normal handler deal with it
    return EXCEPTION_CONTINUE_SEARCH;
}
#pragma endregion
#pragma region ACStuff
BOOL HookLib::OverrideACHooks() {
    // hook virtualquery func and return false info
    memcpy(wOrigBytes, VirtualQuery, 5);
    oVirtualQuery = (tVirtualQuery)AddHook((char*)VirtualQuery, (char*)hkFunctions::hkVirtualQuery, 5);

    bACHooksOverwritten = true;

    return true;
}

BOOL HookLib::RestoreACHooks() {
    // no hooks overwritten, so we can't patch anything
    if (!bACHooksOverwritten)
        return false;

    DWORD oProc;
    PVOID pVirtualQuery = VirtualQuery;
    SIZE_T iSize = 5;
    NtProtectVirtualMemory(hProc, &pVirtualQuery, &iSize, PAGE_EXECUTE_READWRITE, &oProc);
    memcpy(VirtualQuery, wOrigBytes, 5);
    NtProtectVirtualMemory(hProc, &pVirtualQuery, &iSize, oProc, &oProc);

    bACHooksOverwritten = false;

    return true;
}

#pragma endregion
#pragma region VEHHook
// This function will break all the pointers to trigger an excpetion and call the VEHHandler
BOOL HookLib::DestroyPointers(int index) {
    // no index, destroy all pointer stored
    if (index == NOT_FOUND) {
        for (int i = 0; i < iCounter; i++) {
            DWORD oProc;
            LPVOID ppBaseFnc = (LPVOID)pBaseFnc.at(i);
            SIZE_T pSize = sizeof(pBaseFnc.at(i));
            NtProtectVirtualMemory(hProc, &ppBaseFnc, &pSize, PAGE_EXECUTE_READWRITE, &oProc);
            *((uintptr_t*)pBaseFnc.at(i)) = (uintptr_t)pPointerDestructor.at(i); // break pointer
            NtProtectVirtualMemory(hProc, &ppBaseFnc, &pSize, oProc, &oProc);
        }
    }

    // destroy pointer of index
    else {
        DWORD oProc;
        LPVOID ppBaseFnc = (LPVOID)pBaseFnc.at(index);
        SIZE_T pSize = sizeof(pBaseFnc.at(index));
        NtProtectVirtualMemory(hProc, &ppBaseFnc, &pSize, PAGE_EXECUTE_READWRITE, &oProc);
        *((uintptr_t*)pBaseFnc.at(index)) = (uintptr_t)pPointerDestructor.at(index); // break pointer
        NtProtectVirtualMemory(hProc, &ppBaseFnc, &pSize, oProc, &oProc);
    }

    // if we arrive here all hooks have successfully been placed
    return true;
}

LPVOID HookLib::AddHook(PVOID pHkFunc, PVOID pVTable, INT16 iIndex, const char* sName) {
    // push back new hook values
    pName.push_back(sName);
    pVTableAddr = pVTable;
    nIndex.push_back(iIndex);
    pHkFnc.push_back(pHkFunc);
    pBaseFnc.push_back(*((uintptr_t*)pVTableAddr) + (sizeof(uintptr_t) * nIndex.at(iCounter)));
    pOrigFncAddr.push_back(*((uintptr_t*)(pBaseFnc.at(iCounter))));
    (nIndex.at(iCounter) > 0) ? pPointerDestructor.push_back(*((uintptr_t*)pVTableAddr) - 1) : pPointerDestructor.push_back(*((uintptr_t*)pVTableAddr) + 1);

    // get original function address
    uintptr_t pRetVal = pOrigFncAddr.at(iCounter);

    // activate the hook
    DestroyPointers(iCounter);
    // increment hook counter
    iCounter++;
    return (LPVOID)pRetVal;
}
#pragma endregion

/*REPLACE WITH EMLIN HOOK*/
#pragma region TrampHook
VOID HookLib::Patch(char* dst, char* src, SIZE_T len) {
    //NtProtectVirtualMemory(hProc, &ppCodeCave, (PSIZE_T)&size, PAGE_EXECUTE_READWRITE, &oProc);
    DWORD oProc;
    NtProtectVirtualMemory(hProc, (LPVOID*)&dst, &len, PAGE_EXECUTE_READWRITE, &oProc); //VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &oProc);
    memcpy(dst, src, len);
    //NtProtectVirtualMemory(hProc, (LPVOID*)&dst, &len, oProc, &oProc);                  //VirtualProtect(dst, len, oProc, &oProc);
}

BOOL HookLib::Hook(char* src, char* dst, SIZE_T len) {
    if (len < 5) return false;

    DWORD oProc;
    LPVOID _src = src;
    //NtProtectVirtualMemory(hProc, &_src, &len, PAGE_EXECUTE_READWRITE, &oProc); 
    VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &oProc);
    memset(src, 0x90, len);
    uintptr_t relAddy = (uintptr_t)(dst - src - 5);
    *src = (char)0xE9;
    *(uintptr_t*)(src + 1) = (uintptr_t)relAddy;
    //NtProtectVirtualMemory(hProc, (LPVOID*)&dst, &len, oProc, &oProc);

    return true;
}

void* HookLib::AddHook(char* src, char* dst, short len) {
    if (len < 5) return 0;

    SIZE_T allocateLen = len + 5;
    char* gateway = 0;

    NtAllocateVirtualMemory(hProc, (PVOID*)&gateway, 0, &allocateLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!gateway)
        return nullptr;

    memcpy(gateway, src, len);
    uintptr_t jumpAddy = (uintptr_t)(src - gateway - 5);
    *(gateway + len) = (char)0xE9;
    *(uintptr_t*)(gateway + len + 1) = jumpAddy;
    if (Hook(src, dst, len)) {
        return gateway;
    }
    return nullptr;
}
#pragma endregion
#pragma region TrustedModule
uintptr_t HookLib::FindCodeCave(const char* cModuleName, size_t iSize) {
    MODULEINFO moduleInfo = GetModuleInfo(cModuleName);
    uintptr_t pFinalAddr = 0x00;
    BYTE* moduleContent = (BYTE*)malloc(moduleInfo.SizeOfImage);
    if (!moduleContent)
        return 0x0;

    memcpy(moduleContent, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage - 1);

    for (int i = 0; i < moduleInfo.SizeOfImage; i++)
    {
        bool found = true;
        for (int j = 0; j < iSize + 1; j++)
        {
            if (moduleContent[i + j] != 0x00)
                found = false;
        }

        if (found == true)
        {
            uintptr_t pCodeCave = ((uintptr_t)moduleInfo.lpBaseOfDll + i);
            CodeCave cave{ pCodeCave, iSize };
            cCodeCaves.push_back(cave);
            return ((uintptr_t)moduleInfo.lpBaseOfDll + i);
        }
    }

    return 0x0;
}

void* HookLib::AddHook(const char* cModuleName, void* pVirtualTable, void* pTargetFunction, size_t iIndex) {
    // get addr of the VTableEntry
    uintptr_t pVTable = *((uintptr_t*)pVirtualTable);
    uintptr_t pEntry = pVTable + (sizeof(uintptr_t) * iIndex);
    uintptr_t pOrig = *((uintptr_t*)pEntry);

    uintptr_t pCodeCave = FindCodeCave(cModuleName, SIZE);

    uintptr_t pRelAddr = (uintptr_t)pTargetFunction - pCodeCave - SIZE;

    // place our shellcode in the code cave
    DWORD oProc;

    int sizeOfEntry = sizeof(pEntry);
    int size = SIZE;

    LPVOID ppCodeCave = (LPVOID)pCodeCave;
    LPVOID ppEntry = (LPVOID)pEntry;

    NtProtectVirtualMemory(hProc, &ppCodeCave, (PSIZE_T)&size, PAGE_EXECUTE_READWRITE, &oProc);
    *(uintptr_t*)(pCodeCave) = (char)0x8B;
    *(uintptr_t*)(pCodeCave + 0x01) = (char)0xED;
    *(uintptr_t*)(pCodeCave + 0x02) = (char)0xE9;
    *(uintptr_t*)(pCodeCave + 0x03) = (uintptr_t)pRelAddr;
    // dont restore to keep execute priviliges


    // swap pointer to our code cave
    NtProtectVirtualMemory(hProc, &ppEntry, (PSIZE_T)&sizeOfEntry, PAGE_EXECUTE_WRITECOPY, &oProc);
    *(uintptr_t*)pEntry = (uintptr_t)pCodeCave;
    // dont restore to keep execute priviliges

    return (char*)pOrig;
}
#pragma endregion

/*TODO:*/
uintptr_t HookLib::EmlinHook(uintptr_t target, uintptr_t trampoline, size_t iSize, bool* enabled)
{
    DWORD oProt;

    // copy stolen bytes
    BYTE* bStolenBytes = (BYTE*)malloc(iSize);
    memcpy((void*)target, bStolenBytes, iSize);

    // clear memory
    ZeroMemory((void*)target, iSize);

    uintptr_t gateway = (uintptr_t)VirtualAlloc(0, 24, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    VirtualProtect((LPVOID)target, 12, PAGE_EXECUTE_READWRITE, &oProt);
    uintptr_t _gateway = gateway - target - 5;

    uintptr_t targetptr = target + (*(uintptr_t*)(target + 0x1) + 5);
    uintptr_t trampolineptr = trampoline + (*(uintptr_t*)(trampoline + 0x1) + 5);

    std::cout << targetptr << std::endl;
    std::cout << trampolineptr << std::endl;

    //jump to gateway
    *(char*)(target) = (char)0xE9;
    *(uintptr_t*)((uintptr_t)target + 1) = (uintptr_t)_gateway;

    //gateway
    *(char*)((int)gateway) = (char)0x80;
    *(char*)((int)gateway + 1) = (char)0x3D;
    *(uintptr_t*)((int)gateway + 2) = (uintptr_t)enabled;
    *(char*)((int)gateway + 6) = (char)0x01;
    *(char*)((int)gateway + 7) = (char)0x74;
    *(char*)((int)gateway + 8) = (char)5;
    *(char*)((int)gateway + 9) = (char)0xE9;
    *(uintptr_t*)((int)gateway + 10) = (uintptr_t)targetptr - gateway - 14;
    *(char*)((int)gateway + 14) = (char)0xE9;
    *(uintptr_t*)((int)gateway + 15) = (uintptr_t)trampolineptr - gateway - 19;

    return targetptr;
}