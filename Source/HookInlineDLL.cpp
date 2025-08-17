#include <windows.h>
#include "pch.h"
#include <winternl.h>
#include <tchar.h>
#include <shlwapi.h>


// === Hook CreateFileW ===
typedef HANDLE(WINAPI* tdOrigCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
    );
tdOrigCreateFileW createFileWTrampoline = nullptr;

HANDLE WINAPI HookCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    static bool shownMsg = false;

    if (lpFileName) {
        LPCWSTR fileNameOnly = wcsrchr(lpFileName, L'\\');
        fileNameOnly = fileNameOnly ? fileNameOnly + 1 : lpFileName;
        // so sanh ten file vs 1.txt
        if (_wcsicmp(fileNameOnly, L"1.txt") == 0) {
            if ((dwDesiredAccess & GENERIC_READ) || (dwDesiredAccess & GENERIC_WRITE)) {
                if (!shownMsg) {
                    MessageBoxW(NULL, L"Opening 1.txt", L"Alert", MB_OK);
                    shownMsg = true; 
                }
            }
        }
    }

    HANDLE hFile = createFileWTrampoline(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );

    // sau khi thuc hien hook xong thi tra ve handle createFileWTrampoline de thuc thi ham ban dau
    return hFile;
}


// === Hook Patch Function ===
bool HookFunction64(BYTE* targetFunc, void* hookFunc, void** originalFunc) {
    DWORD oldProtect;
    //ghi de 12 byte
    BYTE originalBytes[12];
    // copy 12 byte dau tien của targetfunc
    memcpy(originalBytes, targetFunc, 12);

    // cap phat bo nho cho trampoline
    BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return false;

    memcpy(trampoline, originalBytes, 12);
    // tao jmp de jmp lai sau doan da bi ghi de
    BYTE jmpBack[12] = {
        0x48, 0xB8,             // mov rax, 
        0,0,0,0,0,0,0,0,        // 8 byte dia chi
        0xFF, 0xE0              // jmp rax
    };
    *(UINT64*)&jmpBack[2] =
        (UINT64)(targetFunc + 12);
    // ghi vao trampoline + 12 sau doan da copy 12 byte day cua targetfunc
    memcpy(trampoline + 12, jmpBack, 12);

    *originalFunc = (void*)trampoline;
    // jmp den dia chi cua ham hook
    BYTE patch[12] = {
        0x48, 0xB8,             // mov rax,
        0,0,0,0,0,0,0,0,        // 8 byte dia chi
        0xFF, 0xE0              // jmp rax
    };

    *(UINT64*)&patch[2] = (UINT64)hookFunc;
    // thay quyen de ghi de vao targetfunc
    VirtualProtect(targetFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect);
    // copy 12 byte patch vao targetfunc
    memcpy(targetFunc, patch, 12);
    // tra lai quyen ban dau
    VirtualProtect(targetFunc, 12, oldProtect, &oldProtect);

    return true;
}

// === Hook Init Thread ===
DWORD WINAPI InitHookThread(LPVOID lpParam) {
    // Hook CreateFileA/W from kernelbase.dll
    HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");
    if (hKernelBase) {

        BYTE* addrW = (BYTE*)GetProcAddress(hKernelBase, "CreateFileW");
        // goi hook ham CreateFile
        if (addrW && HookFunction64(addrW, (void*)&HookCreateFileW, (void**)&createFileWTrampoline)) {
            MessageBoxA(NULL, "Hook CreateFileW installed!", "Success", MB_OK);
        }
    }


    return 0;
}

// === DLL Entry ===
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, InitHookThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
