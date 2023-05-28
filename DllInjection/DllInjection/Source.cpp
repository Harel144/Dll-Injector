// Barak Gonen 2019
// Skeleton code - inject DLL to a running process
// 
// 
//ps: this is old af so much things went wrong i had to
//    open the project 3 different times and install windows all over again.

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetProcessIdByName(const wchar_t* processName);

int main()
{
    // Get full path of DLL to inject
    char dllPath[MAX_PATH];
    DWORD pathLen = GetFullPathNameA("MyFirstDLL.dll", MAX_PATH, dllPath, nullptr);

    // Get LoadLibrary function address –
    // the address doesn't change at remote process
    PVOID addrLoadLibrary = (PVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    DWORD pid;
    std::cout << "Waiting for notepad.exe to start..." << std::endl;
    do
    {
        pid = GetProcessIdByName(L"notepad.exe");

    } while (pid == 0);

    std::cout << "Found notepad.exe! Injecting..." << std::endl;

    // Open remote process
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
     
    // Get a pointer to memory location in remote process,
    // big enough to store DLL path
    PVOID memAddr = (PVOID)VirtualAllocEx(proc, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (NULL == memAddr)
    {
        std::cout << GetLastError();
        return 0;
    }

    // Write DLL name to remote process memory
    BOOL check = WriteProcessMemory(proc, memAddr, dllPath, pathLen, NULL);
    if (0 == check)
    {
        std::cout << GetLastError();
        return 0;
    }

    // Open remote thread, while executing LoadLibrary
    // with parameter DLL name, will trigger DLLMain
    HANDLE hRemote = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)addrLoadLibrary, memAddr, 0, NULL);
    if (NULL == hRemote)
    {
        std::cout << GetLastError();
        return 0;
    }

    WaitForSingleObject(hRemote, INFINITE);

    check = CloseHandle(hRemote);
    return 0;
}

/*
This function gets a process name and finiding the process's
pid. If the process isn't exist the function returns 0
input: process name.
output: process pid.
*/
DWORD GetProcessIdByName(const wchar_t* processName)
{
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (wcscmp(pe.szExeFile, processName) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    return pid;
}