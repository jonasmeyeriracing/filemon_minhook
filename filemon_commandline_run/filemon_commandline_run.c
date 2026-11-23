/*
 * filemon_commandline_run.c
 *
 * Runs a target process with filemon_hook.dll injected.
 * The hook writes intercepted file paths directly to an output file
 * via the FILEMON_FILE environment variable.
 *
 * Usage: filemon_commandline_run OUTPUT_FILE COMMAND [ARGS...]
 *        filemon_commandline_run --inject PID DLL
 *
 * Built as filemon_commandline_run.exe (x64) and filemon_commandline_run32.exe (x86),
 * next to filemon_hook.dll and filemon_hook32.dll. A process can only be injected
 * by a launcher of its own bitness (LoadLibraryW's address must be valid in it), so
 * for the other bitness this runs the other launcher with --inject. The hook DLL
 * does the same for child processes.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>

static void fail(const char *msg)
{
    fprintf(stderr, "error: %s (error %lu)\n", msg, GetLastError());
    exit(1);
}

/* Skip one whitespace-delimited argument in a raw command line (handles quotes) */
static const wchar_t *SkipArg(const wchar_t *p)
{
    BOOL inQuote = FALSE;
    while (*p == L' ' || *p == L'\t') p++;
    while (*p) {
        if (*p == L'"')
            inQuote = !inQuote;
        else if ((*p == L' ' || *p == L'\t') && !inQuote)
            break;
        p++;
    }
    while (*p == L' ' || *p == L'\t') p++;
    return p;
}

/* Inject a DLL into a process via CreateRemoteThread + LoadLibraryW */
static BOOL InjectDll(HANDLE hProcess, const wchar_t *dllPath)
{
    SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteMem;
    HMODULE hKernel32;
    FARPROC pLoadLibraryW;
    HANDLE hThread;
    DWORD waitResult, threadExit;

    remoteMem = VirtualAllocEx(hProcess, NULL, pathSize,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return FALSE;

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

    hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW, remoteMem, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    waitResult = WaitForSingleObject(hThread, 10000);
    threadExit = 0;
    GetExitCodeThread(hThread, &threadExit);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);

    /* threadExit is the low 32 bits of the LoadLibraryW return value;
       zero means LoadLibraryW failed (DLL not loaded) */
    return (waitResult == WAIT_OBJECT_0) && (threadExit != 0);
}

/* Inject the hook DLL of the target's bitness, directly or through the other launcher */
static BOOL InjectHook(HANDLE hProcess, DWORD pid, const wchar_t *exeDir)
{
    /* on 64-bit Windows, IsWow64Process is TRUE exactly for 32-bit processes */
    BOOL targetIs32 = FALSE;
#ifdef _WIN64
    const BOOL selfIs32 = FALSE;
#else
    const BOOL selfIs32 = TRUE;
#endif
    wchar_t dll[MAX_PATH], cmd[3 * MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD exitCode = 1;

    if (!IsWow64Process(hProcess, &targetIs32))
        return FALSE;
    swprintf_s(dll, MAX_PATH, L"%s%s", exeDir, targetIs32 ? L"filemon_hook32.dll" : L"filemon_hook.dll");
    if (GetFileAttributesW(dll) == INVALID_FILE_ATTRIBUTES)
        return FALSE;
    if (targetIs32 == selfIs32)
        return InjectDll(hProcess, dll);

    swprintf_s(cmd, 3 * MAX_PATH, L"\"%s%s\" --inject %lu \"%s\"", exeDir,
               targetIs32 ? L"filemon_commandline_run32.exe" : L"filemon_commandline_run.exe", pid, dll);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return FALSE;
    CloseHandle(pi.hThread);
    if (WaitForSingleObject(pi.hProcess, 15000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(pi.hProcess, &exitCode))
        exitCode = 1;
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

/* --inject PID DLL: inject DLL into a (suspended) process of this launcher's bitness */
static int InjectMode(int nArgs, LPWSTR *args)
{
    DWORD pid;
    HANDLE hProcess;
    BOOL ok;

    if (nArgs < 4) {
        fprintf(stderr, "Usage: filemon_commandline_run --inject PID DLL\n");
        return 2;
    }
    pid = wcstoul(args[2], NULL, 10);
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                           PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "error: cannot open process %lu (error %lu)\n", pid, GetLastError());
        return 1;
    }
    ok = InjectDll(hProcess, args[3]);
    CloseHandle(hProcess);
    return ok ? 0 : 1;
}

int main(void)
{
    int nArgs;
    LPWSTR *args;
    const wchar_t *targetCmd;
    wchar_t *cmdBuf;
    SIZE_T cmdLen;
    wchar_t exeDir[MAX_PATH];
    wchar_t dllPath[MAX_PATH];
    wchar_t outPath[MAX_PATH];
    HANDLE hOutFile;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD exitCode;

    /* Parse command line */
    args = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (args && nArgs >= 2 && wcscmp(args[1], L"--inject") == 0)
        return InjectMode(nArgs, args);
    if (!args || nArgs < 3) {
        fprintf(stderr, "Usage: filemon_commandline_run OUTPUT_FILE COMMAND [ARGS...]\n");
        return 1;
    }

    /* Extract target command from raw command line (preserves original quoting) */
    targetCmd = SkipArg(SkipArg(GetCommandLineW()));
    if (!*targetCmd) {
        fprintf(stderr, "Usage: filemon_commandline_run OUTPUT_FILE COMMAND [ARGS...]\n");
        return 1;
    }

    /* CreateProcessW may modify the command line buffer — make a writable copy */
    cmdLen = wcslen(targetCmd);
    cmdBuf = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, (cmdLen + 1) * sizeof(wchar_t));
    if (!cmdBuf) fail("HeapAlloc");
    memcpy(cmdBuf, targetCmd, (cmdLen + 1) * sizeof(wchar_t));

    /* Resolve hook DLL path (same directory as this exe) */
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    {
        wchar_t *slash = wcsrchr(exeDir, L'\\');
        if (slash) slash[1] = L'\0';
    }
    wcscpy_s(dllPath, MAX_PATH, exeDir);
    wcscat_s(dllPath, MAX_PATH, L"filemon_hook.dll");

    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES)
        fail("filemon_hook.dll not found next to this executable");

    /* Resolve output file to absolute path and publish via environment */
    if (!GetFullPathNameW(args[1], MAX_PATH, outPath, NULL))
        fail("cannot resolve output file path");
    SetEnvironmentVariableW(L"FILEMON_FILE", outPath);

    /* Create/truncate the output file so it starts fresh */
    hOutFile = CreateFileW(outPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE)
        fail("cannot create output file");
    CloseHandle(hOutFile);

    /* Start target process suspended */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, cmdBuf, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "error: cannot start process (error %lu)\n", GetLastError());
        return 1;
    }

    /* Inject the hook DLL of the target's bitness */
    if (!InjectHook(pi.hProcess, pi.dwProcessId, exeDir)) {
        fprintf(stderr, "error: DLL injection failed (error %lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }

    /* Let the target run */
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    /* Wait for target to exit and propagate its exit code */
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);

    /* Clean up */
    CloseHandle(pi.hProcess);
    HeapFree(GetProcessHeap(), 0, cmdBuf);
    LocalFree(args);

    return (int)exitCode;
}
