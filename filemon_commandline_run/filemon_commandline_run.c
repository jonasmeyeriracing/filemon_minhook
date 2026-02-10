/*
 * filemon_commandline_run.c
 *
 * Runs a target process with filemon_hook.dll injected, captures
 * intercepted file paths, and writes them to an output file.
 *
 * Usage: filemon_commandline_run OUTPUT_FILE COMMAND [ARGS...]
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

/* Read exactly 'size' bytes from the pipe */
static BOOL ReadPipeExact(HANDLE hPipe, void *buf, DWORD size)
{
    BYTE *p = (BYTE *)buf;
    DWORD remaining = size;
    while (remaining > 0) {
        DWORD bytesRead = 0;
        if (!ReadFile(hPipe, p, remaining, &bytesRead, NULL) || bytesRead == 0)
            return FALSE;
        p += bytesRead;
        remaining -= bytesRead;
    }
    return TRUE;
}

/* Write a UTF-16 path as a UTF-8 line to the output file */
static void WritePathToFile(HANDLE hFile, const wchar_t *path, size_t charLen)
{
    int utf8Len;
    char *utf8;
    DWORD written;

    if (charLen == 0) return;

    utf8Len = WideCharToMultiByte(CP_UTF8, 0, path, (int)charLen, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) return;

    utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, utf8Len + 2);
    if (!utf8) return;

    WideCharToMultiByte(CP_UTF8, 0, path, (int)charLen, utf8, utf8Len, NULL, NULL);
    utf8[utf8Len] = '\n';
    WriteFile(hFile, utf8, utf8Len + 1, &written, NULL);

    HeapFree(GetProcessHeap(), 0, utf8);
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
    wchar_t pipeName[256];
    HANDLE hPipe;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HANDLE hOutFile;
    DWORD exitCode;

    /* Parse command line */
    args = CommandLineToArgvW(GetCommandLineW(), &nArgs);
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

    /* Generate unique pipe name and publish via environment */
    swprintf_s(pipeName, 256, L"\\\\.\\pipe\\filemon_%lu", GetCurrentProcessId());
    SetEnvironmentVariableW(L"FILEMON_PIPE", pipeName);

    /* Create named pipe (server side) */
    hPipe = CreateNamedPipeW(pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
        fail("CreateNamedPipeW");

    /* Open output file */
    hOutFile = CreateFileW(args[1], GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE)
        fail("cannot create output file");

    /* Start target process suspended */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, cmdBuf, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "error: cannot start process (error %lu)\n", GetLastError());
        CloseHandle(hOutFile);
        CloseHandle(hPipe);
        return 1;
    }

    /* Inject hook DLL into the target process */
    if (!InjectDll(pi.hProcess, dllPath)) {
        fprintf(stderr, "error: DLL injection failed (error %lu)\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hOutFile);
        CloseHandle(hPipe);
        return 1;
    }

    /* Let the target run */
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    /* Wait for the hook's reporter thread to connect */
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        /* Hook never connected — target may have exited immediately */
    } else {
        /* Read length-prefixed UTF-16 paths and write to output file */
        for (;;) {
            uint32_t byteLen = 0;
            wchar_t *pathBuf;
            size_t charLen;

            if (!ReadPipeExact(hPipe, &byteLen, sizeof(byteLen)))
                break;
            if (byteLen == 0)
                continue;
            if (byteLen > 1024 * 1024)
                break;

            pathBuf = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, byteLen + sizeof(wchar_t));
            if (!pathBuf) break;

            if (!ReadPipeExact(hPipe, pathBuf, byteLen)) {
                HeapFree(GetProcessHeap(), 0, pathBuf);
                break;
            }

            charLen = byteLen / sizeof(wchar_t);
            pathBuf[charLen] = L'\0';

            WritePathToFile(hOutFile, pathBuf, charLen);

            HeapFree(GetProcessHeap(), 0, pathBuf);
        }
    }

    /* Wait for target to exit and propagate its exit code */
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);

    /* Clean up */
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    CloseHandle(hOutFile);
    CloseHandle(pi.hProcess);
    HeapFree(GetProcessHeap(), 0, cmdBuf);
    LocalFree(args);

    return (int)exitCode;
}
