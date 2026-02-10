/*
 * filemon_test.c — Integration test for filemon_hook + filemon_controller
 *
 * Starts the controller, self-injects the hook DLL, performs a file read,
 * and verifies that the file path appears in the controller output.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static void fail(const char *msg)
{
    fprintf(stderr, "[FAIL] %s (error %lu)\n", msg, GetLastError());
    exit(1);
}

int main(void)
{
    wchar_t exeDir[MAX_PATH];
    wchar_t controllerPath[MAX_PATH];
    wchar_t dllPath[MAX_PATH];
    wchar_t pipeName[256];
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    HMODULE hDll;
    wchar_t tempDir[MAX_PATH];
    wchar_t tempFile[MAX_PATH];
    HANDLE hFile;
    char dummy[1];
    DWORD bytesRead;
    wchar_t *fileName;
    char output[65536];
    DWORD totalRead;
    char fileNameUtf8[MAX_PATH * 3];
    int result;

    printf("[TEST] Starting filemon integration test\n");

    /* Resolve paths relative to this executable */
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    {
        wchar_t *slash = wcsrchr(exeDir, L'\\');
        if (slash) slash[1] = L'\0';
    }
    wcscpy_s(controllerPath, MAX_PATH, exeDir);
    wcscat_s(controllerPath, MAX_PATH, L"filemon_controller.exe");
    wcscpy_s(dllPath, MAX_PATH, exeDir);
    wcscat_s(dllPath, MAX_PATH, L"filemon_hook.dll");

    /* Generate unique pipe name and publish via environment */
    swprintf_s(pipeName, 256, L"\\\\.\\pipe\\filemon_%lu", GetCurrentProcessId());
    SetEnvironmentVariableW(L"FILEMON_PIPE", pipeName);

    /* Create anonymous pipe for capturing controller stdout */
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 64 * 1024))
        fail("CreatePipe");
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    /* Start controller with redirected stdout+stderr */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;

    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(controllerPath, NULL, NULL, NULL, TRUE,
                        0, NULL, NULL, &si, &pi))
        fail("CreateProcess filemon_controller.exe");

    /* Close write end in parent so pipe breaks when child exits */
    CloseHandle(hWritePipe);

    printf("[TEST] Controller started (PID %lu)\n", pi.dwProcessId);

    /* Wait for named pipe to appear */
    {
        DWORD start = GetTickCount();
        for (;;) {
            if (WaitNamedPipeW(pipeName, 500))
                break;
            if (GetTickCount() - start > 10000)
                fail("Timed out waiting for named pipe");
            Sleep(50);
        }
    }
    printf("[TEST] Pipe ready\n");

    /* Load hook DLL (self-inject into this process) */
    hDll = LoadLibraryW(dllPath);
    if (!hDll)
        fail("LoadLibrary filemon_hook.dll");
    printf("[TEST] Hook DLL loaded\n");

    /* Create temp file, then open it for reading (triggers the hook) */
    GetTempPathW(MAX_PATH, tempDir);
    if (!GetTempFileNameW(tempDir, L"fmt", 0, tempFile))
        fail("GetTempFileNameW");

    hFile = CreateFileW(tempFile, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        fail("CreateFileW temp file for reading");

    bytesRead = 0;
    ReadFile(hFile, dummy, sizeof(dummy), &bytesRead, NULL);
    CloseHandle(hFile);

    fileName = wcsrchr(tempFile, L'\\');
    fileName = fileName ? fileName + 1 : tempFile;

    printf("[TEST] Created and read temp file: %ls\n", tempFile);

    /* Wait for reporter thread to drain (50ms poll + pipe latency) */
    Sleep(300);

    /* Unload DLL — DLL_PROCESS_DETACH flushes remaining paths and unhooks */
    FreeLibrary(hDll);

    /* Give controller a moment to flush its stdout, then terminate */
    Sleep(100);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);

    printf("[TEST] DLL unloaded, controller stopped\n");

    /* Read captured stdout from the anonymous pipe */
    totalRead = 0;
    while (totalRead < sizeof(output) - 1) {
        DWORD n = 0;
        BOOL ok = ReadFile(hReadPipe, output + totalRead,
                           (DWORD)(sizeof(output) - 1 - totalRead), &n, NULL);
        if (!ok || n == 0) break;
        totalRead += n;
    }
    output[totalRead] = '\0';
    CloseHandle(hReadPipe);

    printf("[TEST] Controller captured %lu bytes\n", totalRead);

    /* Convert temp filename to UTF-8 and search in output */
    WideCharToMultiByte(CP_UTF8, 0, fileName, -1,
                        fileNameUtf8, sizeof(fileNameUtf8), NULL, NULL);

    if (strstr(output, fileNameUtf8)) {
        printf("[PASS] Found temp file path in output\n");
        result = 0;
    } else {
        printf("[FAIL] Temp file path not found in output\n");
        printf("[DEBUG] Looking for: %s\n", fileNameUtf8);
        printf("[DEBUG] Output:\n%s\n", output);
        result = 1;
    }

    /* Clean up */
    DeleteFileW(tempFile);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result;
}
