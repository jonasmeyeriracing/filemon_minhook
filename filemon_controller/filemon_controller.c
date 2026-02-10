/*
 * filemon_controller.c — Named pipe server for filemon_hook
 *
 * Creates \\.\pipe\filemon, reads length-prefixed UTF-16 file paths,
 * and prints them as UTF-8 to stdout. Reconnects on client disconnect.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static volatile BOOL g_running = TRUE;
static wchar_t g_pipeName[256] = L"\\\\.\\pipe\\filemon";

static BOOL WINAPI CtrlHandler(DWORD ctrlType)
{
    (void)ctrlType;
    g_running = FALSE;
    return TRUE;
}

/* Read exactly 'size' bytes from the pipe. Returns FALSE on disconnect/error. */
static BOOL ReadPipeExact(HANDLE hPipe, void *buf, DWORD size)
{
    BYTE *p = (BYTE *)buf;
    DWORD remaining = size;

    while (remaining > 0) {
        DWORD bytesRead = 0;
        if (!ReadFile(hPipe, p, remaining, &bytesRead, NULL) || bytesRead == 0)
            return FALSE;
        p         += bytesRead;
        remaining -= bytesRead;
    }
    return TRUE;
}

/* Convert UTF-16 to UTF-8 and print to stdout */
static void PrintPathUtf8(const wchar_t *path, size_t charLen)
{
    if (charLen == 0) return;

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, path, (int)charLen, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) return;

    char *utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, utf8Len + 1);
    if (!utf8) return;

    WideCharToMultiByte(CP_UTF8, 0, path, (int)charLen, utf8, utf8Len, NULL, NULL);
    utf8[utf8Len] = '\0';

    printf("%s\n", utf8);
    fflush(stdout);

    HeapFree(GetProcessHeap(), 0, utf8);
}

int main(void)
{
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    /* Check for custom pipe name from environment */
    {
        wchar_t buf[256];
        DWORD n = GetEnvironmentVariableW(L"FILEMON_PIPE", buf, 256);
        if (n > 0 && n < 256)
            memcpy(g_pipeName, buf, (n + 1) * sizeof(wchar_t));
    }

    /* Set console output to UTF-8 */
    SetConsoleOutputCP(CP_UTF8);

    printf("filemon_controller: creating pipe...\n");
    fflush(stdout);

    while (g_running) {
        /* Create the named pipe */
        HANDLE hPipe = CreateNamedPipeW(
            g_pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,          /* max instances */
            4096,       /* out buffer */
            4096,       /* in buffer */
            0,          /* default timeout */
            NULL);      /* security */

        if (hPipe == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "CreateNamedPipe failed: %lu\n", GetLastError());
            return 1;
        }

        printf("filemon_controller: waiting for client...\n");
        fflush(stdout);

        /* Wait for client to connect */
        if (!ConnectNamedPipe(hPipe, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_PIPE_CONNECTED) {
                CloseHandle(hPipe);
                if (!g_running) break;
                continue;
            }
        }

        printf("filemon_controller: client connected\n");
        fflush(stdout);

        /* Read loop: length-prefixed UTF-16 messages */
        while (g_running) {
            uint32_t byteLen = 0;
            if (!ReadPipeExact(hPipe, &byteLen, sizeof(byteLen)))
                break;

            if (byteLen == 0)
                continue;

            /* Sanity check — reject absurdly large messages */
            if (byteLen > 1024 * 1024) {
                fprintf(stderr, "filemon_controller: message too large (%u bytes), skipping\n", byteLen);
                break;
            }

            wchar_t *pathBuf = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, byteLen + sizeof(wchar_t));
            if (!pathBuf) break;

            if (!ReadPipeExact(hPipe, pathBuf, byteLen)) {
                HeapFree(GetProcessHeap(), 0, pathBuf);
                break;
            }

            size_t charLen = byteLen / sizeof(wchar_t);
            pathBuf[charLen] = L'\0';

            PrintPathUtf8(pathBuf, charLen);

            HeapFree(GetProcessHeap(), 0, pathBuf);
        }

        printf("filemon_controller: client disconnected\n");
        fflush(stdout);

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    printf("filemon_controller: shutting down\n");
    return 0;
}
