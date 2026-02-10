/*
 * filemon_hook.c — NtCreateFile hook DLL
 *
 * Uses MinHook to intercept NtCreateFile, records files opened for reading,
 * and reports them via a named pipe (FILEMON_PIPE) or directly to a file
 * (FILEMON_FILE).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stddef.h>

#include "MinHook.h"

/* --------------------------------------------------------------------------
 * NT definitions not in winternl.h
 * ----------------------------------------------------------------------- */

#ifndef FILE_OPEN
#define FILE_OPEN                   0x00000001
#endif
#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF                0x00000003
#endif
#ifndef FILE_READ_DATA
#define FILE_READ_DATA              0x0001
#endif
#ifndef FILE_WRITE_DATA
#define FILE_WRITE_DATA             0x0002
#endif

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS (NTAPI *NtCreateFile_t)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength);

/* --------------------------------------------------------------------------
 * Globals
 * ----------------------------------------------------------------------- */

static NtCreateFile_t g_pNtCreateFileOriginal = NULL;

/* Singly-linked path list */
typedef struct PathEntry {
    struct PathEntry *next;
    wchar_t           path[1]; /* flexible array (overallocated) */
} PathEntry;

static PathEntry *volatile g_pathHead = NULL;
static SRWLOCK             g_pathLock = SRWLOCK_INIT;

/* Reporter thread */
static HANDLE g_hReporterThread = NULL;
static HANDLE g_hStopEvent      = NULL;
static HANDLE g_hPipeHandle     = INVALID_HANDLE_VALUE;

/* Pipe name (overridden by FILEMON_PIPE env var) */
static wchar_t g_pipeName[256] = L"\\\\.\\pipe\\filemon";

/* File output mode (alternative to pipe, set via FILEMON_FILE env var) */
static BOOL    g_useFile     = FALSE;
static HANDLE  g_hFileHandle = INVALID_HANDLE_VALUE;
static wchar_t g_fileName[MAX_PATH];

/* --------------------------------------------------------------------------
 * Path list operations
 * ----------------------------------------------------------------------- */

static void PathList_Push(const wchar_t *path, size_t charLen)
{
    PathEntry *entry = (PathEntry *)HeapAlloc(
        GetProcessHeap(), 0,
        offsetof(PathEntry, path) + (charLen + 1) * sizeof(wchar_t));
    if (!entry) return;

    memcpy(entry->path, path, charLen * sizeof(wchar_t));
    entry->path[charLen] = L'\0';

    AcquireSRWLockExclusive(&g_pathLock);
    entry->next = g_pathHead;
    g_pathHead  = entry;
    ReleaseSRWLockExclusive(&g_pathLock);
}

/* Drain: atomically swap head to NULL, return old list */
static PathEntry *PathList_Drain(void)
{
    PathEntry *head;
    AcquireSRWLockExclusive(&g_pathLock);
    head       = g_pathHead;
    g_pathHead = NULL;
    ReleaseSRWLockExclusive(&g_pathLock);
    return head;
}

/* Reverse a singly-linked list (so we report in insertion order) */
static PathEntry *PathList_Reverse(PathEntry *head)
{
    PathEntry *prev = NULL;
    while (head) {
        PathEntry *next = head->next;
        head->next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

static void PathList_FreeChain(PathEntry *head)
{
    while (head) {
        PathEntry *next = head->next;
        HeapFree(GetProcessHeap(), 0, head);
        head = next;
    }
}

/* --------------------------------------------------------------------------
 * NtCreateFile detour
 * ----------------------------------------------------------------------- */

static NTSTATUS NTAPI NtCreateFile_Hook(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength)
{
    /* Call the original first */
    NTSTATUS status = g_pNtCreateFileOriginal(
        FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
        CreateOptions, EaBuffer, EaLength);

    /* Only record successful opens */
    if (!NT_SUCCESS(status))
        return status;

    {
        BOOL hasRead  = (DesiredAccess & (FILE_READ_DATA  | GENERIC_READ))  != 0;
        BOOL hasWrite = (DesiredAccess & (FILE_WRITE_DATA | GENERIC_WRITE)) != 0;
        if (!hasRead && !hasWrite)
            return status;
    }

    /* Extract the path */
    if (!ObjectAttributes || !ObjectAttributes->ObjectName ||
        !ObjectAttributes->ObjectName->Buffer ||
        ObjectAttributes->ObjectName->Length == 0)
        return status;

    const wchar_t *buf = ObjectAttributes->ObjectName->Buffer;
    USHORT byteLen     = ObjectAttributes->ObjectName->Length;
    size_t charLen     = byteLen / sizeof(wchar_t);

    /* Skip non-filesystem NT paths:
     *   \Device\NamedPipe, \Registry, \Device\Afd, etc.
     * We only want paths that start with \Device\ but not the above,
     * OR DOS-style paths like \??\C:\...
     */
    if (charLen < 4)
        return status;

    /* Skip named pipes (our own pipe, and others) */
    if (charLen >= 18 &&
        _wcsnicmp(buf, L"\\Device\\NamedPipe", 17) == 0)
        return status;

    /* Skip registry */
    if (charLen >= 10 &&
        _wcsnicmp(buf, L"\\Registry\\", 10) == 0)
        return status;

    /* Skip Afd (sockets) */
    if (charLen >= 12 &&
        _wcsnicmp(buf, L"\\Device\\Afd", 11) == 0)
        return status;

    /* Accept \??\ (DOS device paths) and \Device\ filesystem paths */
    if (buf[0] != L'\\')
        return status;

    /* Strip \??\ prefix from DOS device paths */
    if (charLen >= 4 && buf[0] == L'\\' && buf[1] == L'?' &&
        buf[2] == L'?' && buf[3] == L'\\') {
        buf += 4;
        charLen -= 4;
    }

    /* Build "R ", "W ", or "RW " prefixed path */
    {
        BOOL hasRead  = (DesiredAccess & (FILE_READ_DATA  | GENERIC_READ))  != 0;
        BOOL hasWrite = (DesiredAccess & (FILE_WRITE_DATA | GENERIC_WRITE)) != 0;
        const wchar_t *prefix;
        size_t prefixLen;

        if (hasRead && hasWrite)      { prefix = L"RW "; prefixLen = 3; }
        else if (hasWrite)            { prefix = L"W ";  prefixLen = 2; }
        else                          { prefix = L"R ";  prefixLen = 2; }

        {
            size_t totalLen = prefixLen + charLen;
            PathEntry *entry = (PathEntry *)HeapAlloc(
                GetProcessHeap(), 0,
                offsetof(PathEntry, path) + (totalLen + 1) * sizeof(wchar_t));
            if (entry) {
                memcpy(entry->path, prefix, prefixLen * sizeof(wchar_t));
                memcpy(entry->path + prefixLen, buf, charLen * sizeof(wchar_t));
                entry->path[totalLen] = L'\0';

                AcquireSRWLockExclusive(&g_pathLock);
                entry->next = g_pathHead;
                g_pathHead  = entry;
                ReleaseSRWLockExclusive(&g_pathLock);
            }
        }
    }

    return status;
}

/* --------------------------------------------------------------------------
 * Named pipe reporter thread
 * ----------------------------------------------------------------------- */

static BOOL WritePipe(HANDLE hPipe, const void *data, DWORD size)
{
    DWORD written;
    return WriteFile(hPipe, data, size, &written, NULL) && written == size;
}

static BOOL SendPath(HANDLE hPipe, const wchar_t *path)
{
    uint32_t byteLen = (uint32_t)(wcslen(path) * sizeof(wchar_t));

    if (!WritePipe(hPipe, &byteLen, sizeof(byteLen)))
        return FALSE;
    if (byteLen > 0 && !WritePipe(hPipe, path, byteLen))
        return FALSE;
    return TRUE;
}

static BOOL SendPathToFile(HANDLE hFile, const wchar_t *path)
{
    int charLen = (int)wcslen(path);
    int utf8Len;
    char *utf8;
    DWORD written;
    BOOL ok;

    if (charLen == 0) return TRUE;

    utf8Len = WideCharToMultiByte(CP_UTF8, 0, path, charLen, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) return TRUE;

    utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, utf8Len + 2);
    if (!utf8) return FALSE;

    WideCharToMultiByte(CP_UTF8, 0, path, charLen, utf8, utf8Len, NULL, NULL);
    utf8[utf8Len] = '\n';

    ok = WriteFile(hFile, utf8, utf8Len + 1, &written, NULL);
    HeapFree(GetProcessHeap(), 0, utf8);
    return ok;
}

static DWORD WINAPI ReporterThreadProc(LPVOID param)
{
    (void)param;

    HANDLE hOutput      = INVALID_HANDLE_VALUE;
    DWORD  retryDelayMs = 100;

    /* In file mode, open the output file up front */
    if (g_useFile) {
        hOutput = CreateFileW(
            g_fileName,
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hOutput == INVALID_HANDLE_VALUE)
            return 1;
        g_hFileHandle = hOutput;
    }

    while (WaitForSingleObject(g_hStopEvent, 0) != WAIT_OBJECT_0) {
        /* Pipe mode: connect if not connected */
        if (!g_useFile && hOutput == INVALID_HANDLE_VALUE) {
            hOutput = CreateFileW(
                g_pipeName,
                GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL);

            if (hOutput == INVALID_HANDLE_VALUE) {
                DWORD waitResult = WaitForSingleObject(g_hStopEvent, retryDelayMs);
                if (waitResult == WAIT_OBJECT_0)
                    break;
                if (retryDelayMs < 2000)
                    retryDelayMs *= 2;
                continue;
            }

            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(hOutput, &mode, NULL, NULL);
            g_hPipeHandle = hOutput;
            retryDelayMs = 100;
        }

        /* Wait for stop or poll interval */
        {
            DWORD waitResult = WaitForSingleObject(g_hStopEvent, 50);
            if (waitResult == WAIT_OBJECT_0) {
                /* Drain remaining entries before exiting */
                PathEntry *list = PathList_Drain();
                list = PathList_Reverse(list);
                while (list) {
                    PathEntry *next = list->next;
                    if (g_useFile)
                        SendPathToFile(hOutput, list->path);
                    else
                        SendPath(hOutput, list->path);
                    HeapFree(GetProcessHeap(), 0, list);
                    list = next;
                }
                break;
            }
        }

        /* Drain and send */
        {
            BOOL sendFailed = FALSE;
            PathEntry *list = PathList_Drain();
            if (!list) continue;

            list = PathList_Reverse(list);
            while (list) {
                PathEntry *next = list->next;
                BOOL ok = g_useFile ? SendPathToFile(hOutput, list->path)
                                    : SendPath(hOutput, list->path);
                if (!ok) {
                    if (g_useFile)
                        g_hFileHandle = INVALID_HANDLE_VALUE;
                    else
                        g_hPipeHandle = INVALID_HANDLE_VALUE;
                    CloseHandle(hOutput);
                    hOutput = INVALID_HANDLE_VALUE;
                    HeapFree(GetProcessHeap(), 0, list);
                    PathList_FreeChain(next);
                    sendFailed = TRUE;
                    break;
                }
                HeapFree(GetProcessHeap(), 0, list);
                list = next;
            }
            /* File write failure is unrecoverable */
            if (sendFailed && g_useFile)
                break;
        }
    }

    if (g_useFile)
        g_hFileHandle = INVALID_HANDLE_VALUE;
    else
        g_hPipeHandle = INVALID_HANDLE_VALUE;
    if (hOutput != INVALID_HANDLE_VALUE)
        CloseHandle(hOutput);

    return 0;
}

/* --------------------------------------------------------------------------
 * DllMain
 * ----------------------------------------------------------------------- */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule;

    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);

        /* Check for output mode from environment:
         *   FILEMON_PIPE → named pipe (custom name)
         *   FILEMON_FILE → direct file output
         *   neither      → default pipe name */
        {
            wchar_t buf[MAX_PATH];
            DWORD n = GetEnvironmentVariableW(L"FILEMON_PIPE", buf, 256);
            if (n > 0 && n < 256) {
                memcpy(g_pipeName, buf, (n + 1) * sizeof(wchar_t));
            } else {
                n = GetEnvironmentVariableW(L"FILEMON_FILE", buf, MAX_PATH);
                if (n > 0 && n < MAX_PATH) {
                    memcpy(g_fileName, buf, (n + 1) * sizeof(wchar_t));
                    g_useFile = TRUE;
                }
            }
        }

        /* Resolve NtCreateFile */
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return FALSE;

        NtCreateFile_t pNtCreateFile =
            (NtCreateFile_t)GetProcAddress(hNtdll, "NtCreateFile");
        if (!pNtCreateFile) return FALSE;

        /* Initialize MinHook */
        if (MH_Initialize() != MH_OK)
            return FALSE;

        /* Create hook */
        if (MH_CreateHook((LPVOID)pNtCreateFile,
                          (LPVOID)NtCreateFile_Hook,
                          (LPVOID *)&g_pNtCreateFileOriginal) != MH_OK) {
            MH_Uninitialize();
            return FALSE;
        }

        /* Enable hook */
        if (MH_EnableHook((LPVOID)pNtCreateFile) != MH_OK) {
            MH_Uninitialize();
            return FALSE;
        }

        /* Create stop event and start reporter thread */
        g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!g_hStopEvent) {
            MH_DisableHook((LPVOID)pNtCreateFile);
            MH_Uninitialize();
            return FALSE;
        }

        g_hReporterThread = CreateThread(NULL, 0, ReporterThreadProc, NULL, 0, NULL);
        if (!g_hReporterThread) {
            CloseHandle(g_hStopEvent);
            MH_DisableHook((LPVOID)pNtCreateFile);
            MH_Uninitialize();
            return FALSE;
        }
        break;
    }

    case DLL_PROCESS_DETACH: {
        if (reserved != NULL) {
            /* Process termination: other threads are already dead.
               Flush remaining paths directly from here. */
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();

            {
                HANDLE hOutput = g_useFile ? g_hFileHandle : g_hPipeHandle;
                if (hOutput != INVALID_HANDLE_VALUE) {
                    PathEntry *list = PathList_Drain();
                    list = PathList_Reverse(list);
                    while (list) {
                        PathEntry *next = list->next;
                        if (g_useFile)
                            SendPathToFile(hOutput, list->path);
                        else
                            SendPath(hOutput, list->path);
                        HeapFree(GetProcessHeap(), 0, list);
                        list = next;
                    }
                    CloseHandle(hOutput);
                    if (g_useFile)
                        g_hFileHandle = INVALID_HANDLE_VALUE;
                    else
                        g_hPipeHandle = INVALID_HANDLE_VALUE;
                }
            }
        } else {
            /* Dynamic unload (FreeLibrary): signal reporter and wait */
            if (g_hStopEvent)
                SetEvent(g_hStopEvent);

            if (g_hReporterThread) {
                WaitForSingleObject(g_hReporterThread, 3000);
                CloseHandle(g_hReporterThread);
                g_hReporterThread = NULL;
            }

            if (g_hStopEvent) {
                CloseHandle(g_hStopEvent);
                g_hStopEvent = NULL;
            }

            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();

            PathList_FreeChain(PathList_Drain());
        }
        break;
    }
    }

    return TRUE;
}
