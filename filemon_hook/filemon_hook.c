/*
 * filemon_hook.c — NtCreateFile hook DLL
 *
 * Uses MinHook to intercept NtCreateFile, records files opened for reading,
 * and reports them to a controller process via \\.\pipe\filemon.
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

/* Pipe name */
static const wchar_t g_pipeName[] = L"\\\\.\\pipe\\filemon";

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

    /* Only record successful opens that read existing files */
    if (!NT_SUCCESS(status))
        return status;

    if (!(DesiredAccess & (FILE_READ_DATA | GENERIC_READ)))
        return status;

    if (CreateDisposition != FILE_OPEN && CreateDisposition != FILE_OPEN_IF)
        return status;

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

    PathList_Push(buf, charLen);
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

static DWORD WINAPI ReporterThreadProc(LPVOID param)
{
    (void)param;

    HANDLE hPipe       = INVALID_HANDLE_VALUE;
    DWORD  retryDelayMs = 100;

    while (WaitForSingleObject(g_hStopEvent, 0) != WAIT_OBJECT_0) {
        /* Connect to pipe if not connected */
        if (hPipe == INVALID_HANDLE_VALUE) {
            hPipe = CreateFileW(
                g_pipeName,
                GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL);

            if (hPipe == INVALID_HANDLE_VALUE) {
                /* Pipe not available — wait with backoff */
                DWORD waitResult = WaitForSingleObject(g_hStopEvent, retryDelayMs);
                if (waitResult == WAIT_OBJECT_0)
                    break;
                if (retryDelayMs < 2000)
                    retryDelayMs *= 2;
                continue;
            }

            /* Connected — set to byte mode */
            DWORD mode = PIPE_READMODE_BYTE;
            SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
            retryDelayMs = 100;
        }

        /* Wait for stop or poll interval */
        DWORD waitResult = WaitForSingleObject(g_hStopEvent, 50);
        if (waitResult == WAIT_OBJECT_0) {
            /* Drain remaining entries before exiting */
            PathEntry *list = PathList_Drain();
            list = PathList_Reverse(list);
            while (list) {
                PathEntry *next = list->next;
                SendPath(hPipe, list->path);
                HeapFree(GetProcessHeap(), 0, list);
                list = next;
            }
            break;
        }

        /* Drain and send */
        PathEntry *list = PathList_Drain();
        if (!list) continue;

        list = PathList_Reverse(list);
        while (list) {
            PathEntry *next = list->next;
            if (!SendPath(hPipe, list->path)) {
                /* Pipe broken — requeue remaining entries and reconnect */
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;

                /* Free entries we couldn't send */
                HeapFree(GetProcessHeap(), 0, list);
                PathList_FreeChain(next);
                break;
            }
            HeapFree(GetProcessHeap(), 0, list);
            list = next;
        }
    }

    if (hPipe != INVALID_HANDLE_VALUE)
        CloseHandle(hPipe);

    return 0;
}

/* --------------------------------------------------------------------------
 * DllMain
 * ----------------------------------------------------------------------- */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    (void)hModule;
    (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);

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
        /* Signal reporter to stop */
        if (g_hStopEvent)
            SetEvent(g_hStopEvent);

        /* Wait for reporter thread with timeout */
        if (g_hReporterThread) {
            WaitForSingleObject(g_hReporterThread, 3000);
            CloseHandle(g_hReporterThread);
            g_hReporterThread = NULL;
        }

        if (g_hStopEvent) {
            CloseHandle(g_hStopEvent);
            g_hStopEvent = NULL;
        }

        /* Disable hook and uninitialize MinHook */
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();

        /* Free any remaining list entries */
        PathList_FreeChain(PathList_Drain());
        break;
    }
    }

    return TRUE;
}
