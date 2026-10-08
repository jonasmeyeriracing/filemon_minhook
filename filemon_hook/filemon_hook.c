/*
 * filemon_hook.c — NtCreateFile hook DLL
 *
 * Uses MinHook to intercept NtCreateFile/NtOpenFile, the attribute queries and
 * NtSetInformationFile, records files opened, probed, renamed and deleted (see
 * Record below for the line format), and reports them via a named pipe
 * (FILEMON_PIPE) or directly to a file (FILEMON_FILE).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

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

#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE         0x00000001
#endif
#ifndef FILE_DELETE_ON_CLOSE
#define FILE_DELETE_ON_CLOSE        0x00001000
#endif

/* FILE_INFORMATION_CLASS values (winternl.h only has the first) */
#define FM_FileRenameInformation          10
#define FM_FileDispositionInformation     13
#define FM_FileDispositionInformationEx   64
#define FM_FileRenameInformationEx        65

typedef struct {
    LARGE_INTEGER CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
    ULONG         FileAttributes;
} FM_BASIC_INFORMATION;

typedef struct {
    LARGE_INTEGER CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
    LARGE_INTEGER AllocationSize, EndOfFile;
    ULONG         FileAttributes;
} FM_NETWORK_OPEN_INFORMATION;

typedef NTSTATUS (NTAPI *NtOpenFile_t)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions);

typedef NTSTATUS (NTAPI *NtQueryAttributesFile_t)(
    POBJECT_ATTRIBUTES ObjectAttributes, FM_BASIC_INFORMATION *FileInformation);

typedef NTSTATUS (NTAPI *NtQueryFullAttributesFile_t)(
    POBJECT_ATTRIBUTES ObjectAttributes, FM_NETWORK_OPEN_INFORMATION *FileInformation);

typedef NTSTATUS (NTAPI *NtQueryInformationByName_t)(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PVOID              FileInformation,
    ULONG              Length,
    ULONG              FileInformationClass);

typedef NTSTATUS (NTAPI *NtQueryDirectoryFile_t)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass,
    BOOLEAN          ReturnSingleEntry,
    PUNICODE_STRING  FileName,
    BOOLEAN          RestartScan);

typedef NTSTATUS (NTAPI *NtQueryDirectoryFileEx_t)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PVOID            ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass,
    ULONG            QueryFlags,
    PUNICODE_STRING  FileName);

typedef NTSTATUS (NTAPI *NtSetInformationFile_t)(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass);

/* kernelbase!CreateProcessInternalW: every CreateProcess* variant ends up here */
typedef BOOL (WINAPI *CreateProcessInternalW_t)(
    HANDLE                hUserToken,
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE               hNewToken);

/* --------------------------------------------------------------------------
 * Globals
 * ----------------------------------------------------------------------- */

static NtCreateFile_t g_pNtCreateFileOriginal = NULL;
static NtOpenFile_t g_pNtOpenFileOriginal = NULL;
static NtQueryAttributesFile_t g_pNtQueryAttributesFileOriginal = NULL;
static NtQueryFullAttributesFile_t g_pNtQueryFullAttributesFileOriginal = NULL;
static NtSetInformationFile_t g_pNtSetInformationFileOriginal = NULL;
static NtQueryInformationByName_t g_pNtQueryInformationByNameOriginal = NULL;
static NtQueryDirectoryFile_t g_pNtQueryDirectoryFileOriginal = NULL;
static NtQueryDirectoryFileEx_t g_pNtQueryDirectoryFileExOriginal = NULL;
static CreateProcessInternalW_t g_pCreateProcessInternalWOriginal = NULL;
static wchar_t g_dllPath[MAX_PATH];  /* this DLL, injected into child processes */

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
 * Recording
 *
 * One line per event, "<prefix> <path>":
 *   R / W / RW  opened for reading / writing / both
 *   E           exists: opened without data access, or attributes queried
 *   M           missing: an open or attribute query found no such file/path
 *   D           deleted (delete disposition, or FILE_DELETE_ON_CLOSE)
 *   MV          renamed: "MV <old path>\t<new path>"
 *   L           folder listed: "L <dir>\<wildcard pattern>"
 *   X / XU      child process started, traced / untraced (its image path)
 * ----------------------------------------------------------------------- */

static void Record(const wchar_t *prefix, const wchar_t *text)
{
    size_t prefixLen = wcslen(prefix), textLen = wcslen(text);
    PathEntry *entry = (PathEntry *)HeapAlloc(
        GetProcessHeap(), 0,
        offsetof(PathEntry, path) + (prefixLen + textLen + 1) * sizeof(wchar_t));
    if (!entry) return;
    memcpy(entry->path, prefix, prefixLen * sizeof(wchar_t));
    memcpy(entry->path + prefixLen, text, textLen * sizeof(wchar_t));
    entry->path[prefixLen + textLen] = L'\0';

    AcquireSRWLockExclusive(&g_pathLock);
    entry->next = g_pathHead;
    g_pathHead  = entry;
    ReleaseSRWLockExclusive(&g_pathLock);
}

#define FM_PATH 1024

/* set while this thread is inside our own path lookup: its opens are not the tool's */
static __declspec(thread) int t_lookingUp;

/* DOS path of an open handle into out (FM_PATH chars), without the \\?\ prefix */
static BOOL HandlePath(HANDLE h, wchar_t *out)
{
    wchar_t tmp[FM_PATH];
    DWORD len;
    const wchar_t *p = tmp;
    t_lookingUp++;
    len = GetFinalPathNameByHandleW(h, tmp, FM_PATH, FILE_NAME_NORMALIZED);
    t_lookingUp--;
    if (len == 0 || len >= FM_PATH)
        return FALSE;
    if (len >= 4 && p[0] == L'\\' && p[1] == L'\\' && p[2] == L'?' && p[3] == L'\\')
        p += 4;
    wcscpy_s(out, FM_PATH, p);
    return TRUE;
}

/* Path named by ObjectAttributes into out (FM_PATH chars). For a name relative to
   a directory handle, 'opened' (the handle just opened, or NULL when the call
   failed) gives the final path; otherwise the directory's path plus the name. */
static BOOL ObjectPath(POBJECT_ATTRIBUTES oa, HANDLE opened, wchar_t *out)
{
    const wchar_t *buf;
    size_t charLen;

    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer || oa->ObjectName->Length == 0)
        return FALSE;
    buf = oa->ObjectName->Buffer;
    charLen = oa->ObjectName->Length / sizeof(wchar_t);

    if (buf[0] == L'\\') {
        /* Absolute NT path — filter out non-filesystem paths */
        if (charLen < 4)
            return FALSE;
        if (charLen >= 18 && _wcsnicmp(buf, L"\\Device\\NamedPipe", 17) == 0)
            return FALSE;
        if (charLen >= 10 && _wcsnicmp(buf, L"\\Registry\\", 10) == 0)
            return FALSE;
        if (charLen >= 12 && _wcsnicmp(buf, L"\\Device\\Afd", 11) == 0)
            return FALSE;
        /* Strip \??\ prefix from DOS device paths */
        if (buf[1] == L'?' && buf[2] == L'?' && buf[3] == L'\\') {
            buf += 4;
            charLen -= 4;
        }
        if (charLen >= FM_PATH)
            return FALSE;
        memcpy(out, buf, charLen * sizeof(wchar_t));
        out[charLen] = L'\0';
        return TRUE;
    }
    if (!oa->RootDirectory)
        return FALSE;
    if (opened)
        return HandlePath(opened, out);
    {
        size_t n;
        if (!HandlePath(oa->RootDirectory, out))
            return FALSE;
        n = wcslen(out);
        if (n + 1 + charLen >= FM_PATH)
            return FALSE;
        if (n && out[n - 1] != L'\\')
            out[n++] = L'\\';
        memcpy(out + n, buf, charLen * sizeof(wchar_t));
        out[n + charLen] = L'\0';
        return TRUE;
    }
}

/* Missing-file probes not worth a line: debug symbol searches (dbghelp looks for every
   module's .pdb in each folder of the symbol path, hundreds per process) and NT device
   paths (\Device\...) */
static void RecordMissing(const wchar_t *path)
{
    const wchar_t *p;
    if (path[0] == L'\\' && path[1] != L'\\')
        return;
    for (p = path; *p; p++) {
        if (p[0] == L'.' && (p[1] | 0x20) == L'p' && (p[2] | 0x20) == L'd' && (p[3] | 0x20) == L'b' &&
            (p[4] == L'\0' || p[4] == L'\\'))
            return;
    }
    Record(L"M ", path);
}

static BOOL IsNotFound(NTSTATUS status)
{
    return status == (NTSTATUS)0xC0000034L     /* STATUS_OBJECT_NAME_NOT_FOUND */
        || status == (NTSTATUS)0xC000003AL     /* STATUS_OBJECT_PATH_NOT_FOUND */
        || status == (NTSTATUS)0xC000000FL;    /* STATUS_NO_SUCH_FILE */
}

/* After NtCreateFile / NtOpenFile */
static void RecordOpen(NTSTATUS status, PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                       POBJECT_ATTRIBUTES ObjectAttributes, ULONG CreateOptions)
{
    wchar_t path[FM_PATH];
    const wchar_t *prefix;
    BOOL hasRead, hasWrite;

    if (t_lookingUp)
        return;
    if (!NT_SUCCESS(status)) {
        if (IsNotFound(status) && ObjectPath(ObjectAttributes, NULL, path))
            RecordMissing(path);
        return;
    }

    hasRead  = (DesiredAccess & (FILE_READ_DATA  | GENERIC_READ))  != 0;
    hasWrite = (DesiredAccess & (FILE_WRITE_DATA | GENERIC_WRITE)) != 0;
    if (hasRead && hasWrite)                      prefix = L"RW ";
    else if (hasWrite)                            prefix = L"W ";
    else if (hasRead)                             prefix = L"R ";
    else if (CreateOptions & FILE_DELETE_ON_CLOSE) prefix = L"D ";
    else if ((CreateOptions & FILE_DIRECTORY_FILE) || (DesiredAccess & DELETE))
        return;  /* a directory handle, or opened to rename/delete (logged then) */
    else                                          prefix = L"E ";

    if (ObjectPath(ObjectAttributes, *FileHandle, path))
        Record(prefix, path);
}

/* --------------------------------------------------------------------------
 * Detours
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
    NTSTATUS status = g_pNtCreateFileOriginal(
        FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
        CreateOptions, EaBuffer, EaLength);
    RecordOpen(status, FileHandle, DesiredAccess, ObjectAttributes, CreateOptions);
    return status;
}

static NTSTATUS NTAPI NtOpenFile_Hook(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions)
{
    NTSTATUS status = g_pNtOpenFileOriginal(
        FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    RecordOpen(status, FileHandle, DesiredAccess, ObjectAttributes, OpenOptions);
    return status;
}

/* GetFileAttributes(Ex), PathFileExists, _access, ... */
static void RecordQuery(NTSTATUS status, POBJECT_ATTRIBUTES ObjectAttributes, ULONG attributes)
{
    wchar_t path[FM_PATH];
    if (t_lookingUp)
        return;
    if (NT_SUCCESS(status)) {
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) && ObjectPath(ObjectAttributes, NULL, path))
            Record(L"E ", path);
    } else if (IsNotFound(status) && ObjectPath(ObjectAttributes, NULL, path)) {
        RecordMissing(path);
    }
}

static NTSTATUS NTAPI NtQueryAttributesFile_Hook(
    POBJECT_ATTRIBUTES ObjectAttributes, FM_BASIC_INFORMATION *FileInformation)
{
    NTSTATUS status = g_pNtQueryAttributesFileOriginal(ObjectAttributes, FileInformation);
    RecordQuery(status, ObjectAttributes, NT_SUCCESS(status) ? FileInformation->FileAttributes : 0);
    return status;
}

static NTSTATUS NTAPI NtQueryFullAttributesFile_Hook(
    POBJECT_ATTRIBUTES ObjectAttributes, FM_NETWORK_OPEN_INFORMATION *FileInformation)
{
    NTSTATUS status = g_pNtQueryFullAttributesFileOriginal(ObjectAttributes, FileInformation);
    RecordQuery(status, ObjectAttributes, NT_SUCCESS(status) ? FileInformation->FileAttributes : 0);
    return status;
}

/* GetFileInformationByName (Python 3.12+ os.stat on Windows 11, ...) */
static NTSTATUS NTAPI NtQueryInformationByName_Hook(
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PVOID              FileInformation,
    ULONG              Length,
    ULONG              FileInformationClass)
{
    NTSTATUS status = g_pNtQueryInformationByNameOriginal(
        ObjectAttributes, IoStatusBlock, FileInformation, Length, FileInformationClass);
    /* the attributes' position depends on the class; the stat classes have them at 56
       (FileStatInformation 68, FileStatLxInformation 70, FileStatBasicInformation 77) */
    ULONG attributes = 0;
    if (NT_SUCCESS(status) && Length >= 60 &&
        (FileInformationClass == 68 || FileInformationClass == 70 || FileInformationClass == 77))
        attributes = *(const ULONG *)((const BYTE *)FileInformation + 56);
    RecordQuery(status, ObjectAttributes, attributes);
    return status;
}

/* FindFirstFile: an exact name is an existence probe ("if exist x", _findfirst("x")),
   a wildcard is a folder listing: "L <dir>\<pattern>" */
static void RecordDirectoryQuery(NTSTATUS status, HANDLE dir, PUNICODE_STRING name)
{
    wchar_t path[FM_PATH];
    size_t n, i, len;
    BOOL wild = FALSE;

    if (t_lookingUp || !name || !name->Buffer || name->Length == 0 || status == STATUS_PENDING)
        return;
    len = name->Length / sizeof(wchar_t);
    for (i = 0; i < len; i++) {
        wchar_t c = name->Buffer[i];
        if (c == L'*' || c == L'?' || c == L'<' || c == L'>' || c == L'"')
            wild = TRUE;
    }
    if (!HandlePath(dir, path))
        return;
    n = wcslen(path);
    if (n + 1 + len >= FM_PATH)
        return;
    if (n && path[n - 1] != L'\\')
        path[n++] = L'\\';
    for (i = 0; i < len; i++) {
        /* FindFirstFile's DOS wildcards back to what the caller wrote */
        wchar_t c = name->Buffer[i];
        path[n + i] = c == L'<' ? L'*' : c == L'>' ? L'?' : c == L'"' ? L'.' : c;
    }
    path[n + len] = L'\0';

    if (wild)
        Record(L"L ", path);
    else if (NT_SUCCESS(status))
        Record(L"E ", path);
    else if (IsNotFound(status) || status == (NTSTATUS)0x80000006L)  /* STATUS_NO_MORE_FILES */
        RecordMissing(path);
}

static NTSTATUS NTAPI NtQueryDirectoryFile_Hook(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName,
    BOOLEAN RestartScan)
{
    NTSTATUS status = g_pNtQueryDirectoryFileOriginal(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
        FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
    RecordDirectoryQuery(status, FileHandle, FileName);
    return status;
}

static NTSTATUS NTAPI NtQueryDirectoryFileEx_Hook(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName)
{
    NTSTATUS status = g_pNtQueryDirectoryFileExOriginal(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length,
        FileInformationClass, QueryFlags, FileName);
    RecordDirectoryQuery(status, FileHandle, FileName);
    return status;
}

/* Renames (MoveFileEx, rename(), cmd move/ren) and deletes (DeleteFile, cmd del) */
static NTSTATUS NTAPI NtSetInformationFile_Hook(
    HANDLE           FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            FileInformation,
    ULONG            Length,
    ULONG            FileInformationClass)
{
    wchar_t oldPath[FM_PATH];
    BOOL rename = FileInformationClass == FM_FileRenameInformation ||
                  FileInformationClass == FM_FileRenameInformationEx;
    BOOL del = FALSE;
    BOOL known;
    NTSTATUS status;

    if (FileInformation) {
        if (FileInformationClass == FM_FileDispositionInformation && Length >= 1)
            del = *(const BOOLEAN *)FileInformation != 0;
        else if (FileInformationClass == FM_FileDispositionInformationEx && Length >= 4)
            del = (*(const ULONG *)FileInformation & 0x1) != 0;  /* FILE_DISPOSITION_DELETE */
    }
    /* the handle's name before the call: a rename changes it */
    known = (rename || del) && HandlePath(FileHandle, oldPath);

    status = g_pNtSetInformationFileOriginal(FileHandle, IoStatusBlock, FileInformation,
                                             Length, FileInformationClass);
    if (!NT_SUCCESS(status) || !known)
        return status;
    if (del) {
        Record(L"D ", oldPath);
    } else {
        wchar_t newPath[FM_PATH], line[2 * FM_PATH + 1];
        if (HandlePath(FileHandle, newPath)) {
            swprintf_s(line, 2 * FM_PATH + 1, L"%s\t%s", oldPath, newPath);
            Record(L"MV ", line);
        }
    }
    return status;
}

/* --------------------------------------------------------------------------
 * Child processes: start them suspended, inject this DLL, then let them run.
 * The child finds FILEMON_FILE / FILEMON_PIPE in the environment it inherits
 * (an explicit environment block without them leaves the child untraced).
 * ----------------------------------------------------------------------- */

/* Same bitness only: LoadLibraryW's address here is valid in the child */
static BOOL InjectDll(HANDLE hProcess, const wchar_t *dllPath)
{
    SIZE_T size = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remote;
    HANDLE hThread;
    DWORD exitCode = 0;
    BOOL ok = FALSE;

    remote = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return FALSE;
    if (WriteProcessMemory(hProcess, remote, dllPath, size, NULL)) {
        hThread = CreateRemoteThread(hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"),
            remote, 0, NULL);
        if (hThread) {
            ok = WaitForSingleObject(hThread, 10000) == WAIT_OBJECT_0
                 && GetExitCodeThread(hThread, &exitCode) && exitCode != 0;
            CloseHandle(hThread);
        }
    }
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    return ok;
}

/* Other bitness: run the launcher of the child's bitness as
   "filemon_commandline_run[32].exe --inject <pid> <dll>". Started through the
   original CreateProcessInternalW, so it is not traced itself. */
static BOOL InjectViaHelper(DWORD pid, BOOL childIs32)
{
    wchar_t dir[MAX_PATH], cmd[3 * MAX_PATH];
    wchar_t *slash;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD exitCode = 1;

    wcscpy_s(dir, MAX_PATH, g_dllPath);
    slash = wcsrchr(dir, L'\\');
    if (!slash) return FALSE;
    slash[1] = L'\0';
    swprintf_s(cmd, 3 * MAX_PATH, L"\"%s%s\" --inject %lu \"%s%s\"",
               dir, childIs32 ? L"filemon_commandline_run32.exe" : L"filemon_commandline_run.exe", pid,
               dir, childIs32 ? L"filemon_hook32.dll" : L"filemon_hook.dll");

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!g_pCreateProcessInternalWOriginal(NULL, NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                                           NULL, NULL, &si, &pi, NULL))
        return FALSE;
    CloseHandle(pi.hThread);
    if (WaitForSingleObject(pi.hProcess, 15000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(pi.hProcess, &exitCode))
        exitCode = 1;
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

static BOOL InjectChild(PROCESS_INFORMATION *pi)
{
    /* on 64-bit Windows, IsWow64Process is TRUE exactly for 32-bit processes */
    BOOL childIs32 = FALSE;
#ifdef _WIN64
    const BOOL selfIs32 = FALSE;
#else
    const BOOL selfIs32 = TRUE;
#endif
    if (!IsWow64Process(pi->hProcess, &childIs32))
        return FALSE;
    if (childIs32 == selfIs32)
        return InjectDll(pi->hProcess, g_dllPath);
    return InjectViaHelper(pi->dwProcessId, childIs32);
}

static BOOL WINAPI CreateProcessInternalW_Hook(
    HANDLE                hUserToken,
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE               hNewToken)
{
    BOOL ok = g_pCreateProcessInternalWOriginal(
        hUserToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation, hNewToken);
    if (!ok)
        return ok;

    {
        /* "X <image path>" for a traced child, "XU <image path>" for one that is not
           (the injection failed) */
        wchar_t image[MAX_PATH];
        DWORD n = MAX_PATH;
        BOOL injected = InjectChild(lpProcessInformation);
        if (QueryFullProcessImageNameW(lpProcessInformation->hProcess, 0, image, &n))
            Record(injected ? L"X " : L"XU ", image);
    }

    if (!(dwCreationFlags & CREATE_SUSPENDED))
        ResumeThread(lpProcessInformation->hThread);
    return ok;
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

    t_lookingUp++;  /* this thread only opens our own output (file or pipe) */

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

        /* Failed opens, existence probes, renames and deletes */
        {
            struct { const char *name; LPVOID detour; LPVOID *original; } extra[] = {
                { "NtOpenFile", (LPVOID)NtOpenFile_Hook, (LPVOID *)&g_pNtOpenFileOriginal },
                { "NtQueryAttributesFile", (LPVOID)NtQueryAttributesFile_Hook,
                  (LPVOID *)&g_pNtQueryAttributesFileOriginal },
                { "NtQueryFullAttributesFile", (LPVOID)NtQueryFullAttributesFile_Hook,
                  (LPVOID *)&g_pNtQueryFullAttributesFileOriginal },
                { "NtSetInformationFile", (LPVOID)NtSetInformationFile_Hook,
                  (LPVOID *)&g_pNtSetInformationFileOriginal },
                { "NtQueryInformationByName", (LPVOID)NtQueryInformationByName_Hook,
                  (LPVOID *)&g_pNtQueryInformationByNameOriginal },
                { "NtQueryDirectoryFile", (LPVOID)NtQueryDirectoryFile_Hook,
                  (LPVOID *)&g_pNtQueryDirectoryFileOriginal },
                { "NtQueryDirectoryFileEx", (LPVOID)NtQueryDirectoryFileEx_Hook,
                  (LPVOID *)&g_pNtQueryDirectoryFileExOriginal },
            };
            int i;
            for (i = 0; i < (int)(sizeof(extra) / sizeof(extra[0])); i++) {
                LPVOID target = (LPVOID)GetProcAddress(hNtdll, extra[i].name);
                if (target)
                    MH_CreateHook(target, extra[i].detour, extra[i].original);
            }
        }

        /* Follow child processes (FILEMON_NOCHILDREN=1 turns it off) */
        if (GetEnvironmentVariableW(L"FILEMON_NOCHILDREN", NULL, 0) == 0 &&
            GetModuleFileNameW(hModule, g_dllPath, MAX_PATH) > 0) {
            HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
            LPVOID pCreateProcessInternalW =
                hKernelBase ? (LPVOID)GetProcAddress(hKernelBase, "CreateProcessInternalW") : NULL;
            if (pCreateProcessInternalW)
                MH_CreateHook(pCreateProcessInternalW, (LPVOID)CreateProcessInternalW_Hook,
                              (LPVOID *)&g_pCreateProcessInternalWOriginal);
        }

        /* Enable the hooks (all at once: one thread freeze) */
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            MH_Uninitialize();
            return FALSE;
        }

        /* Create stop event and start reporter thread */
        g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!g_hStopEvent) {
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
            return FALSE;
        }

        g_hReporterThread = CreateThread(NULL, 0, ReporterThreadProc, NULL, 0, NULL);
        if (!g_hReporterThread) {
            CloseHandle(g_hStopEvent);
            MH_DisableHook(MH_ALL_HOOKS);
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
