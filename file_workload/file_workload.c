/*
 * file_workload.c — Test workload for filemon
 *
 * Creates 100 randomly named files, reads 50 of them, then writes
 * a manifest file listing all written and read filenames.
 *
 * Usage: file_workload DIRECTORY
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

#define NUM_FILES  100
#define NUM_READS   50

/* Simple xorshift32 PRNG */
static unsigned int g_rng;

static unsigned int rng_next(void)
{
    unsigned int x = g_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng = x;
    return x;
}

int main(void)
{
    int nArgs, i, j;
    LPWSTR *args;
    const wchar_t *dir;
    wchar_t filePaths[NUM_FILES][MAX_PATH];
    wchar_t fileNames[NUM_FILES][64];
    wchar_t manifestPath[MAX_PATH];
    int readFlags[NUM_FILES];
    int indices[NUM_FILES];
    HANDLE hFile;
    DWORD written, bytesRead;

    args = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (!args || nArgs < 2) {
        fprintf(stderr, "Usage: file_workload DIRECTORY\n");
        if (args) LocalFree(args);
        return 1;
    }
    dir = args[1];

    /* Seed PRNG */
    g_rng = GetTickCount() ^ GetCurrentProcessId();
    if (g_rng == 0) g_rng = 1;

    memset(readFlags, 0, sizeof(readFlags));

    /* Generate filenames and create files */
    for (i = 0; i < NUM_FILES; i++) {
        unsigned int r = rng_next();
        char content[64];
        int len;

        swprintf_s(fileNames[i], 64, L"wl_%08X.dat", r);
        swprintf_s(filePaths[i], MAX_PATH, L"%s\\%s", dir, fileNames[i]);

        hFile = CreateFileW(filePaths[i], GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "error: cannot create file %d (error %lu)\n",
                    i, GetLastError());
            LocalFree(args);
            return 1;
        }

        len = sprintf_s(content, sizeof(content), "Content of file %d\n", i);
        WriteFile(hFile, content, (DWORD)len, &written, NULL);
        CloseHandle(hFile);
    }

    /* Fisher-Yates shuffle to pick NUM_READS random files to read */
    for (i = 0; i < NUM_FILES; i++)
        indices[i] = i;
    for (i = NUM_FILES - 1; i > 0; i--) {
        j = (int)(rng_next() % (unsigned int)(i + 1));
        {
            int tmp = indices[i];
            indices[i] = indices[j];
            indices[j] = tmp;
        }
    }

    /* Read the selected files */
    for (i = 0; i < NUM_READS; i++) {
        int idx = indices[i];
        char buf[256];

        readFlags[idx] = 1;

        hFile = CreateFileW(filePaths[idx], GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "error: cannot read file %d (error %lu)\n",
                    idx, GetLastError());
            LocalFree(args);
            return 1;
        }

        ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL);
        CloseHandle(hFile);
    }

    /* Write manifest as the last file */
    swprintf_s(manifestPath, MAX_PATH, L"%s\\manifest.txt", dir);

    hFile = CreateFileW(manifestPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "error: cannot create manifest (error %lu)\n",
                GetLastError());
        LocalFree(args);
        return 1;
    }

    for (i = 0; i < NUM_FILES; i++) {
        char line[256];
        char nameUtf8[128];
        int len;

        WideCharToMultiByte(CP_UTF8, 0, fileNames[i], -1,
                            nameUtf8, sizeof(nameUtf8), NULL, NULL);
        len = sprintf_s(line, sizeof(line), "WRITTEN %s\n", nameUtf8);
        WriteFile(hFile, line, (DWORD)len, &written, NULL);
    }

    for (i = 0; i < NUM_FILES; i++) {
        if (readFlags[i]) {
            char line[256];
            char nameUtf8[128];
            int len;

            WideCharToMultiByte(CP_UTF8, 0, fileNames[i], -1,
                                nameUtf8, sizeof(nameUtf8), NULL, NULL);
            len = sprintf_s(line, sizeof(line), "READ %s\n", nameUtf8);
            WriteFile(hFile, line, (DWORD)len, &written, NULL);
        }
    }

    CloseHandle(hFile);
    LocalFree(args);

    printf("Workload complete: %d files written, %d files read\n",
           NUM_FILES, NUM_READS);
    return 0;
}
