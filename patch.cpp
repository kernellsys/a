

#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <vector>
#include <atomic>
#include <thread>

// ---------------------------------------------------------------------------
// Logging: file + console (AllocConsole) + OutputDebugString
// ---------------------------------------------------------------------------
static HANDLE       g_hCon      = nullptr;
static FILE*        g_logFile   = nullptr;
static CRITICAL_SECTION g_cs;
static volatile LONG g_csReady = 0;
static volatile LONG g_logInit = 0;

static void EnsureCs() {
    if (InterlockedCompareExchange(&g_csReady, 1, 0) == 0)
        InitializeCriticalSection(&g_cs);
}

static void LogInit() {
    if (InterlockedCompareExchange(&g_logInit, 1, 0) != 0) return;
    EnsureCs();
    g_logFile = fopen("C:\\NetHooks_log.txt", "w");
    if (!GetConsoleWindow()) AllocConsole();
    g_hCon = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_hCon) SetConsoleTitleA("NetHooks - netc log");
}

static void Log(const char* fmt, ...) {
    if (!fmt) return;
    EnsureCs();
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n <= 0) return;

    EnterCriticalSection(&g_cs);
    if (g_logFile) { fprintf(g_logFile, "%s\n", buf); fflush(g_logFile); }
    if (g_hCon) {
        DWORD w = 0;
        WriteConsoleA(g_hCon, buf, (DWORD)strlen(buf), &w, nullptr);
        WriteConsoleA(g_hCon, "\r\n", 2, &w, nullptr);
    }
    LeaveCriticalSection(&g_cs);
    OutputDebugStringA(buf); OutputDebugStringA("\n");
}

// ---------------------------------------------------------------------------
// IDA-style pattern scanner over a loaded module
//   "53 8B DC 83 EC 08 ? ..."  ('?' or '??' = wildcard)
// ---------------------------------------------------------------------------
static int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool ParseSig(const char* sig, std::vector<BYTE>& bytes, std::vector<BYTE>& mask) {
    bytes.clear(); mask.clear();
    const char* p = sig;
    while (*p) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        if (*p == '?') { ++p; if (*p == '?') ++p; bytes.push_back(0); mask.push_back(0); }
        else {
            int hi = HexVal(*p++); if (hi < 0) return false;
            int lo = HexVal(*p++); if (lo < 0) return false;
            bytes.push_back((BYTE)((hi << 4) | lo)); mask.push_back(0xFF);
        }
    }
    return !bytes.empty();
}

static uintptr_t FindPattern(const char* module, const char* sig) {
    HMODULE hMod = GetModuleHandleA(module);
    if (!hMod) return 0;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    BYTE* base = (BYTE*)hMod;
    size_t size = nt->OptionalHeader.SizeOfImage;

    std::vector<BYTE> bytes, mask;
    if (!ParseSig(sig, bytes, mask)) return 0;
    if (size < bytes.size()) return 0;

    size_t last = size - bytes.size();
    for (size_t i = 0; i <= last; ++i) {
        const BYTE* a = base + i;
        bool ok = true;
        for (size_t k = 0; k < bytes.size(); ++k) {
            if (mask[k] && a[k] != bytes[k]) { ok = false; break; }
        }
        if (ok) return (uintptr_t)a;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Patch state
// ---------------------------------------------------------------------------
struct Patch {
    const char* name;
    const char* pattern;
    const char* bytes;   // replacement hex
    void* addr;
    BYTE  orig[16];
    int   origLen;
};

static Patch g_patch = {
    "CChecker94_Kick",
    // 71-byte AOB from patch.md / readme.txt (single hit at RVA 0x1D25F0)
    "53 8B DC 83 EC 08 83 E4 F0 83 C4 04 55 8B 6B ? 89 6C 24 04 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC 94 01 00 00 A1 ? ? ? ? 33 C5 89 45 EC 56 57 50 8D 45 F4 64 A3 ? ? ? ? 89 8D E0 FE FF FF",
    // mov eax,1 ; ret 0x10  (return 1 = success; ret 0x10 = 4 args)
    "B8 01 00 00 00 C2 10 00",
    nullptr, {0}, 0
};

static bool ParseHexBytes(const char* s, BYTE* out, int maxLen, int* outLen) {
    int n = 0; const char* p = s;
    while (*p && n < maxLen) {
        while (*p == ' ') ++p;
        if (!*p) break;
        int hi = HexVal(*p++); if (hi < 0) return false;
        int lo = HexVal(*p++); if (lo < 0) return false;
        out[n++] = (BYTE)((hi << 4) | lo);
    }
    *outLen = n;
    return n > 0;
}

static void PatchMemory(void* addr, const BYTE* data, int len, BYTE* backup) {
    DWORD oldProt = 0;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProt)) return;
    if (backup) memcpy(backup, addr, len);
    memcpy(addr, data, len);
    VirtualProtect(addr, len, oldProt, &oldProt);
}

// ---------------------------------------------------------------------------
// Apply the single patch + re-seal
// ---------------------------------------------------------------------------
static int InstallPatch() {
    HMODULE netc = GetModuleHandleA("netc.dll");
    if (!netc) { Log("[NetHooks] netc.dll not loaded"); return 0; }

    uintptr_t addr = FindPattern("netc.dll", g_patch.pattern);
    if (!addr) { Log("[-] Not Found -> %s", g_patch.name); return 0; }
    Log("[+] Found -> %s @ %p", g_patch.name, (void*)addr);

    BYTE bytes[16]; int len = 0;
    if (!ParseHexBytes(g_patch.bytes, bytes, sizeof(bytes), &len)) {
        Log("[-] bad patch bytes"); return 0;
    }
    g_patch.addr = (void*)addr;
    g_patch.origLen = len;
    PatchMemory((void*)addr, bytes, len, g_patch.orig);
    Log("[+] Patched -> %s (mov eax,1; ret 0x10)", g_patch.name);

    // Re-seal: make C94_SealSelfMacWitnessed recompute the digest over the
    // now-patched image so the AC sees it as its own (avoids VF#2 Corrupted DLL).
    typedef int(__cdecl* Seal_t)(void);
    Seal_t seal = (Seal_t)GetProcAddress(netc, "C94_SealSelfMacWitnessed");
    if (seal) {
        Log("[NetHooks] re-sealing via C94_SealSelfMacWitnessed @ %p", (void*)seal);
        __try {
            int r = seal();
            Log("[NetHooks] re-seal returned %d", r);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("[NetHooks] re-seal threw (bad signature?)");
        }
    } else {
        Log("[NetHooks] WARN: C94_SealSelfMacWitnessed not found; seal not refreshed");
    }
    return 1;
}

static void RestorePatch() {
    if (g_patch.addr && g_patch.origLen > 0) {
        PatchMemory(g_patch.addr, g_patch.orig, g_patch.origLen, nullptr);
        Log("[NetHooks] restored %s", g_patch.name);
        g_patch.addr = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Hide module from PEB lists
// ---------------------------------------------------------------------------
static void HideModule(HMODULE hModule) {
    if (!hModule) return;
    auto base = reinterpret_cast<uintptr_t>(hModule);
#ifdef _WIN64
    uintptr_t peb = (uintptr_t)__readgsqword(0x60);
    uintptr_t ldr = peb ? *(uintptr_t*)(peb + 0x18) : 0;
#else
    uintptr_t peb = (uintptr_t)__readfsdword(0x30);
    uintptr_t ldr = peb ? *(uintptr_t*)(peb + 0x0C) : 0;
#endif
    if (!ldr) return;
    uintptr_t heads[3] = { ldr + 0x0C, ldr + 0x14, ldr + 0x1C };
    for (int li = 0; li < 3; ++li) {
        uintptr_t head = heads[li];
        uintptr_t e = *(uintptr_t*)head;
        int guard = 0;
        while (e && e != head && guard++ < 512) {
            bool found = false;
            for (uintptr_t off = 0; off < 0x60; off += sizeof(uintptr_t))
                if (*(uintptr_t*)(e + off) == base) { found = true; break; }
            if (found) {
                uintptr_t flink = *(uintptr_t*)(e);
                uintptr_t blink = *(uintptr_t*)(e + 4);
                *(uintptr_t*)(blink) = flink;
                *(uintptr_t*)(flink + 4) = blink;
                break;
            }
            e = *(uintptr_t*)(e);
        }
    }
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------
static std::atomic<bool> g_unload{ false };

static DWORD WINAPI MainThread(LPVOID param) {
    HMODULE hModule = (HMODULE)param;
    LogInit();
    Log("[NetHooks] DLL_PROCESS_ATTACH -> MainThread");

    HideModule(hModule);
    Log("[NetHooks] module hidden");

    // Wait for netc.dll, then patch+re-seal once.
    for (int i = 0; i < 600 && !g_unload.load(); ++i) {
        if (GetModuleHandleA("netc.dll")) {
            if (GetFileAttributesA("C:\\NetHooks_nohooks.txt") != INVALID_FILE_ATTRIBUTES) {
                Log("[NetHooks] nohooks flag -> patch skipped");
            } else {
                Log("[NetHooks] netc.dll detected, installing");
                InstallPatch();
            }
            break;
        }
        Sleep(100);
    }

    while (!(GetAsyncKeyState(VK_END) & 1)) {
        if (g_unload.load()) break;
        Sleep(50);
    }
    RestorePatch();
    Log("[NetHooks] exit");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
        g_unload.store(true);
    }
    return TRUE;
}

// Optional control exports
extern "C" __declspec(dllexport) int  __stdcall NetHooks_Install(void)  { return InstallPatch(); }
extern "C" __declspec(dllexport) void __stdcall NetHooks_Uninstall(void){ RestorePatch(); }
