#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d9.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <unordered_map>
#include <math.h>

#include "../third_party/SkipHook/skiphook.h"
#include "../third_party/imgui/imgui.h"
#include "../third_party/imgui/imgui_internal.h"
#include "../third_party/imgui/backends/imgui_impl_dx9.h"
#include "../third_party/imgui/backends/imgui_impl_win32.h"
#include "../third_party/imgui/addons/fontawesome/fontawesome.h"
#include "../third_party/imgui/addons/fontawesome/fonts.h"
#include "netc.h"

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

static_assert(sizeof(void*) == 4, "Win32/x86 only.");

static void out(WORD, const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
}
#define GREEN 0
#define RED   0
#define YELLOW 0
#define DEF   0

// ============================================================================
// Scanner
// ============================================================================
static void* scan_mask(HMODULE mod, const char* pattern, const char* mask, unsigned occurrence = 1) {
    if (!mod || !pattern || !mask) return nullptr;
    size_t len = strlen(mask);
    if (!len) return nullptr;

    uint8_t* base = (uint8_t*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    unsigned found = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint8_t* s = base + sec[i].VirtualAddress;
        size_t sz = sec[i].Misc.VirtualSize;
        if (sz < len) continue;
        size_t last = sz - len;
        for (size_t o = 0; o <= last; ++o) {
            bool ok = true;
            for (size_t k = 0; k < len; ++k) {
                if (mask[k] == '?') continue;
                if (s[o + k] != (unsigned char)pattern[k]) { ok = false; break; }
            }
            if (ok) {
                if (++found == occurrence) return s + o;
            }
        }
    }
    return nullptr;
}

// ============================================================================
// Originais MTA
// ============================================================================
using fn_send_packet    = bool(__fastcall*)(void*, void*, unsigned char, void*, int, int, int);
using fn_send_lua_check = int(__fastcall*)(DWORD*, void*, unsigned __int8);
using fn_sub_102BDFDE   = int(__cdecl*)(__int64*);

static fn_send_packet    g_o_send_packet    = nullptr;
static fn_send_lua_check g_o_send_lua_check = nullptr;
static fn_sub_102BDFDE   g_o_sub_102BDFDE   = nullptr;

// ============================================================================
// Detours MTA
// ============================================================================
static bool __cdecl d_advanced_memory_validator(int, int, int, DWORD*, int*, DWORD*) { return true; }
static int  __fastcall d_network_packet_state_validator(DWORD*, void*, int, unsigned __int8, unsigned __int16) { return 1; }
static char __stdcall  d_animation_packet_validator(int*) { return 1; }

static bool __fastcall d_send_packet(void* ECX, void* EDX, unsigned char ucPacketID, void* bitStream,
                                     int packetPriority, int packetReliability, int packetOrdering) {
    if (ucPacketID == 33) {
        if (packetReliability == 3) return true;
        if (packetReliability != 1 || !(*(DWORD**)0xBA18FC)) return true;
    }
    if (ucPacketID == 56 || ucPacketID == 71 || ucPacketID == 72 || ucPacketID == 34 ||
        ucPacketID == 91 || ucPacketID == 92 || ucPacketID == 93 || ucPacketID == 25 || ucPacketID == 110)
        return true;
    if (g_o_send_packet)
        return g_o_send_packet(ECX, EDX, ucPacketID, bitStream, packetPriority, packetReliability, packetOrdering);
    return false;
}

static int    __cdecl    d_send_report(char, void*, int, int, int) { return true; }
static HANDLE __stdcall  d_send_driver_report(LPCWSTR, ACCESS_MASK, DWORD, LPSECURITY_ATTRIBUTES, ULONG, ULONG) { return NULL; }
static void   __fastcall d_send_client_kick(int, int, unsigned int, int, DWORD*, int) {}
static void   __fastcall d_send_client_local_kick(int, char) {}
static void   __fastcall d_send_client_ban(int, int, int*, int*, char, int) {}

static int __fastcall d_send_lua_check(DWORD* instance, void* edx, unsigned __int8 checkFlag) {
    *(int*)(instance + 46) = 0;
    *(int*)(instance + 47) = 0;
    if (g_o_send_lua_check)
        return g_o_send_lua_check(instance, edx, checkFlag);
    return 0;
}

static void         __fastcall d_sub_10056A50(void*, void*) {}
static unsigned int __fastcall d_sub_10293EC0(void*, void*, int) { return 1; }
static int          __fastcall d_sub_10159D50(void*, void*) { return 1; }
static int          __cdecl    d_sub_10141000(void*) { return true; }
static int          __fastcall d_sub_101731D0(void*, void*, int, void*, int, const char*, const char*) { return 1; }
static bool         __cdecl    d_sub_1028CB90() { return true; }
static bool         __cdecl    d_detect_hook_new2(char*) { return false; }
static bool         __cdecl    d_detect_hook_new(char*) { return false; }
static char         __cdecl    d_detect_hook(char*) { return 0; }
static void         __cdecl    d_sub_1006CC80(const char*) {}
static char         __fastcall d_bypassnew(void*, void*, int, int) { return true; }
static int          __fastcall d_bypass(void*, void*, int, int) { return true; }
static int          __fastcall d_sub_new(unsigned int, void*, int) { return true; }
static int          __stdcall  d_send_crash_hook(int) { return 1; }

static int __cdecl d_sub_102BDFDE(__int64* a1) {
    static __int64 tempo = 0;
    if (tempo == 0 && g_o_sub_102BDFDE)
        g_o_sub_102BDFDE(&tempo);
    if (a1 != NULL) *a1 = tempo;
    return (int)tempo;
}

static unsigned int __fastcall d_sub_100D57B0(int, int, unsigned int) { return 0; }

static LONG  __stdcall d_veh_stack(void*)          { return 0; }
static DWORD __stdcall d_ac_start_watchdog(void*)  { return 0; }

// ============================================================================
// Patch JMP + Watchdog (re-hook a cada 2ms se removido)
// ============================================================================
struct PatchRecord {
    void*   addr;
    uint8_t original[5];
    void*   detour;
};

static PatchRecord g_patches[64];
static int         g_patch_count = 0;

static volatile LONG g_watchdog_stop = 0;
static HANDLE        g_watchdog_handle = nullptr;
static volatile LONG g_watchdog_repatch_count = 0;

template<typename T>
static bool patch_jmp(void* addr, T detour, T& original_out) {
    if (!addr || !detour) return false;
    T tramp = skip_hook::make_full_hook<T>((uint64_t)addr, 5);
    if (!tramp) return false;

    DWORD old = 0;
    if (!VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &old))
        return false;

    // Salva os bytes originais + o detour (para watchdog re-patchar)
    if (g_patch_count < 64) {
        g_patches[g_patch_count].addr = addr;
        memcpy(g_patches[g_patch_count].original, addr, 5);
        g_patches[g_patch_count].detour = (void*)detour;
        ++g_patch_count;
    }

    uint8_t* p = (uint8_t*)addr;
    p[0] = 0xE9;
    *(int32_t*)(p + 1) = (int32_t)((uintptr_t)detour - (uintptr_t)addr - 5);

    VirtualProtect(addr, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, 5);

    original_out = tramp;
    return true;
}

static void unpatch_all() {
    for (int i = 0; i < g_patch_count; ++i) {
        DWORD old = 0;
        if (VirtualProtect(g_patches[i].addr, 5, PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(g_patches[i].addr, g_patches[i].original, 5);
            VirtualProtect(g_patches[i].addr, 5, old, &old);
            FlushInstructionCache(GetCurrentProcess(), g_patches[i].addr, 5);
        }
    }
    g_patch_count = 0;
}

static DWORD WINAPI watchdog_thread(LPVOID) {
    while (InterlockedCompareExchange(&g_watchdog_stop, 0, 0) == 0) {
        Sleep(2);

        for (int i = 0; i < g_patch_count; ++i) {
            __try {
                PatchRecord& pr = g_patches[i];
                uint8_t* bytes = (uint8_t*)pr.addr;

                // Se o primeiro byte não é 0xE9, o hook foi removido/sobrescrito
                if (bytes[0] != 0xE9) {
                    bool matched_original = (memcmp(pr.addr, pr.original, 5) == 0);

                    DWORD old = 0;
                    if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &old)) {
                        bytes[0] = 0xE9;
                        *(int32_t*)(bytes + 1) = (int32_t)((uintptr_t)pr.detour - (uintptr_t)pr.addr - 5);
                        VirtualProtect(pr.addr, 5, old, &old);
                        FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);

                        LONG n = InterlockedIncrement(&g_watchdog_repatch_count);
                        if (n == 1 || (n % 100) == 0) {
                            char buf[128];
                            snprintf(buf, sizeof(buf),
                                "[watchdog] re-patched hook #%d (total=%d, original=%d)\n",
                                i, (int)n, matched_original ? 1 : 0);
                            OutputDebugStringA(buf);
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
    return 0;
}
#define FUNC_WORLD_IS_LOS_CLEAR      0x56A490
#define SESSION_HEARTBEAT_MS         600
#define RECONNECT_QUARANTINE_MS      5000
#define RECONNECT_BURST_COUNT        3
#define RECONNECT_BURST_WINDOW_MS    15000
#define LOS_RECHECK_MS               50
#define KICK_BOOT_GRACE_MS           5000
#define KICK_COOLDOWN_MS             30000
#define SWITCH_PARK_MS               4000

static volatile LONG g_session_live      = 0;
static uint32_t      g_session_live_tick = 0;
static volatile LONG g_silent_send_ok    = 0;
static uint32_t      g_reconnect_window  = 0;
static uint32_t      g_reconnect_count   = 0;
static uint32_t      g_quarantine_until  = 0;
static uint32_t      g_session_fail_reason = 0;
static bool          g_session_fail_logged = false;
static uint32_t      g_fail_log_tick       = 0;
static bool          g_fail_clean_done     = false;
static uint32_t      g_server_kick_seen    = 0;
static uint32_t      g_boot_tick           = 0;
static uint32_t      g_kick_last_tick      = 0;
static uint32_t      g_los_tick            = 0;
static uint32_t      g_los_avail_tick      = 0;
static bool          g_los_avail           = false;
static bool          g_los_cached          = false;
static bool          g_los_have_cache      = false;
static float         g_los_cache_a[3]      = {};
static float         g_los_cache_b[3]      = {};
static uint32_t      g_install_generation  = 0;
static uint32_t      g_install_done_generation = 0xFFFFFFFFu;
static uint32_t      g_install_count       = 0;
static uint32_t      g_switch_park_until   = 0;
static bool          g_switch_rebase_seen  = false;

static void silent_retire_hooks();
static void reconnect_note(uint32_t);
static void mta_logf(const char* tag, const char* fmt, ...);

static DWORD WINAPI session_heartbeat_thread(LPVOID) {
    while (!InterlockedCompareExchange(&g_watchdog_stop, 0, 0)) {
        Sleep(50);
        if (g_session_live_tick &&
            GetTickCount() - g_session_live_tick > SESSION_HEARTBEAT_MS) {
            InterlockedExchange(&g_session_live, 0);
            InterlockedExchange(&g_silent_send_ok, 0);
        }
    }
    return 0;
}

static void emergency_disable_all();
static void fly_physics_end();
static void rapid_fire_restore();

static uint32_t      g_netc_base          = 0;
static uint32_t      g_netc_size          = 0;
static bool          g_netc_rebase_logged = false;
static bool          g_netc_unload_logged = false;
static bool          g_netc_needs_reinstall = false;
static uint8_t       g_stale_patch_sink[64][8] = {};

static PatchRecord   g_quit_flush[64]         = {};
static int           g_quit_flush_count       = 0;
static bool          g_quit_flushed           = false;
static volatile LONG g_shutdown_all           = 0;
static volatile LONG g_emergency_done         = 0;

static void quit_flush() {
    if (g_quit_flushed) return;
    if (!g_netc_base || !g_netc_size) return;
    g_quit_flushed = true;
    g_quit_flush_count = 0;
    int w = 0;
    for (int i = 0; i < g_patch_count && i < 64; ++i) {
        PatchRecord pr = g_patches[i];
        uint32_t a = (uint32_t)(uintptr_t)pr.addr;
        if (a >= g_netc_base && a < g_netc_base + g_netc_size) {
            __try {
                DWORD oldp = 0;
                if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &oldp)) {
                    memcpy(pr.addr, pr.original, 5);
                    VirtualProtect(pr.addr, 5, oldp, &oldp);
                    FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
            if (g_quit_flush_count < 64) g_quit_flush[g_quit_flush_count++] = pr;
        } else {
            if (w != i) g_patches[w] = pr;
            ++w;
        }
    }
    g_patch_count = w;
    silent_retire_hooks();
    InterlockedExchange(&g_session_live, 0);
    InterlockedExchange(&g_silent_send_ok, 0);
    mta_logf("quit", "flush antes do Unload: %d hooks do netc restaurados, trajetoria retirada, watchdog sem alvos",
             g_quit_flush_count);
}

static void quit_unflush() {
    if (!g_quit_flushed) return;
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    g_quit_flushed = false;
    for (int i = 0; i < g_quit_flush_count; ++i) {
        PatchRecord pr = g_quit_flush[i];
        __try {
            uint8_t* p = (uint8_t*)pr.addr;
            if (p[0] == 0xE9) continue;
            DWORD oldp = 0;
            if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &oldp)) {
                p[0] = 0xE9;
                *(int32_t*)(p + 1) = (int32_t)((uintptr_t)pr.detour - (uintptr_t)pr.addr - 5);
                VirtualProtect(pr.addr, 5, oldp, &oldp);
                FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        if (g_patch_count < 64) g_patches[g_patch_count++] = pr;
    }
    g_quit_flush_count = 0;
    mta_logf("quit", "flush revertido: janela reapareceu, hooks religados sem novos trampolins");
}

static uint32_t netc_image_size(HMODULE mod) {
    if (!mod) return 0;
    __try {
        uint8_t* b = (uint8_t*)mod;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)b;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(b + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        return (uint32_t)nt->OptionalHeader.SizeOfImage;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static void netc_retire_stale_patches(uint32_t new_base, uint32_t new_size) {
    if (!g_netc_base || !g_netc_size) return;
    __try {
        for (int i = 0; i < g_patch_count && i < 64; ++i) {
            PatchRecord& pr = g_patches[i];
            uint32_t a = (uint32_t)(uintptr_t)pr.addr;
            if (!a || a < g_netc_base || a >= g_netc_base + g_netc_size) continue;
            if (new_base && new_size && a >= new_base && a < new_base + new_size) continue;
            memset(g_stale_patch_sink[i], 0xE9, sizeof(g_stale_patch_sink[i]));
            pr.addr = g_stale_patch_sink[i];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

static void install_all();

static PatchRecord   g_park_netc[64]       = {};
static int           g_park_netc_count     = 0;
static uint32_t      g_park_netc_base      = 0;

static void park_netc_hooks() {
    if (g_park_netc_count) return;
    if (!g_netc_base || !g_netc_size) return;
    g_park_netc_base = g_netc_base;
    for (int i = 0; i < g_patch_count && i < 64; ++i) {
        uint32_t a = (uint32_t)(uintptr_t)g_patches[i].addr;
        if (a >= g_netc_base && a < g_netc_base + g_netc_size &&
            g_park_netc_count < 64)
            g_park_netc[g_park_netc_count++] = g_patches[i];
    }
    silent_retire_hooks();
    mta_logf("safe", "troca de servidor: %d validadores do netc mantidos, hooks de trajetoria retirados",
             g_park_netc_count);
}

static void unpark_netc_hooks() {
    int restored = 0;
    for (int i = 0; i < g_park_netc_count; ++i) {
        PatchRecord pr = g_park_netc[i];
        __try {
            uint8_t* p = (uint8_t*)pr.addr;
            if (p[0] == 0xE9) continue;
            DWORD oldp = 0;
            if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &oldp)) {
                p[0] = 0xE9;
                *(int32_t*)(p + 1) = (int32_t)((uintptr_t)pr.detour - (uintptr_t)pr.addr - 5);
                VirtualProtect(pr.addr, 5, oldp, &oldp);
                FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);
                ++restored;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    g_park_netc_count = 0;
    mta_logf("safe", "troca de servidor: %d validadores reconfirmados sem novos trampolins",
             restored);
}

static void arm_switch_park(uint32_t now) {
    uint32_t t = now ? now : 1;
    if (g_netc_needs_reinstall) return;
    if (g_switch_park_until && (int32_t)(g_switch_park_until - t) > 0) return;
    park_netc_hooks();
    g_switch_park_until = t + SWITCH_PARK_MS;
    g_netc_needs_reinstall = true;
    g_switch_rebase_seen = false;
    reconnect_note(t);
}

static void netc_rebase_patches(uint32_t new_base, uint32_t new_size) {
    if (!new_base || !new_size) return;
    if (new_base != g_netc_base) {
        int w = 0;
        for (int i = 0; i < g_patch_count && i < 64; ++i) {
            uint32_t a = (uint32_t)(uintptr_t)g_patches[i].addr;
            if (a >= g_netc_base && a < g_netc_base + g_netc_size) continue;
            if (w != i) g_patches[w] = g_patches[i];
            ++w;
        }
        g_patch_count = w;
        g_park_netc_count = 0;
    }
    g_netc_base = new_base;
    g_netc_size = new_size;
    g_netc_needs_reinstall = true;
}

static bool g_cursor_hidden = false;
static bool g_menu_prev     = false;

static void menu_cursor_sync(bool open) {
    if (open == g_cursor_hidden) return;
    g_cursor_hidden = open;
    ShowCursor(open ? FALSE : TRUE);
    ClipCursor(nullptr);
}
#define MTA_LOG_PATH       "C:\\mta.log"
#define MTA_LOG_PATH_OLD   "C:\\mta.log.old"
#define MTA_LOG_MAX_BYTES  (512 * 1024)
static volatile LONG g_log_busy    = 0;
static char          g_log_path[MAX_PATH] = { 0 };

static const char* mta_log_path() {
    if (g_log_path[0]) return g_log_path;
    FILE* f = nullptr;
    if (fopen_s(&f, MTA_LOG_PATH, "ab") == 0 && f) {
        long sz = 0;
        FILE* r = nullptr;
        if (fopen_s(&r, MTA_LOG_PATH, "rb") == 0 && r) {
            fseek(r, 0, SEEK_END); sz = ftell(r); fclose(r);
        }
        fclose(f);
        if (sz > MTA_LOG_MAX_BYTES) {
            remove(MTA_LOG_PATH_OLD);
            rename(MTA_LOG_PATH, MTA_LOG_PATH_OLD);
        }
        _snprintf_s(g_log_path, sizeof(g_log_path), _TRUNCATE, "%s", MTA_LOG_PATH);
    } else {
        char tmp[MAX_PATH] = { 0 };
        if (GetTempPathA(MAX_PATH, tmp) > 0)
            _snprintf_s(g_log_path, sizeof(g_log_path), _TRUNCATE, "%smta.log", tmp);
        else
            _snprintf_s(g_log_path, sizeof(g_log_path), _TRUNCATE, ".\\mta.log");
    }
    return g_log_path;
}

static bool mta_log_tick(int ch, DWORD ms) {
    static DWORD last[8] = { 0 };
    if (ch < 0 || ch >= 8) return true;
    DWORD now = GetTickCount();
    if (last[ch] && (now - last[ch]) < ms) return false;
    last[ch] = now ? now : 1;
    return true;
}

static void mta_logf(const char* tag, const char* fmt, ...) {
    if (InterlockedCompareExchange(&g_log_busy, 1, 0) != 0) return;
    char msg[768];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, ap);
    va_end(ap);
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    char line[1024];
    int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
        "[%02u:%02u:%02u.%03u][p%u/t%u][%10u][%s] %s\n",
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
        (unsigned)st.wMilliseconds,
        (unsigned)GetCurrentProcessId(), (unsigned)GetCurrentThreadId(),
        (unsigned)GetTickCount(), tag ? tag : "log", msg);
    if (n < 0) line[sizeof(line) - 1] = '\0';
    OutputDebugStringA(line);
    FILE* f = nullptr;
    if (fopen_s(&f, mta_log_path(), "a") == 0 && f) { fputs(line, f); fclose(f); }
    InterlockedExchange(&g_log_busy, 0);
}

static const ImU32 COL_ACCENT      = IM_COL32(136, 100, 255, 255);
static const ImU32 COL_ACCENT_DIM  = IM_COL32(136, 100, 255, 60);
static const ImU32 COL_ACCENT_SOFT = IM_COL32(160, 130, 255, 255);
static const ImU32 COL_BG_PANEL    = IM_COL32(12, 12, 14, 245);
static const ImU32 COL_BG_HEADER   = IM_COL32(20, 20, 26, 255);
static const ImU32 COL_BG_SIDEBAR  = IM_COL32(16, 16, 20, 255);
static const ImU32 COL_BG_CARD     = IM_COL32(18, 18, 24, 255);
static const ImU32 COL_BORDER      = IM_COL32(40, 40, 50, 255);
static const ImU32 COL_TEXT        = IM_COL32(230, 230, 235, 255);
static const ImU32 COL_TEXT_DIM    = IM_COL32(120, 120, 130, 255);

enum MenuTab {
    TAB_COMBAT = 0,
    TAB_VISUALS,
    TAB_MISC,
    TAB_TROLL,
    TAB_COUNT
};

static bool  g_menu_open       = true;
static bool  g_prev_insert     = false;
static bool  g_prev_menu_open  = false;

static int   g_current_tab     = TAB_VISUALS;
static int   g_anim_tab        = TAB_VISUALS;
static float g_tab_alpha       = 1.0f;

static ImVec2 g_menu_pos       = ImVec2(0, 0);
static ImVec2 g_menu_size      = ImVec2(640, 420);

static bool  g_esp_local_enable  = false;
static bool  g_esp_local_box     = false;
static bool  g_esp_local_box_filled = false;
static bool  g_esp_local_lines   = false;
static bool  g_esp_local_names   = false;
static bool  g_esp_local_health  = false;
static bool  g_esp_local_health_dynamic = false;
static bool  g_esp_local_armor   = false;
static bool  g_esp_local_skeleton= false;
static bool  g_esp_local_distance = true;

static float g_col_local_box[4]      = { 1.0f, 1.0f, 1.0f, 1.0f };
static float g_col_local_lines[3]    = { 1.0f, 1.0f, 1.0f };
static float g_col_local_names[3]    = { 1.0f, 1.0f, 1.0f };
static float g_col_local_health[3]   = { 0.0f, 1.0f, 0.0f };
static float g_col_local_armor[3]    = { 0.0f, 0.63f, 1.0f };
static float g_col_local_skeleton[3] = { 1.0f, 1.0f, 1.0f };
static float g_col_local_distance[3] = { 1.0f, 1.0f, 1.0f };

static bool  g_esp_players_enable  = false;
static bool  g_esp_players_box     = false;
static bool  g_esp_players_box_filled = false;
static bool  g_esp_players_lines   = false;
static bool  g_esp_players_names   = false;
static bool  g_esp_players_health  = false;
static bool  g_esp_players_health_dynamic = false;
static bool  g_esp_players_armor   = false;
static bool  g_esp_players_skeleton= false;
static bool  g_esp_players_distance = true;

static float g_col_players_box[4]      = { 1.0f, 1.0f, 1.0f, 1.0f };
static float g_col_players_lines[3]    = { 1.0f, 1.0f, 1.0f };
static float g_col_players_names[3]    = { 1.0f, 1.0f, 1.0f };
static float g_col_players_health[3]   = { 0.0f, 1.0f, 0.0f };
static float g_col_players_armor[3]    = { 0.0f, 0.63f, 1.0f };
static float g_col_players_skeleton[3] = { 1.0f, 1.0f, 1.0f };
static float g_col_players_distance[3] = { 1.0f, 1.0f, 1.0f };

#define ESP_NAME_FONT_SIZE   15.0f

#define ESP_TEXT_STROKE        1.0f
#define ESP_TEXT_STROKE_ALPHA  200

#define ESP_SHOW_UNRESOLVED_NAME 0

#define ESP_SKELETON_THICKNESS  1.0f

static bool session_live() {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return false;
    if (!InterlockedCompareExchange(&g_session_live, 0, 0)) return false;
    uint32_t t = g_session_live_tick;
    if (!t || GetTickCount() - t > SESSION_HEARTBEAT_MS) return false;
    return true;
}
static bool          g_emergency_logged  = false;

static int      g_menu_key_vk        = VK_INSERT;
static char     g_menu_key_name[32] = "Insert";
static bool     g_menu_key_latch     = false;
static uint32_t g_menu_toggle_tick   = 0;
static volatile LONG g_menu_toggle_pending = 0;
static int      g_fly_key_vk         = VK_F8;
static char     g_fly_key_name[32]  = "F8";
static bool     g_fly_key_prev       = false;
static bool     g_fly_key_held       = false;
static int      g_bind_capture       = 0;
static uint32_t g_bind_capture_tick  = 0;

#define FLY_MODE_HOLD      0
#define FLY_MODE_TOGGLE    1
#ifndef VK_SHIFT
#define VK_SHIFT 0x10
#endif
static bool  g_fly_enable       = false;
static bool  g_rapid_fire_enable = false;
static float g_rapid_fire_rate   = 1.0f;
static bool  g_rf_patched        = false;
static float g_rf_applied_rate   = 0.0f;
static uint32_t g_rf_tick        = 0;
#define ADDR_WEAPON_INFO_ARRAY   0xC8AAB8
#define ADDR_WEAPON_INFO_ALT     0xC8AB38
#define FUNC_GET_WEAPON_INFO     0x743C60
#define WEAPON_INFO_STRIDE       0x70
#define RF_TABLE_MAX_ENTRIES     80
#define RF_SKILL_COUNT           4
#define WI_OFF_SLOT              0x14
#define WI_OFF_FLAGS             0x18
#define WI_OFF_AMMO_CLIP         0x20
#define WI_OFF_ANIM_LOOP_START   0x40
#define WI_OFF_ANIM_LOOP_END     0x44
#define WI_OFF_ANIM_LOOP_FIRE    0x48
#define WI_OFF_ANIM_LOOP2_START  0x4C
#define WI_OFF_ANIM_LOOP2_END    0x50
#define WI_OFF_ANIM_LOOP2_FIRE   0x54
#define RF_FIRE_ANIM_MIN         22
#define RF_FIRE_ANIM_MAX         34
struct RFWeaponSave {
    float    start, end, start2, end2, fire, fire2;
    uint32_t ptr;
    bool     ok;
};
static RFWeaponSave g_rf_save[RF_SKILL_COUNT][35] = {};
static uint32_t g_rf_table        = 0;
static bool     g_rf_table_tried  = false;
static bool     g_rf_probe_logged = false;
static bool     g_rf_src_fn       = false;
static float    g_rf_last_window  = 0.0f;
static uint32_t g_rf_rewrites     = 0;
static bool  g_fly_active       = false;
static float g_fly_speed        = 12.0f;
static int   g_fly_mode         = FLY_MODE_HOLD;
static float g_fly_pitch_base   = 0.0f;
static bool  g_fly_pitch_init   = false;
static int   g_fly_pitch_axis   = -1;
static bool  g_fly_toggle_on    = false;
static bool  g_fly_key_edge     = false;
static bool  g_fly_hover_valid  = false;
static float g_fly_hover_pos[3] = { 0.0f, 0.0f, 0.0f };
static bool  g_fly_phys_saved    = false;
static uint32_t g_fly_phys_flags  = 0;
static uint32_t g_fly_phys_ped    = 0;
static float g_fly_hp_saved       = 100.0f;
static float g_fly_armor_saved    = 0.0f;
static int   g_fly_axis_idx       = -1;


#define WDA_NONE_VALUE            0x00000000
#define WDA_MONITOR_VALUE         0x00000001
#define WDA_EXCLUDEFROMCAPTURE_V  0x00000011
static bool     g_stream_proof         = true;   // default ON: WDA_EXCLUDEFROMCAPTURE no boot
static bool     g_stream_proof_ok      = true;
static bool     g_stream_proof_ready   = false;
static DWORD    g_stream_proof_applied = WDA_NONE_VALUE;
static HWND     g_stream_proof_hwnd    = nullptr;
static uint32_t g_stream_proof_last_try = 0;

#define CFG_NAME_MAX   32
#define CFG_MAX_FILES  64
static char  g_cfg_dir[MAX_PATH]                  = {};
static char  g_cfg_input[CFG_NAME_MAX + 1]        = {};
static char  g_cfg_names[CFG_MAX_FILES][CFG_NAME_MAX + 1] = {};
static int   g_cfg_count       = 0;
static int   g_cfg_selected    = -1;
static char  g_cfg_status[160] = "Nenhuma config carregada.";
static bool  g_cfg_status_ok   = true;
static bool  g_cfg_pending_overwrite = false;
static bool  g_cfg_pending_delete    = false;

static void notify_push(const char*, const char*, bool, const char*, ...);

static void cfg_status(bool ok, const char* fmt, ...) {
    g_cfg_status_ok = ok;
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(g_cfg_status, sizeof(g_cfg_status), _TRUNCATE, fmt, ap);
    va_end(ap);
    mta_logf(ok ? "cfg" : "cfg!", "%s", g_cfg_status);
    notify_push("Config", ICON_FA_COG, ok, "%s", g_cfg_status);
}

static const char* cfg_get_dir() {
    if (g_cfg_dir[0]) return g_cfg_dir;
    char app[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableA("APPDATA", app, MAX_PATH);
    if (!n || n >= MAX_PATH) {
        if (!GetTempPathA(MAX_PATH, app) || !app[0]) return nullptr;
    }
    _snprintf_s(g_cfg_dir, sizeof(g_cfg_dir), _TRUNCATE, "%s\\Hijacking", app);
    CreateDirectoryA(g_cfg_dir, nullptr);
    return g_cfg_dir;
}

static int cfg_ieq(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

static bool cfg_valid_name(const char* s, char* why, size_t why_sz) {
    if (!s || !s[0]) { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Digite um nome para salvar."); return false; }
    size_t n = strlen(s);
    if (n > CFG_NAME_MAX) { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Maximo de %d caracteres.", CFG_NAME_MAX); return false; }
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ' ';
        if (!ok) { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Use apenas letras, numeros, _ - e espaco."); return false; }
    }
    if (s[0] == ' ' || s[n - 1] == ' ') { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Sem espaco no inicio/fim."); return false; }
    static const char* reserved[] = { "CON","PRN","AUX","NUL","CLOCK$",
        "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
        "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9", nullptr };
    for (int i = 0; reserved[i]; ++i)
        if (cfg_ieq(s, reserved[i])) { if (why) _snprintf_s(why, why_sz, _TRUNCATE, "Nome reservado pelo Windows."); return false; }
    return true;
}

static bool cfg_make_path(const char* name, char* out, size_t out_sz) {
    const char* d = cfg_get_dir();
    if (!d) return false;
    int n = _snprintf_s(out, out_sz, _TRUNCATE, "%s\\%s.hcfg", d, name);
    return n > 0;
}

static bool cfg_exists(const char* name) {
    char path[MAX_PATH];
    if (!cfg_make_path(name, path, sizeof(path))) return false;
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void cfg_scan(bool force = false) {
    static uint32_t last_scan = 0;
    uint32_t now = GetTickCount();
    if (!force && last_scan && now - last_scan < 2000) return;
    last_scan = now ? now : 1;
    g_cfg_count = 0;
    const char* d = cfg_get_dir();
    if (!d) return;
    char pat[MAX_PATH];
    _snprintf_s(pat, sizeof(pat), _TRUNCATE, "%s\\*.hcfg", d);
    WIN32_FIND_DATAA fd = {};
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) { g_cfg_selected = -1; return; }
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        const char* dot = strrchr(fd.cFileName, '.');
        if (!dot || strcmp(dot, ".hcfg") != 0) continue;
        size_t n = (size_t)(dot - fd.cFileName);
        if (n == 0 || n > CFG_NAME_MAX || g_cfg_count >= CFG_MAX_FILES) continue;
        memcpy(g_cfg_names[g_cfg_count], fd.cFileName, n);
        g_cfg_names[g_cfg_count][n] = '\0';
        ++g_cfg_count;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (g_cfg_selected >= g_cfg_count) g_cfg_selected = g_cfg_count ? 0 : -1;
}

static bool cfg_name_combo(const char** items, int count) {
    static char joined[CFG_MAX_FILES * (CFG_NAME_MAX + 2)] = {};
    joined[0] = '\0';
    size_t at = 0;
    for (int i = 0; i < count && i < CFG_MAX_FILES; ++i) {
        size_t l = strlen(g_cfg_names[i]);
        if (at + l + 1 >= sizeof(joined)) break;
        memcpy(joined + at, g_cfg_names[i], l);
        at += l; joined[at++] = '\0';
    }
    joined[at] = '\0';
    *items = joined;
    return true;
}

static void bind_format_key(int vk, char* out, size_t sz) {
    const char* fixed = nullptr;
    switch (vk) {
    case VK_LBUTTON: fixed = "Mouse1"; break;
    case VK_RBUTTON: fixed = "Mouse2"; break;
    case VK_MBUTTON: fixed = "Mouse3"; break;
    case VK_XBUTTON1: fixed = "Mouse4"; break;
    case VK_XBUTTON2: fixed = "Mouse5"; break;
    case VK_INSERT: fixed = "Insert"; break;
    case VK_DELETE: fixed = "Delete"; break;
    case VK_HOME: fixed = "Home"; break;
    case VK_SHIFT: fixed = "Shift"; break;
    case VK_CONTROL: fixed = "Ctrl"; break;
    case VK_MENU: fixed = "Alt"; break;
    case VK_SPACE: fixed = "Space"; break;
    case VK_RETURN: fixed = "Enter"; break;
    case VK_BACK: fixed = "Back"; break;
    case VK_TAB: fixed = "Tab"; break;
    case VK_CAPITAL: fixed = "Caps"; break;
    case VK_ESCAPE: fixed = "Esc"; break;
    }
    if (fixed) { _snprintf_s(out, sz, _TRUNCATE, "%s", fixed); return; }
    if (vk >= VK_F1 && vk <= VK_F12) { _snprintf_s(out, sz, _TRUNCATE, "F%d", vk - VK_F1 + 1); return; }
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) { _snprintf_s(out, sz, _TRUNCATE, "Num%d", vk - VK_NUMPAD0); return; }
    UINT scan = MapVirtualKeyA((UINT)vk, MAPVK_VK_TO_VSC);
    char nm[64] = {};
    int n = GetKeyNameTextA((LONG)(scan << 16), nm, (int)sizeof(nm) - 1);
    if (n > 0 && nm[0] && nm[0] != ' ') _snprintf_s(out, sz, _TRUNCATE, "%s", nm);
    else if ((vk >= 'A' && vk <= 'Z') || (vk >= '0' && vk <= '9')) _snprintf_s(out, sz, _TRUNCATE, "%c", (char)vk);
    else _snprintf_s(out, sz, _TRUNCATE, "VK %02X", (unsigned)vk);
}

static void bind_set_key(int which, int vk) {
    if (vk <= 0 || vk > 255) return;
    if      (which == 2) { g_menu_key_vk = vk; bind_format_key(vk, g_menu_key_name, sizeof(g_menu_key_name)); }
    else if (which == 3) { g_fly_key_vk = vk; bind_format_key(vk, g_fly_key_name, sizeof(g_fly_key_name)); }
    g_fly_toggle_on = false;
    g_fly_key_edge = false;
    g_fly_hover_valid = false;
    g_bind_capture = 0;
    g_bind_capture_tick = 0;
    g_menu_key_latch = (GetAsyncKeyState(g_menu_key_vk) & 0x8000) != 0;
    g_fly_key_prev = false;
    mta_logf("bind", "which=%d vk=%02X nome=%s", which, (unsigned)vk,
             which == 2 ? g_menu_key_name : g_fly_key_name);
}

static bool bind_is_down(int vk) {
    if (vk <= 0 || vk > 255) return false;
    return (GetAsyncKeyState(vk) & 0x8000) != 0;
}

typedef BOOL (WINAPI* SetWindowDisplayAffinityFn)(HWND, DWORD);
static bool set_display_affinity(HWND hwnd, DWORD aff) {
    if (!hwnd) return false;
    HMODULE u = GetModuleHandleA("user32.dll");
    if (!u) return false;
    SetWindowDisplayAffinityFn fn =
        (SetWindowDisplayAffinityFn)(void*)GetProcAddress(u, "SetWindowDisplayAffinity");
    if (!fn) return false;
    return fn(hwnd, aff) != FALSE;
}

static char  g_local_nick[64]  = "Local Player";

static bool  g_aimbot_enable     = false;
static bool  g_aimbot_show_fov   = false;
static float g_aimbot_fov_col[3] = { 1.0f, 1.0f, 1.0f };
static float g_aimbot_fov_size   = 120.0f;
static float g_aimbot_smooth     = 10.0f;
static int   g_aimbot_bone       = 0;
static bool  g_aimbot_center_dot = false;
static bool  g_aimbot_show_target= true;
static const char AIMBOT_BONE_ITEMS[] =
    "Head\0Neck\0Chest\0Right Arm\0Left Arm\0Left Leg\0Right Leg\0";

#define AIMBOT_KEY_HOLD_MODE       1
#define AIMBOT_AIM_MODE            0
#define AIMBOT_MOUSE_SENS          1.0f
#define AIMBOT_SNAP_MAX_PIXELS  1600.0f
#define AIMBOT_CAM_YAW_SIGN        1.0f
#define AIMBOT_CAM_PITCH_SIGN      1.0f
#define AIMBOT_ONLY_REAL_PLAYERS   0
#define AIMBOT_CENTER_DOT_RADIUS   1.2f

#define SILENT_FIRE_INSTANT_HIT   0x73FB10
#define NETC_GRACE_MS             2500
#define MTA_FIRE_MID_POS          0x740B89
#define MTA_FIRE_MID_END          0x10
#define MTA_FIRE_MID_START        0x38
#define MTA_SNIPER_MID_POS        0x73AE31
#define MTA_SNIPER_MID_END        0x3C
#define MTA_PACKET_BULLETSYNC     98

static bool  g_silent_enable       = false;
static bool  g_silent_show_fov     = true;
static float g_silent_fov_col[3]   = { 1.0f, 0.0f, 0.0f };
static float g_silent_fov_size     = 70.0f;
static int   g_silent_bone         = 0;
static bool  g_silent_center_dot   = false;
static bool  g_silent_show_target  = true;
static int   g_silent_key_vk       = VK_XBUTTON2;
static char  g_silent_key_name[32] = "Mouse5";
static bool  g_silent_capturing    = false;
static bool  g_silent_aim_on       = false;
static bool  g_silent_has_target   = false;
static float g_silent_target_sx    = 0.0f;
static float g_silent_target_sy    = 0.0f;
static volatile float g_silent_aim_point[3] = {};
static void* g_o_FireInstantHit    = nullptr;
static bool  g_silent_hook_ok      = false;
static void* g_o_mta_fire_mid      = nullptr;
static void* g_o_mta_sniper_mid    = nullptr;
static bool  g_silent_mid_ok        = false;
static bool  g_silent_sniper_ok     = false;
static bool  g_silent_mid_logged    = false;
static bool  g_silent_sniper_logged = false;
static bool  g_silent_ignore_walls = false;
static bool  g_los_logged          = false;
static uint32_t g_conn_grace       = 0;
static bool  g_conn_prev_active    = false;

static bool conn_handshake_active() {
    uint32_t t = g_conn_grace;
    if (!t) return false;
    if (GetTickCount() - t < NETC_GRACE_MS) return true;
    g_conn_grace = 0;
    return false;
}

#ifdef ICON_FA_KEYBOARD
#define AIMBOT_ICON_KEYBOARD  ICON_FA_KEYBOARD
#else
#define AIMBOT_ICON_KEYBOARD  "\xEF\x84\x9C"
#endif
#define TROLL_ICON_GLYPH "\xEF\x96\x88"

static int      g_aimbot_key_vk       = VK_XBUTTON1;
static char     g_aimbot_key_name[32] = "Mouse4";
static bool     g_aimbot_key_is_mouse = true;
static bool     g_aimbot_capturing    = false;
static uint32_t g_aimbot_capture_tick = 0;
static bool     g_aimbot_key_held     = false;
static uint32_t g_aimbot_held_tick    = 0;
static bool     g_aimbot_aim_on       = false;
static bool     g_aimbot_has_target   = false;
static float    g_aimbot_target_sx    = 0.0f;
static float    g_aimbot_target_sy    = 0.0f;

static void session_fail_closed(uint32_t reason) {
    uint32_t now = GetTickCount();
    InterlockedExchange(&g_session_live, 0);
    g_session_live_tick = 0;
    InterlockedExchange(&g_silent_send_ok, 0);
    g_silent_aim_on = g_silent_has_target = false;
    g_aimbot_aim_on = g_aimbot_has_target = false;
    if (!g_fail_clean_done) {
        g_fail_clean_done = true;
        fly_physics_end();
        rapid_fire_restore();
    }
    if ((!g_session_fail_logged || g_session_fail_reason != reason) &&
        (!g_fail_log_tick || now - g_fail_log_tick > 1000)) {
        g_session_fail_logged = true;
        g_session_fail_reason = reason;
        g_fail_log_tick = now ? now : 1;
        mta_logf("safe", "fail-closed motivo=%u: trajetoria, mira e packet desligados",
                 (unsigned)reason);
    }
}

static void reconnect_note(uint32_t now) {
    uint32_t t = now ? now : 1;
    if (g_quarantine_until &&
        (t - g_quarantine_until < RECONNECT_QUARANTINE_MS))
        return;
    if (!g_reconnect_window ||
        t - g_reconnect_window > RECONNECT_BURST_WINDOW_MS) {
        g_reconnect_window = t;
        g_reconnect_count = 0;
    }
    ++g_reconnect_count;
    if (g_reconnect_count >= RECONNECT_BURST_COUNT) {
        g_quarantine_until = t;
        g_reconnect_count = 0;
        mta_logf("safe", "quarentena %ums: %u trocas de servidor em %ums",
                 (unsigned)RECONNECT_QUARANTINE_MS,
                 (unsigned)RECONNECT_BURST_COUNT,
                 (unsigned)RECONNECT_BURST_WINDOW_MS);
    }
}

static void aimbot_set_key(int vk) {
    g_aimbot_key_vk = vk;
    g_aimbot_key_is_mouse =
        (vk == VK_LBUTTON || vk == VK_RBUTTON || vk == VK_MBUTTON ||
         vk == VK_XBUTTON1 || vk == VK_XBUTTON2);

    const char* fixed = nullptr;
    switch (vk) {
    case VK_LBUTTON:  fixed = "Mouse1"; break;
    case VK_RBUTTON:  fixed = "Mouse2"; break;
    case VK_MBUTTON:  fixed = "Mouse3"; break;
    case VK_XBUTTON1: fixed = "Mouse4"; break;
    case VK_XBUTTON2: fixed = "Mouse5"; break;
    case VK_SHIFT:    fixed = "Shift";  break;
    case VK_CONTROL:  fixed = "Ctrl";   break;
    case VK_MENU:     fixed = "Alt";    break;
    case VK_SPACE:    fixed = "Space";  break;
    case VK_RETURN:   fixed = "Enter";  break;
    case VK_BACK:     fixed = "Back";   break;
    case VK_TAB:      fixed = "Tab";    break;
    case VK_CAPITAL:  fixed = "Caps";   break;
    case VK_ESCAPE:   fixed = "Esc";    break;
    }
    if (fixed) {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "%s", fixed);
        return;
    }
    if (vk >= VK_F1 && vk <= VK_F12) {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "F%d", vk - VK_F1 + 1);
        return;
    }
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "Num%d", vk - VK_NUMPAD0);
        return;
    }
    UINT scan = MapVirtualKeyA((UINT)vk, MAPVK_VK_TO_VSC);
    char nm[64] = {};
    int n = GetKeyNameTextA((LONG)(scan << 16), nm, (int)sizeof(nm) - 1);
    if (n > 0 && nm[0] && nm[0] != ' ') {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "%s", nm);
    } else if ((vk >= 'A' && vk <= 'Z') || (vk >= '0' && vk <= '9')) {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "%c", (char)vk);
    } else {
        snprintf(g_aimbot_key_name, sizeof(g_aimbot_key_name), "VK %02X", (unsigned)vk);
    }
}

static void aimbot_stop_capture() {
    g_aimbot_capturing    = false;
    g_aimbot_capture_tick = 0;
    g_aimbot_key_held     = false;
    g_aimbot_aim_on       = false;
}

static void aimbot_poll_capture() {
    if (!g_aimbot_capturing) return;

    static bool     armed = false;
    static bool     was_down[256] = {};
    static uint32_t start = 0;

    if (g_aimbot_capture_tick == 0) {
        g_aimbot_capture_tick = GetTickCount();
        start = g_aimbot_capture_tick;
        armed = false;
        return;
    }
    if (GetTickCount() - start > 8000) { aimbot_stop_capture(); return; }

    if (!armed) {
        for (int i = 0; i < 256; ++i)
            was_down[i] = (GetAsyncKeyState(i) & 0x8000) != 0;
        if ((GetAsyncKeyState(VK_LBUTTON) & 0x8000) == 0) {
            armed = true;
            was_down[VK_LBUTTON] = false;
        }
        return;
    }

    if ((GetAsyncKeyState(VK_ESCAPE) & 0x8000) != 0 && !was_down[VK_ESCAPE]) {
        aimbot_stop_capture();
        return;
    }
    for (int vk = 1; vk < 256; ++vk) {
        if (vk == VK_ESCAPE || was_down[vk]) continue;
        if ((GetAsyncKeyState(vk) & 0x8000) != 0) {
            aimbot_set_key(vk);
            aimbot_stop_capture();
            return;
        }
    }
}

static bool aimbot_is_key_down() {
    const bool async = (GetAsyncKeyState(g_aimbot_key_vk) & 0x8000) != 0;
    if (async) return true;
    if (!g_aimbot_key_held) return false;
    if (GetTickCount() - g_aimbot_held_tick > 4000) {
        g_aimbot_key_held = false;
        return false;
    }
    return g_aimbot_key_is_mouse;
}

static void aimbot_update_key() {
    const bool held = aimbot_is_key_down() && !g_aimbot_capturing;
#if AIMBOT_KEY_HOLD_MODE
    g_aimbot_aim_on = held;
#else
    static bool prev = false;
    if (held && !prev) g_aimbot_aim_on = !g_aimbot_aim_on;
    prev = held;
#endif
    if (!g_aimbot_enable) g_aimbot_aim_on = false;
}

static ImFont* g_font_regular   = nullptr;
static ImFont* g_font_header    = nullptr;
static ImFont* g_font_esp_name  = nullptr;
static ImFont* g_font_icons     = nullptr;
static float   g_icon_font_size = 20.0f;
static std::unordered_map<ImGuiID, float> g_check_anim;

enum { CFG_BOOL = 0, CFG_FLOAT = 1, CFG_INT = 2, CFG_COL3 = 3, CFG_COL4 = 4 };
struct CfgEntry { const char* key; void* ptr; int type; };
static const CfgEntry CFG_ENTRIES[] = {
    { "esp.local.enable",     &g_esp_local_enable,     CFG_BOOL  },
    { "esp.local.box",        &g_esp_local_box,        CFG_BOOL  },
    { "esp.local.filled",     &g_esp_local_box_filled, CFG_BOOL  },
    { "esp.local.lines",      &g_esp_local_lines,      CFG_BOOL  },
    { "esp.local.names",      &g_esp_local_names,      CFG_BOOL  },
    { "esp.local.health",     &g_esp_local_health,     CFG_BOOL  },
    { "esp.local.healthdyn",  &g_esp_local_health_dynamic, CFG_BOOL },
    { "esp.local.armor",      &g_esp_local_armor,      CFG_BOOL  },
    { "esp.local.skeleton",   &g_esp_local_skeleton,   CFG_BOOL  },
    { "esp.local.distance",   &g_esp_local_distance,   CFG_BOOL  },
    { "esp.local.colbox",     g_col_local_box,         CFG_COL4  },
    { "esp.local.collines",   g_col_local_lines,       CFG_COL3  },
    { "esp.local.colnames",   g_col_local_names,       CFG_COL3  },
    { "esp.local.colhealth",  g_col_local_health,      CFG_COL3  },
    { "esp.local.colarmor",   g_col_local_armor,       CFG_COL3  },
    { "esp.local.colskel",    g_col_local_skeleton,    CFG_COL3  },
    { "esp.local.coldist",    g_col_local_distance,    CFG_COL3  },
    { "esp.players.enable",   &g_esp_players_enable,   CFG_BOOL  },
    { "esp.players.box",      &g_esp_players_box,      CFG_BOOL  },
    { "esp.players.filled",   &g_esp_players_box_filled, CFG_BOOL },
    { "esp.players.lines",    &g_esp_players_lines,    CFG_BOOL  },
    { "esp.players.names",    &g_esp_players_names,    CFG_BOOL  },
    { "esp.players.health",   &g_esp_players_health,   CFG_BOOL  },
    { "esp.players.healthdyn",&g_esp_players_health_dynamic, CFG_BOOL },
    { "esp.players.armor",    &g_esp_players_armor,    CFG_BOOL  },
    { "esp.players.skeleton", &g_esp_players_skeleton, CFG_BOOL  },
    { "esp.players.distance", &g_esp_players_distance, CFG_BOOL  },
    { "esp.players.colbox",   g_col_players_box,       CFG_COL4  },
    { "esp.players.collines", g_col_players_lines,     CFG_COL3  },
    { "esp.players.colnames", g_col_players_names,     CFG_COL3  },
    { "esp.players.colhealth",g_col_players_health,    CFG_COL3  },
    { "esp.players.colarmor", g_col_players_armor,     CFG_COL3  },
    { "esp.players.colskel",  g_col_players_skeleton,  CFG_COL3  },
    { "esp.players.coldist",  g_col_players_distance,  CFG_COL3  },
    { "aim.enable",           &g_aimbot_enable,        CFG_BOOL  },
    { "aim.showfov",          &g_aimbot_show_fov,      CFG_BOOL  },
    { "aim.centerdot",        &g_aimbot_center_dot,    CFG_BOOL  },
    { "aim.showtarget",       &g_aimbot_show_target,   CFG_BOOL  },
    { "aim.fovsize",          &g_aimbot_fov_size,      CFG_FLOAT },
    { "aim.smooth",           &g_aimbot_smooth,        CFG_FLOAT },
    { "aim.bone",             &g_aimbot_bone,          CFG_INT   },
    { "aim.fovcol",           g_aimbot_fov_col,        CFG_COL3  },
    { "aim.key",              &g_aimbot_key_vk,        CFG_INT   },
    { "sil.enable",           &g_silent_enable,        CFG_BOOL  },
    { "sil.showfov",          &g_silent_show_fov,      CFG_BOOL  },
    { "sil.centerdot",        &g_silent_center_dot,    CFG_BOOL  },
    { "sil.showtarget",       &g_silent_show_target,   CFG_BOOL  },
    { "sil.fovsize",          &g_silent_fov_size,      CFG_FLOAT },
    { "sil.bone",             &g_silent_bone,          CFG_INT   },
    { "sil.fovcol",           g_silent_fov_col,        CFG_COL3  },
    { "sil.key",              &g_silent_key_vk,        CFG_INT   },
    { "sil.ignorewalls",       &g_silent_ignore_walls,  CFG_BOOL  },
    { "misc.menukey",         &g_menu_key_vk,          CFG_INT   },
    { "misc.flyenable",       &g_fly_enable,           CFG_BOOL  },
    { "misc.flykey",          &g_fly_key_vk,           CFG_INT   },
    { "misc.flyspeed",        &g_fly_speed,            CFG_FLOAT },
    { "misc.flymode",         &g_fly_mode,            CFG_INT   },
    { "misc.streamproof",     &g_stream_proof,         CFG_BOOL  },
    { "troll.rapidfire",      &g_rapid_fire_enable,    CFG_BOOL  },
    { "troll.firerate",       &g_rapid_fire_rate,      CFG_FLOAT },
};
static const int CFG_ENTRY_COUNT = (int)(sizeof(CFG_ENTRIES) / sizeof(CFG_ENTRIES[0]));

static float cfg_clampf(float v, float lo, float hi) { return v < lo ? lo : (v > hi ? hi : v); }

static bool cfg_save(const char* name) {
    char why[128];
    if (!cfg_valid_name(name, why, sizeof(why))) { cfg_status(false, "%s", why); return false; }
    if (cfg_exists(name) && !g_cfg_pending_overwrite) {
        g_cfg_pending_overwrite = true;
        cfg_status(false, "'%s' ja existe. Clique Salvar novamente para sobrescrever.", name);
        return false;
    }
    char path[MAX_PATH];
    if (!cfg_make_path(name, path, sizeof(path))) { cfg_status(false, "Sem pasta para salvar."); return false; }
    FILE* f = nullptr;
    if (fopen_s(&f, path, "w") != 0 || !f) { cfg_status(false, "Falha ao abrir arquivo."); return false; }
    fprintf(f, "HJCfg1\n");
    for (int i = 0; i < CFG_ENTRY_COUNT; ++i) {
        const CfgEntry& e = CFG_ENTRIES[i];
        switch (e.type) {
        case CFG_BOOL:  fprintf(f, "%s=%d\n", e.key, *(bool*)e.ptr ? 1 : 0); break;
        case CFG_INT:   fprintf(f, "%s=%d\n", e.key, *(int*)e.ptr); break;
        case CFG_FLOAT: fprintf(f, "%s=%.4f\n", e.key, *(float*)e.ptr); break;
        case CFG_COL3: {
            float* c = (float*)e.ptr;
            fprintf(f, "%s=%.4f,%.4f,%.4f\n", e.key, c[0], c[1], c[2]); break;
        }
        case CFG_COL4: {
            float* c = (float*)e.ptr;
            fprintf(f, "%s=%.4f,%.4f,%.4f,%.4f\n", e.key, c[0], c[1], c[2], c[3]); break;
        }
        }
    }
    fclose(f);
    g_cfg_pending_overwrite = false;
    cfg_scan(true);
    for (int i = 0; i < g_cfg_count; ++i)
        if (strcmp(g_cfg_names[i], name) == 0) { g_cfg_selected = i; break; }
    cfg_status(true, "Config '%s' foi salva.", name);
    return true;
}

static bool cfg_load(const char* name) {
    char why[128];
    if (!cfg_valid_name(name, why, sizeof(why))) { cfg_status(false, "%s", why); return false; }
    char path[MAX_PATH];
    if (!cfg_make_path(name, path, sizeof(path)) || !cfg_exists(name)) {
        cfg_status(false, "Arquivo nao encontrado."); return false;
    }
    FILE* f = nullptr;
    if (fopen_s(&f, path, "r") != 0 || !f) { cfg_status(false, "Falha ao ler arquivo."); return false; }
    char line[256];
    if (!fgets(line, sizeof(line), f) || strncmp(line, "HJCfg1", 6) != 0) {
        fclose(f); cfg_status(false, "Arquivo invalido (nao e uma config)."); return false;
    }
    int applied = 0;
    while (fgets(line, sizeof(line), f)) {
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char* key = line;
        char* val = eq + 1;
        for (int i = 0; i < CFG_ENTRY_COUNT; ++i) {
            const CfgEntry& e = CFG_ENTRIES[i];
            if (strcmp(key, e.key) != 0) continue;
            switch (e.type) {
            case CFG_BOOL:  *(bool*)e.ptr = (atoi(val) != 0); break;
            case CFG_INT: {
                int v = atoi(val);
                if (v >= 0 && v <= 255) *(int*)e.ptr = v;
                break;
            }
            case CFG_FLOAT: *(float*)e.ptr = cfg_clampf((float)atof(val), -1000.0f, 1000.0f); break;
            case CFG_COL3: case CFG_COL4: {
                float* c = (float*)e.ptr;
                int n = (e.type == CFG_COL3) ? 3 : 4;
                char* p = val;
                for (int k = 0; k < n; ++k) {
                    while (*p == ' ' || *p == ',') ++p;
                    if (!*p || *p == '\n' || *p == '\r') break;
                    c[k] = cfg_clampf((float)strtod(p, &p), 0.0f, 1.0f);
                }
                break;
            }
            }
            ++applied;
            break;
        }
    }
    fclose(f);
    if (applied == 0) { cfg_status(false, "Nenhuma opcao valida no arquivo."); return false; }
    g_aimbot_fov_size = cfg_clampf(g_aimbot_fov_size, 1.0f, 900.0f);
    g_aimbot_smooth   = cfg_clampf(g_aimbot_smooth, 0.0f, 100.0f);
    g_aimbot_bone     = g_aimbot_bone < 0 ? 0 : (g_aimbot_bone > 6 ? 6 : g_aimbot_bone);
    g_silent_fov_size = cfg_clampf(g_silent_fov_size, 1.0f, 900.0f);
    g_silent_bone     = g_silent_bone < 0 ? 0 : (g_silent_bone > 6 ? 6 : g_silent_bone);
    if (g_silent_key_vk <= 0 || g_silent_key_vk > 255) g_silent_key_vk = VK_XBUTTON2;
    bind_format_key(g_silent_key_vk, g_silent_key_name, sizeof(g_silent_key_name));
    g_fly_speed       = cfg_clampf(g_fly_speed, 1.0f, 60.0f);
    g_rapid_fire_rate = cfg_clampf(g_rapid_fire_rate, 1.0f, 100.0f);
    if (g_menu_key_vk <= 0 || g_menu_key_vk > 255) g_menu_key_vk = VK_INSERT;
    if (g_fly_key_vk  <= 0 || g_fly_key_vk  > 255) g_fly_key_vk  = VK_F8;
    g_fly_mode = (g_fly_mode == FLY_MODE_TOGGLE) ? FLY_MODE_TOGGLE : FLY_MODE_HOLD;
    if (g_aimbot_key_vk <= 0 || g_aimbot_key_vk > 255) g_aimbot_key_vk = VK_XBUTTON1;
    bind_format_key(g_menu_key_vk, g_menu_key_name, sizeof(g_menu_key_name));
    bind_format_key(g_fly_key_vk,  g_fly_key_name,  sizeof(g_fly_key_name));
    aimbot_set_key(g_aimbot_key_vk);
    g_fly_toggle_on = false; g_fly_key_edge = false;
    g_fly_hover_valid = false;
    g_stream_proof_applied = WDA_NONE_VALUE;
    cfg_status(true, "Config '%s' foi carregada.", name);
    return true;
}

static bool cfg_delete(const char* name) {
    char why[128];
    if (!cfg_valid_name(name, why, sizeof(why))) { cfg_status(false, "%s", why); return false; }
    if (!g_cfg_pending_delete) {
        g_cfg_pending_delete = true;
        cfg_status(false, "Clique Excluir novamente para apagar '%s'.", name);
        return false;
    }
    char path[MAX_PATH];
    if (!cfg_make_path(name, path, sizeof(path))) { cfg_status(false, "Sem pasta."); return false; }
    bool ok = DeleteFileA(path) != FALSE;
    g_cfg_pending_delete = false;
    cfg_scan(true);
    cfg_status(ok, ok ? "Config '%s' foi deletada." : "Falha ao excluir: %s", name);
    return ok;
}

static char     g_notify_title[64]  = {};
static char     g_notify_text[160] = {};
static const char* g_notify_icon   = nullptr;
static bool     g_notify_ok        = true;
static uint32_t g_notify_tick      = 0;
static float    g_notify_anim      = 0.0f;
static float    g_tab_slide        = 0.0f;
static float    g_tab_dir          = 1.0f;
static float    g_hover_anim       = 0.0f;
static char     g_troll_names[64][48] = {};
static int      g_troll_count      = 0;
static char     g_troll_selected_name[48] = {};
static std::unordered_map<ImGuiID, float> g_sub_anim;
static std::unordered_map<ImGuiID, float> g_slider_anim;
static std::unordered_map<ImGuiID, float> g_btn_anim;

static void notify_push(const char* title, const char* icon, bool ok,
                        const char* fmt, ...) {
    snprintf(g_notify_title, sizeof(g_notify_title), "%s", title);
    g_notify_icon = icon;
    g_notify_ok = ok;
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(g_notify_text, sizeof(g_notify_text), _TRUNCATE, fmt, ap);
    va_end(ap);
    uint32_t t = GetTickCount();
    g_notify_tick = t ? t : 1;
    g_notify_anim = 0.0f;
}

static void notify_draw() {
    if (!g_notify_tick || InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    ImGuiIO& io = ImGui::GetIO();
    uint32_t age = GetTickCount() - g_notify_tick;
    float target = (age < 3200) ? 1.0f : 0.0f;
    g_notify_anim += (target - g_notify_anim) * ImMin(1.0f, 10.0f * io.DeltaTime);
    if (target == 0.0f && g_notify_anim < 0.003f) { g_notify_tick = 0; g_notify_anim = 0.0f; return; }
    float a = ImClamp(g_notify_anim, 0.0f, 1.0f);
    ImVec2 ts = ImGui::CalcTextSize(g_notify_title);
    ImVec2 ds = ImGui::CalcTextSize(g_notify_text);
    float fs = g_icon_font_size * 0.9f;
    ImVec2 is = ImVec2(0, 0);
    bool has_icon = (g_font_icons && g_notify_icon && g_notify_icon[0]);
    if (has_icon) is = g_font_icons->CalcTextSizeA(fs, FLT_MAX, 0.0f, g_notify_icon);
    float icon_w = has_icon ? is.x + 12.0f : 20.0f;
    float w = icon_w + ImMax(ts.x, ds.x) + 26.0f;
    float h = 52.0f;
    float r = h * 0.5f;
    ImVec2 pos(io.DisplaySize.x - 18.0f, io.DisplaySize.y - 18.0f + (1.0f - a) * 20.0f);
    ImGui::SetNextWindowPos(pos, ImGuiCond_Always, ImVec2(1.0f, 1.0f));
    ImGui::SetNextWindowSize(ImVec2(w, h), ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, a);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, r);
    ImGui::Begin("##notify", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBackground |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMouseInputs);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetWindowPos();
    ImVec2 p1(p0.x + w, p0.y + h);
    dl->AddRectFilled(p0, p1, IM_COL32(18, 18, 24, (int)(245.0f * a)), r);
    dl->AddRect(p0, p1, IM_COL32(136, 100, 255, (int)(255.0f * a)), r, 0, 1.2f);
    ImU32 ic = g_notify_ok ? IM_COL32(160, 130, 255, (int)(255.0f * a))
                           : IM_COL32(255, 140, 140, (int)(255.0f * a));
    ImU32 tc = ic;
    ImU32 dc = g_notify_ok ? IM_COL32(215, 215, 225, (int)(235.0f * a))
                           : IM_COL32(255, 175, 175, (int)(235.0f * a));
    if (has_icon) {
        dl->AddText(g_font_icons, fs,
            ImVec2(p0.x + 14.0f, p0.y + (h - is.y) * 0.5f), ic, g_notify_icon);
    } else {
        dl->AddCircleFilled(ImVec2(p0.x + 18.0f, p0.y + h * 0.5f), 5.0f, ic);
    }
    float tx = p0.x + icon_w + 10.0f;
    dl->AddText(ImVec2(tx, p0.y + 9.0f), tc, g_notify_title);
    dl->AddText(ImVec2(tx, p0.y + 28.0f), dc, g_notify_text);
    ImGui::End();
    ImGui::PopStyleVar(4);
}

static void draw_check_v(ImDrawList* dl, const ImRect& b, float t) {
    if (t <= 0.01f) return;
    ImVec2 p1(b.Min.x + 3.8f, b.Min.y + b.GetHeight() * 0.52f);
    ImVec2 p2(b.Min.x + b.GetWidth() * 0.44f, b.Max.y - 3.8f);
    ImVec2 p3(b.Max.x - 3.4f, b.Min.y + 4.0f);
    ImU32 col = IM_COL32(245, 245, 250, (int)(t * 255));
    float a = ImMin(1.0f, t * 2.0f);
    float c = ImClamp(t * 2.0f - 1.0f, 0.0f, 1.0f);
    dl->AddLine(p1, ImVec2(p1.x + (p2.x - p1.x) * a, p1.y + (p2.y - p1.y) * a), col, 2.0f);
    if (c > 0.0f)
        dl->AddLine(p2, ImVec2(p2.x + (p3.x - p2.x) * c, p2.y + (p3.y - p2.y) * c), col, 2.0f);
}

static void draw_check_glow(ImDrawList* dl, const ImRect& b, float anim, bool hovered) {
    if (anim <= 0.01f) return;
    float expand = hovered ? 2.6f : 1.8f;
    dl->AddRectFilled(ImVec2(b.Min.x - expand, b.Min.y - expand),
                      ImVec2(b.Max.x + expand, b.Max.y + expand),
                      IM_COL32(136, 100, 255, (int)(10.0f * anim)), 6.0f);
}

static bool accent_checkbox(const char* label, bool* v) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(v);
    ImGui::PushID(label);
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);
    const float box_size = 17.0f;
    const float height = ImMax(box_size, label_size.y);
    const float total_w = box_size + (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f);
    ImVec2 pos = window->DC.CursorPos;
    ImRect total_bb(pos, ImVec2(pos.x + total_w, pos.y + height));
    ImGui::ItemSize(total_bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(total_bb, id)) { ImGui::PopID(); ImGui::PopID(); return false; }
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(total_bb, id, &hovered, &held);
    if (pressed) { *v = !*v; ImGui::MarkItemEdited(id); }
    float& anim = g_check_anim[id];
    float target = *v ? 1.0f : 0.0f;
    anim += (target - anim) * ImMin(1.0f, 14.0f * g.IO.DeltaTime);
    if (anim < 0.001f) anim = 0.0f;
    if (anim > 0.999f) anim = 1.0f;
    ImRect box_bb(pos, ImVec2(pos.x + box_size, pos.y + box_size));
    ImDrawList* dl = window->DrawList;
    draw_check_glow(dl, box_bb, anim, hovered);
    if (anim > 0.01f)
        dl->AddRectFilled(box_bb.Min, box_bb.Max, IM_COL32(136, 100, 255, (int)(anim * 255)), 4.0f);
    dl->AddRect(box_bb.Min, box_bb.Max,
        anim > 0.01f ? IM_COL32(136, 100, 255, 255) : IM_COL32(92, 92, 106, 255), 4.0f, 0, 1.2f);
    draw_check_v(dl, box_bb, anim);
    if (label_size.x > 0.0f)
        ImGui::RenderText(ImVec2(box_bb.Max.x + style.ItemInnerSpacing.x,
                                 pos.y + (height - label_size.y) * 0.5f), label);
    ImGui::PopID();
    ImGui::PopID();
    return pressed;
}

static bool accent_checkbox_color(const char* label, bool* v, float* col, int comps, const char* popup_id) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(label);
    ImGui::PushID(popup_id);
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);
    const float swatch_size = 14.0f;
    const float box_size    = 17.0f;
    const float gap_sw      = 8.0f;
    const float gap_cb      = 8.0f;
    const float height = ImMax(ImMax(swatch_size, box_size), label_size.y);
    const float total_w = swatch_size + gap_sw + box_size +
                          (label_size.x > 0.0f ? gap_cb + label_size.x : 0.0f);
    ImVec2 pos = window->DC.CursorPos;
    ImRect total_bb(pos, ImVec2(pos.x + total_w, pos.y + height));
    ImGui::ItemSize(total_bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(total_bb, id)) { ImGui::PopID(); ImGui::PopID(); return false; }
    ImRect swatch_bb(ImVec2(pos.x, pos.y + (height - swatch_size) * 0.5f),
                     ImVec2(pos.x + swatch_size, pos.y + (height + swatch_size) * 0.5f));
    ImGui::SetCursorScreenPos(swatch_bb.Min);
    ImGui::PushID(popup_id);
    bool swatch_clicked = ImGui::InvisibleButton("##swatch", ImVec2(swatch_size, swatch_size));
    if (swatch_clicked) ImGui::OpenPopup("##picker_popup");
    ImGui::PopID();
    int a = (comps >= 4) ? (int)(col[3] * 255) : 255;
    ImU32 swatch_col = IM_COL32((int)(col[0] * 255), (int)(col[1] * 255),
                                (int)(col[2] * 255), a);
    window->DrawList->AddRectFilled(swatch_bb.Min, swatch_bb.Max, swatch_col, 3.0f);
    ImGui::PushID(popup_id);
    bool popup_open = ImGui::BeginPopup("##picker_popup");
    if (popup_open) {
        ImGui::PushID("##picker_inner");
        if (comps >= 4) {
            ImGui::ColorPicker4("##picker", col,
                ImGuiColorEditFlags_PickerHueBar | ImGuiColorEditFlags_NoInputs |
                ImGuiColorEditFlags_AlphaBar);
        } else {
            ImGui::ColorPicker3("##picker", col,
                ImGuiColorEditFlags_PickerHueBar | ImGuiColorEditFlags_NoInputs |
                ImGuiColorEditFlags_NoAlpha);
        }
        ImGui::PopID();
        ImGui::EndPopup();
    }
    ImGui::PopID();
    ImVec2 cb_pos(swatch_bb.Max.x + gap_sw, pos.y + (height - box_size) * 0.5f);
    ImRect cb_bb(cb_pos, ImVec2(cb_pos.x + box_size, cb_pos.y + box_size));
    ImGui::SetCursorScreenPos(cb_bb.Min);
    ImGui::PushID("##chk");
    bool cb_clicked = ImGui::InvisibleButton("##chkbox", ImVec2(box_size, box_size));
    bool cb_hovered = ImGui::IsItemHovered();
    ImGui::PopID();
    if (cb_clicked) { *v = !*v; ImGui::MarkItemEdited(id); }
    float& anim = g_check_anim[id];
    float target = *v ? 1.0f : 0.0f;
    anim += (target - anim) * ImMin(1.0f, 14.0f * g.IO.DeltaTime);
    if (anim < 0.001f) anim = 0.0f;
    if (anim > 0.999f) anim = 1.0f;
    ImDrawList* dl = window->DrawList;
    draw_check_glow(dl, cb_bb, anim, cb_hovered);
    if (anim > 0.01f)
        dl->AddRectFilled(cb_bb.Min, cb_bb.Max, IM_COL32(136, 100, 255, (int)(anim * 255)), 4.0f);
    dl->AddRect(cb_bb.Min, cb_bb.Max,
        anim > 0.01f ? IM_COL32(136, 100, 255, 255) : IM_COL32(92, 92, 106, 255), 4.0f, 0, 1.2f);
    draw_check_v(dl, cb_bb, anim);
    if (label_size.x > 0.0f)
        ImGui::RenderText(ImVec2(cb_bb.Max.x + gap_cb,
                                 pos.y + (height - label_size.y) * 0.5f), label);
    ImGui::PopID();
    ImGui::PopID();
    return cb_clicked;
}

static bool smooth_slider(const char* label, float* v, float lo, float hi,
                          const char* fmt, const char* lo_tag = nullptr,
                          const char* hi_tag = nullptr) {
    *v = ImClamp(*v, lo, hi);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(label);
    const ImGuiID id = window->GetID("##s");
    const ImGuiID track_id = window->GetID("##track");
    ImGuiIO& io = ImGui::GetIO();
    const ImGuiStyle& style = ImGui::GetStyle();
    float avail = ImGui::GetContentRegionAvail().x;
    float label_w = ImGui::CalcTextSize(label).x;
    char valbuf[32] = {};
    snprintf(valbuf, sizeof(valbuf), fmt, *v);
    float val_w = ImGui::CalcTextSize(valbuf).x;
    float track_w = avail - label_w - val_w - 30.0f;
    if (track_w < 40.0f) track_w = 40.0f;
    float h = ImMax(1.0f, ImGui::GetFrameHeight() - 2.0f);
    ImVec2 pos = window->DC.CursorPos;
    float tx = pos.x + label_w + 10.0f;
    ImGui::SetCursorScreenPos(ImVec2(tx, pos.y));
    ImGui::InvisibleButton("##track", ImVec2(track_w, h));
    bool hovered = ImGui::IsItemHovered();
    bool active  = ImGui::IsItemActive();
    bool changed = false;
    if (active) {
        float f = (io.MousePos.x - tx) / track_w;
        f = ImClamp(f, 0.0f, 1.0f);
        float nv = lo + f * (hi - lo);
        if (fabsf(nv - *v) > 0.0001f) { *v = nv; changed = true; ImGui::MarkItemEdited(track_id); }
    }
    float frac = ImClamp((*v - lo) / (hi - lo), 0.0f, 1.0f);
    float& sm = g_slider_anim[id];
    sm += (frac - sm) * ImMin(1.0f, 13.0f * io.DeltaTime);
    ImDrawList* dl = window->DrawList;
    float cy = pos.y + h * 0.5f;
    float bar_h = 5.0f;
    dl->AddRectFilled(ImVec2(tx, cy - bar_h * 0.5f), ImVec2(tx + track_w, cy + bar_h * 0.5f),
                      IM_COL32(42, 42, 52, 255), bar_h * 0.5f);
    dl->AddRectFilled(ImVec2(tx, cy - bar_h * 0.5f), ImVec2(tx + track_w * sm, cy + bar_h * 0.5f),
                      COL_ACCENT, bar_h * 0.5f);
    float gx = tx + track_w * sm;
    float gr = (hovered || active) ? 6.5f : 5.0f;
    dl->AddCircleFilled(ImVec2(gx, cy), gr, COL_ACCENT, 12);
    dl->AddCircle(ImVec2(gx, cy), gr, IM_COL32(20, 20, 26, 255), 12, 1.0f);
    float ty = pos.y + (h - ImGui::GetTextLineHeight()) * 0.5f;
    ImGui::RenderText(ImVec2(pos.x, ty), label);
    ImGui::RenderText(ImVec2(tx + track_w + 8.0f, ty), valbuf);
    float advance = h + 4.0f;
    if (lo_tag || hi_tag) {
        ImU32 dim = IM_COL32(120, 120, 130, 255);
        if (lo_tag) dl->AddText(ImVec2(tx, pos.y + h + 1.0f), dim, lo_tag);
        if (hi_tag) {
            float tw = ImGui::CalcTextSize(hi_tag).x;
            dl->AddText(ImVec2(tx + track_w - tw, pos.y + h + 1.0f), dim, hi_tag);
        }
        advance = h + 16.0f;
    }
    ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y + advance));
    ImGui::Dummy(ImVec2(0.0f, 0.0f));
    ImGui::PopID();
    return changed;
}

static bool ui_button(const char* label, float w, float h, bool primary) {
    w = ImMax(1.0f, w);
    h = ImMax(1.0f, h);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(label);

    const ImGuiID id = window->GetID("##b");
    ImVec2 pos = window->DC.CursorPos;
    ImRect bb(pos, ImVec2(pos.x + w, pos.y + h));
    bool pressed = ImGui::InvisibleButton("##b", ImVec2(w, h));
    bool hovered = ImGui::IsItemHovered();
    float& anim = g_btn_anim[id];
    float target = hovered ? 1.0f : 0.0f;
    anim += (target - anim) * ImMin(1.0f, 14.0f * ImGui::GetIO().DeltaTime);
    ImDrawList* dl = window->DrawList;
    ImU32 bg = primary ? IM_COL32(136, 100, 255, (int)(38.0f + anim * 40.0f))
                       : IM_COL32(255, 255, 255, (int)(8.0f + anim * 16.0f));
    ImU32 bd = primary ? IM_COL32(136, 100, 255, (int)(130.0f + anim * 125.0f))
                       : IM_COL32(75, 75, 92, (int)(160.0f + anim * 80.0f));
    dl->AddRectFilled(bb.Min, bb.Max, bg, 7.0f);
    dl->AddRect(bb.Min, bb.Max, bd, 7.0f, 0, 1.0f);
    ImVec2 ts = ImGui::CalcTextSize(label);
    dl->AddText(ImVec2(bb.Min.x + (w - ts.x) * 0.5f, bb.Min.y + (h - ts.y) * 0.5f),
        primary ? COL_ACCENT_SOFT : COL_TEXT, label);
    ImGui::PopID();
    return pressed;
}

struct SubCardState { ImVec2 pos; float w; float h; };
typedef void (*SubCardFn)(void*);

static void draw_sub_card(const char* id, bool open, float full_h,
                          SubCardFn fn, void* ctx, float parent_x) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return;
    ImGui::PushID(id);
    const ImGuiID aid = window->GetID("##anim");
    float& a = g_sub_anim[aid];
    float target = open ? 1.0f : 0.0f;
    a += (target - a) * ImMin(1.0f, 11.0f * ImGui::GetIO().DeltaTime);
    if (target == 1.0f && a > 0.998f) a = 1.0f;
    if (target == 0.0f && a < 0.002f) a = 0.0f;
    ImVec2 pos = window->DC.CursorPos;
    float indent = parent_x + 18.0f;
    float w = ImMax(40.0f, ImGui::GetContentRegionAvail().x - indent - 10.0f);
    float h = full_h * a;
    if (h < 2.0f) { ImGui::PopID(); return; }
    ImVec2 r0(pos.x + indent, pos.y);
    ImVec2 r1(r0.x + w, r0.y + h);
    ImDrawList* dl = window->DrawList;
    dl->AddRect(r0, r1, IM_COL32(118, 118, 132, (int)(150.0f * a)), 9.0f, 0, 1.0f);
    ImU32 cc = IM_COL32(118, 118, 132, (int)(170.0f * a));
    float cx = pos.x + parent_x;
    float cy = r0.y + ImMin(h * 0.5f, 14.0f);
    float top = pos.y - 2.0f;
    float bend = ImMax(top + 1.0f, cy - 8.0f);
    float ex = r0.x - 3.0f;
    float rad = ImMin(8.0f, ImMax(2.0f, (ex - cx) * 0.5f));
    dl->AddLine(ImVec2(cx, top), ImVec2(cx, bend), cc, 1.0f);
    ImVec2 q0(cx, bend);
    ImVec2 q1(cx, cy);
    ImVec2 q2(cx + rad, cy);
    ImVec2 prev = q0;
    for (int k = 1; k <= 12; ++k) {
        float u = (float)k / 12.0f;
        float v = 1.0f - u;
        ImVec2 pt(v * v * q0.x + 2.0f * v * u * q1.x + u * u * q2.x,
                  v * v * q0.y + 2.0f * v * u * q1.y + u * u * q2.y);
        dl->AddLine(prev, pt, cc, 1.0f);
        prev = pt;
    }
    dl->AddLine(q2, ImVec2(ex, cy), cc, 1.0f);
    dl->AddLine(ImVec2(ex - 3.5f, cy - 2.5f), ImVec2(ex, cy), cc, 1.0f);
    dl->AddLine(ImVec2(ex - 3.5f, cy + 2.5f), ImVec2(ex, cy), cc, 1.0f);
    ImGui::SetCursorScreenPos(ImVec2(r0.x + 10.0f, r0.y + 6.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::BeginChild("##sub_body", ImVec2(ImMax(1.0f, w - 20.0f), ImMax(1.0f, h - 12.0f)), false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    if (fn) fn(ctx);
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    ImGui::PopID();
    ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y + h + 6.0f));
    ImGui::Dummy(ImVec2(0.0f, 0.0f));
}

struct SubFilledCtx { bool* filled; float* col; };
struct SubDynCtx    { bool* dyn; };

static void sub_filled_fn(void* p) {
    SubFilledCtx* c = (SubFilledCtx*)p;
    bool was = *c->filled;
    if (accent_checkbox("Filled", c->filled) && *c->filled && !was) {
        c->col[0] = 0.0f; c->col[1] = 0.0f; c->col[2] = 0.0f; c->col[3] = 0.30f;
    }
}

static void sub_dyn_fn(void* p) {
    accent_checkbox("Dynamic Health", ((SubDynCtx*)p)->dyn);
}

static void card_begin(const char* id, const char* title, float w) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.07f, 0.07f, 0.09f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.16f, 0.16f, 0.19f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 9.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 10));
    ImGui::BeginChild(id, ImVec2(ImMax(1.0f, w), 0), true, ImGuiWindowFlags_NoScrollbar);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(136/255.f, 100/255.f, 255/255.f, 1.0f));
    ImGui::TextUnformatted(title);
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Dummy(ImVec2(0, 6));
}

static void card_end() {
    ImGui::EndChild();
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(2);
}

static void draw_esp_card(const char* card_id, const char* title, float card_w,
                          bool* enable,
                          bool* box,   float col_box[4],   const char* pop_box,
                          bool* box_filled,
                          bool* lines, float col_lines[3], const char* pop_lines,
                          bool* names, float col_names[3], const char* pop_names,
                          bool* health,float col_health[3],const char* pop_health,
                          bool* health_dynamic,
                          bool* armor, float col_armor[3], const char* pop_armor,
                          bool* skel,  float col_skel[3],  const char* pop_skel,
                          bool* distance, float col_distance[3],
                          const char* pop_distance) {
    card_begin(card_id, title, card_w);
    accent_checkbox("Enable", enable);
    if (*enable) {
        ImGui::Dummy(ImVec2(0, 6));
        accent_checkbox_color("Show Box", box, col_box, 4, pop_box);
        SubFilledCtx fc = { box_filled, col_box };
        draw_sub_card("##sub_filled", *box, 34.0f, sub_filled_fn, &fc, 30.0f);
        accent_checkbox_color("Show Lines",    lines, col_lines, 3, pop_lines);
        accent_checkbox_color("Show Names",    names, col_names, 3, pop_names);
        accent_checkbox_color("Show Distance", distance, col_distance, 3, pop_distance);
        accent_checkbox_color("Show Health",   health, col_health, 3, pop_health);
        SubDynCtx dc = { health_dynamic };
        draw_sub_card("##sub_dyn", *health, 34.0f, sub_dyn_fn, &dc, 30.0f);
        accent_checkbox_color("Show Armor",    armor, col_armor, 3, pop_armor);
        accent_checkbox_color("Show Skeleton", skel,  col_skel,  3, pop_skel);
    }
    card_end();
}

static void draw_visuals_page() {
    float avail_w = ImGui::GetContentRegionAvail().x;
    float gap     = 18.0f;
    float col_w   = ImMax(1.0f, (avail_w - gap) * 0.5f);
    draw_esp_card("##esp_local_card", "ESP LOCAL", col_w,
        &g_esp_local_enable,
        &g_esp_local_box,    g_col_local_box,    "##cp_l_box",
        &g_esp_local_box_filled,
        &g_esp_local_lines,  g_col_local_lines,  "##cp_l_lines",
        &g_esp_local_names,  g_col_local_names,  "##cp_l_names",
        &g_esp_local_health, g_col_local_health, "##cp_l_health",
        &g_esp_local_health_dynamic,
        &g_esp_local_armor,  g_col_local_armor,  "##cp_l_armor",
        &g_esp_local_skeleton,g_col_local_skeleton,"##cp_l_skel",
        &g_esp_local_distance, g_col_local_distance, "##cp_l_dist");
    ImGui::SameLine(0.0f, gap);
    draw_esp_card("##esp_players_card", "ESP PLAYERS", col_w,
        &g_esp_players_enable,
        &g_esp_players_box,    g_col_players_box,    "##cp_p_box",
        &g_esp_players_box_filled,
        &g_esp_players_lines,  g_col_players_lines,  "##cp_p_lines",
        &g_esp_players_names,  g_col_players_names,  "##cp_p_names",
        &g_esp_players_health, g_col_players_health, "##cp_p_health",
        &g_esp_players_health_dynamic,
        &g_esp_players_armor,  g_col_players_armor,  "##cp_p_armor",
        &g_esp_players_skeleton,g_col_players_skeleton,"##cp_p_skel",
        &g_esp_players_distance, g_col_players_distance, "##cp_p_dist");
}

static void draw_placeholder_page(const char* title) { (void)title; }

static float aimbot_icon_w() {
    if (!g_font_icons) return 0.0f;
    ImVec2 s = g_font_icons->CalcTextSizeA(g_icon_font_size * 0.8f, FLT_MAX,
                                           0.0f, AIMBOT_ICON_KEYBOARD);
    return s.x;
}

static bool keybind_button(const char* id, float width, const char* text,
                           bool capturing, bool active) {
    width = ImMax(1.0f, width);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGui::PushID(id);
    const ImGuiID bid = window->GetID("##btn");
    const float   h   = ImMax(1.0f, ImGui::GetFrameHeight());
    const ImVec2  pos = window->DC.CursorPos;
    const ImRect  bb(pos, ImVec2(pos.x + width, pos.y + h));
    ImGui::ItemSize(bb, ImGui::GetStyle().FramePadding.y);
    if (!ImGui::ItemAdd(bb, bid)) { ImGui::PopID(); return false; }
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(bb, bid, &hovered, &held);
    ImU32 bg = hovered ? IM_COL32(255, 255, 255, 16) : IM_COL32(255, 255, 255, 8);
    if (active)    bg = IM_COL32(136, 100, 255, 45);
    if (capturing) bg = IM_COL32(136, 100, 255, 70);
    ImDrawList* dl = window->DrawList;
    dl->AddRectFilled(bb.Min, bb.Max, bg, 6.0f);
    dl->AddRect(bb.Min, bb.Max,
        capturing ? COL_ACCENT : IM_COL32(70, 70, 85, 255), 6.0f, 0, 1.1f);
    const ImVec2 tsz = ImGui::CalcTextSize(text);
    const float  iw  = aimbot_icon_w();
    const float  gap = (iw > 0.0f) ? 6.0f : 0.0f;
    const float  total = iw + gap + tsz.x;
    float x0 = bb.Min.x + (width - total) * 0.5f;
    if (x0 < bb.Min.x + 4.0f) x0 = bb.Min.x + 4.0f;
    const ImU32 col = ImGui::GetColorU32(ImGuiCol_Text);
    if (g_font_icons) {
        const float fs = g_icon_font_size * 0.8f;
        ImVec2 isz = g_font_icons->CalcTextSizeA(fs, FLT_MAX, 0.0f, AIMBOT_ICON_KEYBOARD);
        dl->AddText(g_font_icons, fs,
            ImVec2(x0, bb.Min.y + (h - isz.y) * 0.5f), col, AIMBOT_ICON_KEYBOARD);
    }
    dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(),
        ImVec2(x0 + iw + gap, bb.Min.y + (h - tsz.y) * 0.5f), col, text);
    ImGui::PopID();
    return pressed;
}

static bool aimbot_keybind_button(float width) {
    char label[64] = {};
    if (g_aimbot_capturing)
        snprintf(label, sizeof(label), "Pressione uma tecla...");
    else
        snprintf(label, sizeof(label), "%s%s", g_aimbot_key_name,
                 g_aimbot_aim_on ? " (ON)" : "");
    return keybind_button("##aimbot_keybind", width, label,
                          g_aimbot_capturing, g_aimbot_aim_on);
}

static void misc_bind_start(int which) {
    g_bind_capture = which;
    g_bind_capture_tick = 0;
    g_menu_key_latch = (GetAsyncKeyState(g_menu_key_vk) & 0x8000) != 0;
    g_fly_key_prev = false;
    g_fly_key_edge = bind_is_down(g_fly_key_vk);
}

static void draw_bind_button(const char* label, const char* key_name, int which) {
    float w = ImMax(1.0f, ImGui::GetContentRegionAvail().x);
    ImGui::PushID(which);
    ImGui::PushID(label);
    bool capturing = (g_bind_capture == which);
    ImVec2 lp = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(0, ImGui::GetTextLineHeight() + 2.0f));
    ImGui::GetWindowDrawList()->AddText(lp,
        ImGui::GetColorU32(ImGuiCol_TextDisabled), label);
    char text[64] = {};
    snprintf(text, sizeof(text), "%s", capturing ? "Pressione uma tecla..." : key_name);
    if (keybind_button("##bind", w, text, capturing, false)) misc_bind_start(which);
    ImGui::PopID();
    ImGui::PopID();
}

static void sub_fly_fn(void*) {
    draw_bind_button("Bind Key", g_fly_key_name, 3);
    smooth_slider("Velocity", &g_fly_speed, 1.0f, 60.0f, "%.1f");
    if (g_fly_mode != FLY_MODE_TOGGLE) g_fly_mode = FLY_MODE_HOLD;
    ImGui::Combo("Modo##fly_mode", &g_fly_mode, "Hold\0Toggle\0\0");
}

static void draw_aimbot_card(float w) {
    card_begin("##aimbot_card", "Aimbot", w);
    accent_checkbox("Enable Aimbot", &g_aimbot_enable);
    if (g_aimbot_enable) {
        ImGui::Dummy(ImVec2(0, 8));
        accent_checkbox_color("Show Fov", &g_aimbot_show_fov,
                              g_aimbot_fov_col, 3, "##cp_aimbot_fov");
        ImGui::Dummy(ImVec2(0, 4));
        smooth_slider("Fov Size", &g_aimbot_fov_size, 1.0f, 900.0f, "%.0f");
        smooth_slider("Smooth",   &g_aimbot_smooth,   0.0f, 100.0f, "%.1f");
        ImGui::Dummy(ImVec2(0, 2));
        accent_checkbox("Center Dot", &g_aimbot_center_dot);
        accent_checkbox("Show Target", &g_aimbot_show_target);
        ImGui::Dummy(ImVec2(0, 4));
        float row_w  = ImGui::GetContentRegionAvail().x;
        float item_w = (row_w - 8.0f) * 0.5f;
        if (item_w < 80.0f) item_w = 80.0f;
        ImVec2 lp = ImGui::GetCursorScreenPos();
        ImGui::Dummy(ImVec2(0, ImGui::GetTextLineHeight() + 4.0f));
        ImDrawList* d = ImGui::GetWindowDrawList();
        ImU32 dim = ImGui::GetColorU32(ImGuiCol_TextDisabled);
        d->AddText(lp, dim, "Target Bone");
        d->AddText(ImVec2(lp.x + item_w + 8.0f, lp.y), dim, "Keybind");
        ImGui::PushItemWidth(item_w);
        if (g_aimbot_bone < 0 || g_aimbot_bone > 6) g_aimbot_bone = 0;
        ImGui::Combo("##aimbot_bone", &g_aimbot_bone, AIMBOT_BONE_ITEMS, 7);
        ImGui::PopItemWidth();
        ImGui::SameLine(0.0f, 8.0f);
        if (aimbot_keybind_button(item_w)) {
            g_aimbot_capturing    = true;
            g_aimbot_capture_tick = 0;
            g_aimbot_key_held     = false;
            ImGui::ClearActiveID();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Clique e aperte qualquer tecla ou botao do mouse.\nESC cancela. Padrao: Mouse4.");
    }
    card_end();
}


static bool silent_keybind_button(float width) {
    char label[64] = {};
    if (g_silent_capturing)
        snprintf(label, sizeof(label), "Pressione uma tecla...");
    else
        snprintf(label, sizeof(label), "%s%s", g_silent_key_name,
                 g_silent_aim_on ? " (ON)" : "");
    return keybind_button("##silent_keybind", width, label,
                          g_silent_capturing, g_silent_aim_on);
}

static void draw_silent_card(float w) {
    card_begin("##silent_card", "Silent Aim", w);
    accent_checkbox("Enable Silent Aim", &g_silent_enable);
    if (g_silent_enable) {
        ImGui::Dummy(ImVec2(0, 8));
        accent_checkbox_color("Show Fov", &g_silent_show_fov,
                              g_silent_fov_col, 3, "##cp_silent_fov");
        ImGui::Dummy(ImVec2(0, 4));
        smooth_slider("Fov Size", &g_silent_fov_size, 1.0f, 900.0f, "%.0f");
        ImGui::Dummy(ImVec2(0, 2));
        accent_checkbox("Center Dot", &g_silent_center_dot);
        accent_checkbox("Show Target", &g_silent_show_target);
        accent_checkbox("Ignore Walls", &g_silent_ignore_walls);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Desligado: verifica parede, veiculo e objeto antes do packet.\nLigado: ignora obstrucoes.");
        ImGui::Dummy(ImVec2(0, 4));
        float row_w  = ImGui::GetContentRegionAvail().x;
        float item_w = (row_w - 8.0f) * 0.5f;
        if (item_w < 80.0f) item_w = 80.0f;
        ImVec2 lp = ImGui::GetCursorScreenPos();
        ImGui::Dummy(ImVec2(0, ImGui::GetTextLineHeight() + 4.0f));
        ImDrawList* d = ImGui::GetWindowDrawList();
        ImU32 dim = ImGui::GetColorU32(ImGuiCol_TextDisabled);
        d->AddText(lp, dim, "Target Bone");
        d->AddText(ImVec2(lp.x + item_w + 8.0f, lp.y), dim, "Keybind");
        ImGui::PushItemWidth(item_w);
        if (g_silent_bone < 0 || g_silent_bone > 6) g_silent_bone = 0;
        ImGui::Combo("##silent_bone", &g_silent_bone, AIMBOT_BONE_ITEMS, 7);
        ImGui::PopItemWidth();
        ImGui::SameLine(0.0f, 8.0f);
        if (silent_keybind_button(item_w)) {
            g_silent_capturing = true;
            ImGui::ClearActiveID();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Clique e aperte qualquer tecla ou botao do mouse.\nESC cancela. Padrao: Mouse5.");
    }
    card_end();
}

static void sub_rapid_fn(void*) {
    smooth_slider("Fire Rate", &g_rapid_fire_rate, 1.0f, 100.0f, "%.0f", "x1", "x100");
}

static void draw_players_card(float w) {
    card_begin("##troll_players_card", "Jogadores", w);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0.0f);
    float list_h = ImMax(1.0f, ImGui::GetContentRegionAvail().y * 0.5f);
    ImGui::BeginChild("##troll_player_list", ImVec2(0, list_h), false);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    for (int i = 0; i < g_troll_count; ++i) {
        if (!g_troll_names[i][0]) continue;
        ImGui::PushID(i);
        ImVec2 p = ImGui::GetCursorScreenPos();
        float row_w = ImMax(1.0f, ImGui::GetContentRegionAvail().x);
        bool clicked = ImGui::InvisibleButton("##row", ImVec2(row_w, 22.0f));
        bool hovered = ImGui::IsItemHovered();
        if (clicked)
            snprintf(g_troll_selected_name, sizeof(g_troll_selected_name), "%s", g_troll_names[i]);
        bool sel = (strcmp(g_troll_selected_name, g_troll_names[i]) == 0);
        if (sel || hovered)
            dl->AddRectFilled(ImVec2(p.x, p.y), ImVec2(p.x + row_w, p.y + 22.0f),
                sel ? IM_COL32(136, 100, 255, 30) : IM_COL32(255, 255, 255, 10), 5.0f);
        dl->AddRect(ImVec2(p.x + 0.5f, p.y + 0.5f),
                    ImVec2(p.x + row_w - 0.5f, p.y + 21.5f),
                    IM_COL32(235, 235, 245, 165), 5.0f, 0, 1.0f);
        dl->AddText(ImVec2(p.x + 8.0f, p.y + 4.0f),
            sel ? COL_ACCENT : (hovered ? COL_TEXT : COL_TEXT_DIM), g_troll_names[i]);
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    card_end();
}

static void draw_troll_card(float w) {
    card_begin("##troll_card", "Troll", w);
    accent_checkbox("Rapid Fire", &g_rapid_fire_enable);
    draw_sub_card("##sub_rapid", g_rapid_fire_enable, 56.0f, sub_rapid_fn, nullptr, 8.0f);
    if (accent_checkbox("Fly", &g_fly_enable))
        notify_push("Fly", TROLL_ICON_GLYPH, true,
                    g_fly_enable ? "Fly Habilitado" : "Fly Desabilitado");
    draw_sub_card("##sub_fly", g_fly_enable, 150.0f, sub_fly_fn, nullptr, 8.0f);
    card_end();
}

static void draw_options_card(float w) {
    card_begin("##options_card", "Options", w);
    accent_checkbox("Stream Proof", &g_stream_proof);
    card_end();
}

static void draw_config_card(float w) {
    card_begin("##config_card", "Config", w);
    draw_bind_button("Menu Key", g_menu_key_name, 2);
    ImGui::Dummy(ImVec2(0, 8));
    ImGui::Separator();
    ImGui::Dummy(ImVec2(0, 6));
    if (ImGui::InputText("##cfg_name", g_cfg_input, sizeof(g_cfg_input),
                         ImGuiInputTextFlags_CharsNoBlank)) {
        g_cfg_pending_overwrite = false;
        g_cfg_pending_delete = false;
    }
    ImGui::Dummy(ImVec2(0, 6));
    float gap = 5.0f;
    float bw = (ImGui::GetContentRegionAvail().x - gap * 3.0f) * 0.25f;
    float bh = 24.0f;
    if (ui_button("Save", bw, bh, true)) {
        g_cfg_pending_delete = false;
        cfg_save(g_cfg_input);
    }
    ImGui::SameLine(0.0f, gap);
    if (ui_button("Load", bw, bh, false)) {
        g_cfg_pending_overwrite = false;
        g_cfg_pending_delete = false;
        cfg_scan(true);
        if (g_cfg_selected >= 0 && g_cfg_selected < g_cfg_count)
            cfg_load(g_cfg_names[g_cfg_selected]);
        else
            cfg_status(false, "Nenhuma config selecionada.");
    }
    ImGui::SameLine(0.0f, gap);
    if (ui_button("Del", bw, bh, false)) {
        g_cfg_pending_overwrite = false;
        if (g_cfg_selected >= 0 && g_cfg_selected < g_cfg_count)
            cfg_delete(g_cfg_names[g_cfg_selected]);
        else
            cfg_status(false, "Nenhuma config selecionada.");
    }
    ImGui::SameLine(0.0f, gap);
    if (ui_button("Sync", bw, bh, false)) {
        cfg_scan(true);
        cfg_status(true, "%d config(s) encontrada(s).", g_cfg_count);
    }
    ImGui::Dummy(ImVec2(0, 6));
    cfg_scan();
    const char* joined = "";
    cfg_name_combo(&joined, g_cfg_count);
    if (g_cfg_count > 0) {
        if (g_cfg_selected < 0 || g_cfg_selected >= g_cfg_count) g_cfg_selected = 0;
        ImGui::Combo("##cfg_list", &g_cfg_selected, joined, g_cfg_count);
    }
    card_end();
}

static void draw_options_page() {
    float avail_w = ImGui::GetContentRegionAvail().x;
    float gap     = 18.0f;
    float col_w   = ImMax(1.0f, (avail_w - gap) * 0.5f);
    draw_options_card(col_w);
    ImGui::SameLine(0.0f, gap);
    draw_config_card(col_w);
}

static void draw_troll_page() {
    float avail_w = ImGui::GetContentRegionAvail().x;
    float gap     = 18.0f;
    float col_w   = ImMax(1.0f, (avail_w - gap) * 0.5f);
    draw_troll_card(col_w);
    ImGui::SameLine(0.0f, gap);
    draw_players_card(col_w);
}

static void draw_combat_page() {
    float w = (ImGui::GetContentRegionAvail().x - 10.0f) * 0.5f;
    draw_aimbot_card(w);
    ImGui::SameLine(0.0f, 10.0f);
    draw_silent_card(w);
}

static bool draw_sidebar_tab(const char* icon, const char* id, bool selected,
                             const char* fallback, bool* out_hovered) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) { if (out_hovered) *out_hovered = false; return false; }
    const ImGuiStyle& style = ImGui::GetStyle();
    const ImGuiID iid = window->GetID(id);
    const float size = 34.0f;
    ImVec2 pos = window->DC.CursorPos;
    ImRect bb(pos, ImVec2(pos.x + size, pos.y + size));
    ImGui::ItemSize(bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, iid)) {
        if (out_hovered) *out_hovered = false;
        ImGui::Dummy(ImVec2(0, 6));
        return false;
    }
    bool hovered = false, held = false;
    bool pressed = ImGui::ButtonBehavior(bb, iid, &hovered, &held);
    if (out_hovered) *out_hovered = hovered;
    ImDrawList* dl = window->DrawList;
    if (selected) {
        dl->AddRectFilled(bb.Min, bb.Max, COL_ACCENT_DIM, 8.0f);
        dl->AddRectFilled(ImVec2(bb.Min.x, bb.Min.y + 7.0f),
                          ImVec2(bb.Min.x + 3.0f, bb.Max.y - 7.0f), COL_ACCENT, 1.5f);
    }
    ImU32 col = selected ? COL_ACCENT : COL_TEXT_DIM;
    if (g_font_icons && icon && icon[0]) {
        ImVec2 sz = g_font_icons->CalcTextSizeA(g_icon_font_size, FLT_MAX, 0.0f, icon);
        dl->AddText(g_font_icons, g_icon_font_size,
            ImVec2(bb.Min.x + (size - sz.x) * 0.5f, bb.Min.y + (size - sz.y) * 0.5f),
            col, icon);
    } else {
        ImVec2 sz = ImGui::CalcTextSize(fallback);
        dl->AddText(ImVec2(bb.Min.x + (size - sz.x) * 0.5f,
                           bb.Min.y + (size - sz.y) * 0.5f), col, fallback);
    }
    ImGui::Dummy(ImVec2(0, 6));
    return pressed;
}

static void draw_tab_badge(ImDrawList* dl, const ImVec2& anchor,
                           const char* label, float a) {
    if (a < 0.01f) return;
    ImVec2 ts = ImGui::CalcTextSize(label);
    float w = ts.x + 26.0f;
    float h = 28.0f;
    float x1 = anchor.x;
    float x0 = x1 - w;
    if (x0 < 8.0f) { x0 = 8.0f; x1 = x0 + w; }
    ImVec2 p0(x0, anchor.y - h * 0.5f + (1.0f - a) * 6.0f);
    ImVec2 p1(x1, p0.y + h);
    dl->AddRectFilled(p0, p1, IM_COL32(18, 18, 24, (int)(245.0f * a)), 14.0f);
    dl->AddRect(p0, p1, IM_COL32(136, 100, 255, (int)(255.0f * a)), 14.0f, 0, 1.2f);
    dl->AddText(ImVec2(p0.x + 13.0f, p0.y + (h - ts.y) * 0.5f),
        IM_COL32(160, 130, 255, (int)(255.0f * a)), label);
}

static void draw_menu() {
    const float WIN_W = 640.0f;
    const float WIN_H = 420.0f;
    const float HEADER_H = 48.0f;
    const float SIDEBAR_X = 14.0f;
    const float SIDEBAR_TOP = 62.0f;
    const float CONTENT_X = 76.0f;
    const float CONTENT_TOP = 62.0f;

    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowSize(ImVec2(WIN_W, WIN_H), ImGuiCond_Always);
    ImGui::SetNextWindowPos(
        ImVec2((io.DisplaySize.x - WIN_W) * 0.5f, (io.DisplaySize.y - WIN_H) * 0.5f),
        ImGuiCond_FirstUseEver);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0, 0, 0, 0));
    ImGui::Begin("##main_menu", &g_menu_open,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetWindowPos();
    ImVec2 p1(p0.x + WIN_W, p0.y + WIN_H);
    ImVec2 hdr1(p1.x, p0.y + HEADER_H);
    dl->AddRectFilled(p0, p1, COL_BG_PANEL, 12.0f);
    dl->AddRect(p0, p1, COL_BORDER, 12.0f, 0, 1.0f);
    dl->AddRectFilled(p0, hdr1, COL_BG_HEADER, 12.0f, ImDrawFlags_RoundCornersTop);
    dl->AddLine(ImVec2(p0.x, hdr1.y), hdr1, COL_ACCENT_DIM, 1.5f);
    if (g_font_header) ImGui::PushFont(g_font_header);
    dl->AddText(ImVec2(p0.x + 20.0f, p0.y + 11.0f), COL_ACCENT, "Hijacking");
    float off = ImGui::CalcTextSize("Hijacking").x;
    dl->AddText(ImVec2(p0.x + 20.0f + off + 6.0f, p0.y + 11.0f), COL_TEXT, "Menu");
    if (g_font_header) ImGui::PopFont();
    dl->AddRectFilled(ImVec2(p0.x + 6.0f, p0.y + HEADER_H + 6.0f),
                      ImVec2(p0.x + 58.0f, p1.y - 6.0f), COL_BG_SIDEBAR, 8.0f);
    static const char* tab_icons[TAB_COUNT] = {
        ICON_FA_CROSSHAIRS, ICON_FA_EYE, ICON_FA_COG, TROLL_ICON_GLYPH
    };
    static const char* tab_ids[TAB_COUNT] = {
        "##tab_combat", "##tab_visuals", "##tab_options", "##tab_troll"
    };
    static const char* tab_labels[TAB_COUNT] = {
        "Combat", "Visuals", "Options", "Troll"
    };
    static const char* tab_fallback[TAB_COUNT] = { "C", "V", "O", "T" };
    int hover_idx = -1;
    float tab_y = p0.y + SIDEBAR_TOP;
    for (int i = 0; i < TAB_COUNT; ++i) {
        ImGui::SetCursorScreenPos(ImVec2(p0.x + SIDEBAR_X, tab_y));
        bool hov = false;
        if (draw_sidebar_tab(tab_icons[i], tab_ids[i], g_current_tab == i,
                             tab_fallback[i], &hov)) {
            if (g_current_tab != i) {
                g_tab_dir = (i > g_current_tab) ? 1.0f : -1.0f;
                g_current_tab = i;
            }
        }
        if (hov) hover_idx = i;
        tab_y += 40.0f;
    }
    float hover_target = (hover_idx >= 0) ? 1.0f : 0.0f;
    g_hover_anim += (hover_target - g_hover_anim) * ImMin(1.0f, 12.0f * io.DeltaTime);
    g_tab_alpha = ImClamp(
        g_tab_alpha + (6.0f * io.DeltaTime * (g_current_tab == g_anim_tab ? 1.0f : -1.0f)),
        0.0f, 1.0f);
    if (g_tab_alpha == 0.0f) g_anim_tab = g_current_tab;
    bool leaving = (g_current_tab != g_anim_tab);
    float phase = leaving ? (1.0f - g_tab_alpha) : g_tab_alpha;
    float ease = phase * phase * (3.0f - 2.0f * phase);
    g_tab_slide = leaving ? (-g_tab_dir * 22.0f * ease)
                          : (g_tab_dir * 22.0f * (1.0f - ease));
    ImGui::SetCursorScreenPos(ImVec2(p0.x + CONTENT_X + g_tab_slide, p0.y + CONTENT_TOP));
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, g_tab_alpha * ImGui::GetStyle().Alpha);
    ImGui::BeginChild("##content", ImVec2(WIN_W - CONTENT_X - 14.0f, WIN_H - CONTENT_TOP - 14.0f), false);
    switch (g_anim_tab) {
    case TAB_COMBAT:   draw_combat_page();  break;
    case TAB_VISUALS:  draw_visuals_page(); break;
    case TAB_MISC:     draw_options_page(); break;
    case TAB_TROLL:    draw_troll_page();   break;
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
    if (hover_idx >= 0 && g_hover_anim > 0.01f) {
        float hy = p0.y + SIDEBAR_TOP + (float)hover_idx * 40.0f + 17.0f;
        dl->PushClipRect(ImVec2(0.0f, 0.0f), io.DisplaySize, false);
        draw_tab_badge(dl, ImVec2(p0.x - 8.0f, hy), tab_labels[hover_idx], g_hover_anim);
        dl->PopClipRect();
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(3);
}

using fn_EndScene     = HRESULT(__stdcall*)(IDirect3DDevice9*);
using fn_Reset        = HRESULT(__stdcall*)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);
using fn_Present      = HRESULT(__stdcall*)(IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*);
using fn_SetTransform = HRESULT(__stdcall*)(IDirect3DDevice9*, D3DTRANSFORMSTATETYPE, const D3DMATRIX*);

static fn_EndScene     g_o_EndScene     = nullptr;
static fn_Reset        g_o_Reset        = nullptr;
static fn_Present      g_o_Present      = nullptr;
static fn_SetTransform g_o_SetTransform = nullptr;
static bool            g_imgui_init     = false;
static volatile LONG   g_imgui_invalidated = 0;

static D3DMATRIX g_current_view = {};
static D3DMATRIX g_3d_view      = {};
static D3DMATRIX g_3d_proj      = {};
static bool      g_have_3d      = false;

static HWND    g_game_hwnd = nullptr;
static WNDPROC g_o_wndproc = nullptr;

static void stream_proof_apply() {
    if (!g_game_hwnd || !IsWindow(g_game_hwnd)) {
        g_stream_proof_ready = false;
        g_stream_proof_hwnd  = nullptr;
        return;
    }
    g_stream_proof_ready = true;

    // WDA_EXCLUDEFROMCAPTURE so funciona no Win10 2004+ com DWM composition
    // (windowed/borderless). Em exclusive fullscreen o DWM e desligado e a
    // chamada falha; WDA_MONITOR e o fallback (janela preta em captura).
    DWORD desired = g_stream_proof ? WDA_EXCLUDEFROMCAPTURE_V : WDA_NONE_VALUE;

    if (g_stream_proof_applied == desired && g_stream_proof_hwnd == g_game_hwnd)
        return;

    // Toggle OFF: sempre aplica imediatamente
    if (!g_stream_proof) {
        if (set_display_affinity(g_game_hwnd, WDA_NONE_VALUE)) {
            g_stream_proof_applied = WDA_NONE_VALUE;
            g_stream_proof_hwnd    = g_game_hwnd;
            g_stream_proof_ok      = true;
            mta_logf("wda", "stream proof OFF (WDA_NONE)");
        }
        return;
    }

    // Toggle ON: throttle retry em 2s (evita spam quando exclusive FS falha)
    uint32_t now = GetTickCount();
    if (g_stream_proof_last_try && (now - g_stream_proof_last_try) < 2000)
        return;
    g_stream_proof_last_try = now ? now : 1;

    // 1) WDA_EXCLUDEFROMCAPTURE (janela ausente da captura)
    if (set_display_affinity(g_game_hwnd, WDA_EXCLUDEFROMCAPTURE_V)) {
        if (g_stream_proof_applied != WDA_EXCLUDEFROMCAPTURE_V)
            mta_logf("wda", "stream proof ON: WDA_EXCLUDEFROMCAPTURE (0x%X) aplicado",
                     (unsigned)WDA_EXCLUDEFROMCAPTURE_V);
        g_stream_proof_applied = WDA_EXCLUDEFROMCAPTURE_V;
        g_stream_proof_hwnd    = g_game_hwnd;
        g_stream_proof_ok      = true;
        return;
    }

    // 2) WDA_MONITOR (janela preta em captura; funciona sem DWM / Win7+)
    if (set_display_affinity(g_game_hwnd, WDA_MONITOR_VALUE)) {
        if (g_stream_proof_applied != WDA_MONITOR_VALUE)
            mta_logf("wda", "stream proof ON: WDA_MONITOR (0x%X) fallback (DWM off ou Win<2004)",
                     (unsigned)WDA_MONITOR_VALUE);
        g_stream_proof_applied = WDA_MONITOR_VALUE;
        g_stream_proof_hwnd    = g_game_hwnd;
        g_stream_proof_ok      = true;
        return;
    }

    // 3) Falhou tudo (exclusive fullscreen ou SetWindowDisplayAffinity bloqueado)
    if (g_stream_proof_ok || mta_log_tick(7, 5000))
        mta_logf("wda!", "stream proof falhou: EXCLUDEFROMCAPTURE e MONITOR rejeitados "
                         "(exclusive fullscreen? use borderless)");
    g_stream_proof_applied = WDA_NONE_VALUE;
    g_stream_proof_hwnd    = g_game_hwnd;
    g_stream_proof_ok      = false;
}

#ifndef SC_CLOSE_V
#define SC_CLOSE_V 0xF060
#endif
static PatchRecord g_quit_patches[64] = {};
static int         g_quit_patch_count = 0;

static void quit_hard_restore() {
    InterlockedExchange(&g_watchdog_stop, 1);
    InterlockedExchange(&g_session_live, 0);
    g_session_live_tick = 0;
    InterlockedExchange(&g_silent_send_ok, 0);
    int n = g_patch_count;
    if (n > 64) n = 64;
    if (n < 0) n = 0;
    for (int i = 0; i < n; ++i) g_quit_patches[i] = g_patches[i];
    g_quit_patch_count = n;
    for (int pass = 0; pass < 2; ++pass) {
        for (int i = 0; i < g_quit_patch_count; ++i) {
            PatchRecord& pr = g_quit_patches[i];
            if (!pr.addr) continue;
            __try {
                DWORD oldp = 0;
                if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &oldp)) {
                    memcpy(pr.addr, pr.original, 5);
                    VirtualProtect(pr.addr, 5, oldp, &oldp);
                    FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
}

static void emergency_disable_all() {
    if (InterlockedExchange(&g_emergency_done, 1) != 0) return;
    InterlockedExchange(&g_shutdown_all, 1);
    session_fail_closed(4);
    DWORD t0 = GetTickCount();
    InterlockedExchange(&g_watchdog_stop, 1);
    quit_hard_restore();
    fly_physics_end();
    menu_cursor_sync(false);

    HANDLE wh = g_watchdog_handle;
    g_watchdog_handle = nullptr;
    if (wh) {
        WaitForSingleObject(wh, 0);
        CloseHandle(wh);
    }

    g_esp_local_enable = g_esp_local_box = g_esp_local_box_filled = false;
    g_esp_local_lines = g_esp_local_names = g_esp_local_health = false;
    g_esp_local_health_dynamic = g_esp_local_armor = g_esp_local_skeleton = false;
    g_esp_local_distance = false;
    g_esp_players_enable = g_esp_players_box = g_esp_players_box_filled = false;
    g_esp_players_lines = g_esp_players_names = g_esp_players_health = false;
    g_esp_players_health_dynamic = g_esp_players_armor = g_esp_players_skeleton = false;
    g_esp_players_distance = false;
    g_aimbot_enable = g_aimbot_show_fov = g_aimbot_center_dot = false;
    g_silent_enable = g_silent_show_fov = g_silent_center_dot = false;
    g_silent_aim_on = g_silent_has_target = false;
    g_silent_capturing = false;
    InterlockedExchange(&g_silent_send_ok, 0);
    g_aimbot_show_target = false;
    g_aimbot_aim_on = g_aimbot_has_target = false;
    g_aimbot_capturing = g_aimbot_key_held = false;
    g_bind_capture = 0; g_bind_capture_tick = 0;
    g_menu_key_latch = (GetAsyncKeyState(g_menu_key_vk) & 0x8000) != 0;
    InterlockedExchange(&g_menu_toggle_pending, 0);
    g_fly_key_prev = g_fly_key_held = false;
    g_fly_enable = g_fly_active = false;
    g_rapid_fire_enable = false;
    rapid_fire_restore();
    g_fly_toggle_on = false; g_fly_key_edge = false;
    g_fly_hover_valid = false;
    g_stream_proof = false;
    g_menu_open = false; g_prev_insert = false; g_prev_menu_open = false;
    g_cfg_pending_overwrite = false; g_cfg_pending_delete = false;

    if (g_game_hwnd) set_display_affinity(g_game_hwnd, WDA_NONE_VALUE);
    g_stream_proof_ready   = false;
    g_stream_proof_applied = WDA_NONE_VALUE;
    g_stream_proof_hwnd    = nullptr;

    ClipCursor(nullptr);

    WNDPROC orig = g_o_wndproc;
    if (orig && g_game_hwnd) {
        SetWindowLongPtrA(g_game_hwnd, GWLP_WNDPROC, (LONG_PTR)orig);
        g_o_wndproc = nullptr;
    }

    silent_retire_hooks();
    quit_hard_restore();
    if (!g_emergency_logged) {
        g_emergency_logged = true;
        mta_logf("quit", "kill switch %ums: %d hooks restaurados ANTES do disconnect, watchdog parado, WDA_NONE",
                 (unsigned)(GetTickCount() - t0), g_quit_patch_count);
    }
}

static void misc_bind_poll_capture() {
    int which = g_bind_capture;
    if (!which) return;
    static bool     armed = false;
    static bool     was_down[256] = {};
    static uint32_t start = 0;

    if (g_bind_capture_tick == 0) {
        g_bind_capture_tick = GetTickCount();
        start = g_bind_capture_tick;
        armed = false;
        for (int i = 0; i < 256; ++i) was_down[i] = bind_is_down(i);
        return;
    }
    if (GetTickCount() - start > 8000) { bind_set_key(which, 0); g_bind_capture = 0; return; }
    if (bind_is_down(VK_ESCAPE)) {
        g_bind_capture = 0; g_bind_capture_tick = 0; armed = false;
        return;
    }
    for (int vk = 1; vk < 256; ++vk) {
        bool down = bind_is_down(vk);
        bool edge = down && !was_down[vk];
        was_down[vk] = down;
        if (!edge) continue;
        if (!armed) { armed = true; continue; }
        if (vk == VK_ESCAPE) { g_bind_capture = 0; g_bind_capture_tick = 0; return; }
        bind_set_key(which, vk);
        return;
    }
}

static bool is_perspective(const D3DMATRIX* m) {
    return m->m[3][2] != 0.0f && m->m[3][3] == 0.0f;
}

static LRESULT CALLBACK hk_wndproc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    WNDPROC orig_at_entry = g_o_wndproc;
    if (msg == WM_SHOWWINDOW) {
        if (!wParam && !IsIconic(hwnd)) quit_flush();
        else if (wParam) quit_unflush();
    } else if (msg == WM_WINDOWPOSCHANGED && lParam) {
        __try {
            WINDOWPOS* wp = (WINDOWPOS*)lParam;
            if ((wp->flags & SWP_HIDEWINDOW) && !IsIconic(hwnd)) quit_flush();
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    if (msg == WM_CLOSE || msg == WM_DESTROY || msg == WM_NCDESTROY ||
        msg == WM_QUIT || msg == WM_ENDSESSION || msg == WM_QUERYENDSESSION ||
        (msg == WM_SYSCOMMAND && (wParam & 0xFFF0) == SC_CLOSE_V)) {
        quit_flush();
        emergency_disable_all();
        static bool quit_msg_logged = false;
        if (!quit_msg_logged) {
            quit_msg_logged = true;
            mta_logf("quit", "sinal 0x%04X -> hooks restaurados antes do disconnect", (unsigned)msg);
        }
        return orig_at_entry
            ? CallWindowProc(orig_at_entry, hwnd, msg, wParam, lParam)
            : DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) {
        return orig_at_entry
            ? CallWindowProc(orig_at_entry, hwnd, msg, wParam, lParam)
            : DefWindowProcA(hwnd, msg, wParam, lParam);
    }

    if ((msg == WM_ACTIVATEAPP && !wParam) || msg == WM_KILLFOCUS) {
        InterlockedExchange(&g_silent_send_ok, 0);
        g_silent_aim_on = g_silent_has_target = false;
    }

    if (g_silent_capturing) {
        int cap = 0;
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) cap = (int)(wParam & 0xFF);
        else if (msg == WM_LBUTTONDOWN) cap = VK_LBUTTON;
        else if (msg == WM_RBUTTONDOWN) cap = VK_RBUTTON;
        else if (msg == WM_MBUTTONDOWN) cap = VK_MBUTTON;
        else if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONDBLCLK)
            cap = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        if (cap == VK_ESCAPE) { g_silent_capturing = false; return 1; }
        if (cap) {
            g_silent_key_vk = cap;
            bind_format_key(cap, g_silent_key_name, sizeof(g_silent_key_name));
            g_silent_capturing = false;
            return 1;
        }
    }

    if (g_bind_capture) {
        int cap = 0;
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) cap = (int)(wParam & 0xFF);
        else if (msg == WM_LBUTTONDOWN) cap = VK_LBUTTON;
        else if (msg == WM_RBUTTONDOWN) cap = VK_RBUTTON;
        else if (msg == WM_MBUTTONDOWN) cap = VK_MBUTTON;
        else if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONDBLCLK)
            cap = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        if (cap == VK_ESCAPE) { g_bind_capture = 0; g_bind_capture_tick = 0; return 1; }
        if (cap) { bind_set_key(g_bind_capture, cap); return 1; }
    }

    if (g_aimbot_capturing) {
        int cap = 0;
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) cap = (int)(wParam & 0xFF);
        else if (msg == WM_LBUTTONDOWN) cap = VK_LBUTTON;
        else if (msg == WM_RBUTTONDOWN) cap = VK_RBUTTON;
        else if (msg == WM_MBUTTONDOWN) cap = VK_MBUTTON;
        else if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONDBLCLK)
            cap = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        if (cap == VK_ESCAPE) { aimbot_stop_capture(); return 1; }
        if (cap) { aimbot_set_key(cap); aimbot_stop_capture(); return 1; }
    }
    {
        int dvk = 0, uvk = 0;
        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) dvk = (int)(wParam & 0xFF);
        else if (msg == WM_KEYUP || msg == WM_SYSKEYUP) uvk = (int)(wParam & 0xFF);
        else if (msg == WM_LBUTTONDOWN) dvk = VK_LBUTTON;
        else if (msg == WM_LBUTTONUP)   uvk = VK_LBUTTON;
        else if (msg == WM_RBUTTONDOWN) dvk = VK_RBUTTON;
        else if (msg == WM_RBUTTONUP)   uvk = VK_RBUTTON;
        else if (msg == WM_MBUTTONDOWN) dvk = VK_MBUTTON;
        else if (msg == WM_MBUTTONUP)   uvk = VK_MBUTTON;
        else if (msg == WM_XBUTTONDOWN || msg == WM_XBUTTONDBLCLK)
            dvk = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        else if (msg == WM_XBUTTONUP)
            uvk = (HIWORD(wParam) & XBUTTON1) ? VK_XBUTTON1 : VK_XBUTTON2;
        if (dvk && dvk == g_aimbot_key_vk) {
            g_aimbot_key_held  = true;
            g_aimbot_held_tick = GetTickCount();
        }
        if (uvk && uvk == g_aimbot_key_vk) g_aimbot_key_held = false;
    }
    if (msg == WM_KILLFOCUS) g_aimbot_key_held = false;

    if ((msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN) &&
        !(lParam & 0x40000000) &&
        (int)(wParam & 0xFF) == g_menu_key_vk &&
        !g_bind_capture && !g_aimbot_capturing) {
        InterlockedExchange(&g_menu_toggle_pending, 1);
    }

    if (g_imgui_init) {
        if (msg == WM_SETCURSOR && g_menu_open) return 1;
        ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam);
        ImGuiIO& io = ImGui::GetIO();

        if ((msg == WM_ACTIVATE && LOWORD(wParam) == WA_INACTIVE) ||
            (msg == WM_ACTIVATEAPP && wParam == FALSE) ||
            msg == WM_KILLFOCUS) {
            io.MouseDown[0] = io.MouseDown[1] = io.MouseDown[2] = false;
            io.MouseWheel   = 0.0f;
            io.MouseWheelH  = 0.0f;
            ImGui::ClearActiveID();
            ClipCursor(nullptr);
        }
        if (g_menu_open && io.WantCaptureMouse) {
            switch (msg) {
                case WM_LBUTTONDOWN: case WM_LBUTTONUP:
                case WM_RBUTTONDOWN: case WM_RBUTTONUP:
                case WM_MBUTTONDOWN: case WM_MBUTTONUP:
                case WM_MOUSEWHEEL:  case WM_MOUSEMOVE:
                    return 1;
            }
        }
        if (g_menu_open && io.WantCaptureKeyboard) {
            switch (msg) {
                case WM_KEYDOWN: case WM_KEYUP: case WM_CHAR:
                    return 1;
            }
        }
    }
    return g_o_wndproc
        ? CallWindowProc(g_o_wndproc, hwnd, msg, wParam, lParam)
        : DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void apply_theme() {
    ImGuiStyle& s = ImGui::GetStyle();
    ImVec4* c = s.Colors;

    const ImVec4 accent       = ImVec4(136/255.f, 100/255.f, 255/255.f, 1.00f);
    const ImVec4 accent_hover = ImVec4(160/255.f, 130/255.f, 255/255.f, 1.00f);
    const ImVec4 accent_dim   = ImVec4(100/255.f,  75/255.f, 200/255.f, 1.00f);
    const ImVec4 accent_bg    = ImVec4(136/255.f, 100/255.f, 255/255.f, 0.25f);

    c[ImGuiCol_Text]                  = ImVec4(0.90f, 0.90f, 0.92f, 1.00f);
    c[ImGuiCol_TextDisabled]          = ImVec4(0.47f, 0.47f, 0.51f, 1.00f);
    c[ImGuiCol_WindowBg]              = ImVec4(0.05f, 0.05f, 0.06f, 0.98f);
    c[ImGuiCol_ChildBg]               = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
    c[ImGuiCol_PopupBg]               = ImVec4(0.08f, 0.08f, 0.10f, 0.98f);
    c[ImGuiCol_Border]                = ImVec4(0.16f, 0.16f, 0.19f, 1.00f);
    c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);

    c[ImGuiCol_FrameBg]               = ImVec4(0.13f, 0.13f, 0.16f, 1.00f);
    c[ImGuiCol_FrameBgHovered]        = ImVec4(0.17f, 0.17f, 0.21f, 1.00f);
    c[ImGuiCol_FrameBgActive]         = ImVec4(0.20f, 0.16f, 0.28f, 1.00f);

    c[ImGuiCol_TitleBg]               = ImVec4(0.05f, 0.05f, 0.06f, 1.00f);
    c[ImGuiCol_TitleBgActive]         = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
    c[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.05f, 0.05f, 0.06f, 1.00f);
    c[ImGuiCol_MenuBarBg]             = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);

    c[ImGuiCol_ScrollbarBg]           = ImVec4(0.05f, 0.05f, 0.06f, 1.00f);
    c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.20f, 0.20f, 0.24f, 1.00f);
    c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.30f, 0.30f, 0.35f, 1.00f);
    c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.40f, 0.40f, 0.45f, 1.00f);

    c[ImGuiCol_CheckMark]             = accent;
    c[ImGuiCol_SliderGrab]            = accent;
    c[ImGuiCol_SliderGrabActive]      = accent_hover;

    c[ImGuiCol_Button]                = ImVec4(0.16f, 0.13f, 0.24f, 1.00f);
    c[ImGuiCol_ButtonHovered]         = accent_dim;
    c[ImGuiCol_ButtonActive]          = accent;

    c[ImGuiCol_Header]                = ImVec4(0.16f, 0.13f, 0.24f, 1.00f);
    c[ImGuiCol_HeaderHovered]         = ImVec4(0.20f, 0.16f, 0.30f, 1.00f);
    c[ImGuiCol_HeaderActive]          = accent_dim;

    c[ImGuiCol_Separator]             = ImVec4(0.16f, 0.16f, 0.19f, 1.00f);
    c[ImGuiCol_SeparatorHovered]      = accent_dim;
    c[ImGuiCol_SeparatorActive]       = accent;

    c[ImGuiCol_ResizeGrip]            = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    c[ImGuiCol_ResizeGripHovered]     = accent_dim;
    c[ImGuiCol_ResizeGripActive]      = accent;

    c[ImGuiCol_Tab]                   = ImVec4(0.10f, 0.10f, 0.12f, 1.00f);
    c[ImGuiCol_TabHovered]            = ImVec4(0.20f, 0.16f, 0.30f, 1.00f);
    c[ImGuiCol_TabActive]             = ImVec4(0.16f, 0.13f, 0.24f, 1.00f);

    c[ImGuiCol_PlotLines]             = accent;
    c[ImGuiCol_PlotLinesHovered]      = accent_hover;
    c[ImGuiCol_PlotHistogram]         = accent;
    c[ImGuiCol_PlotHistogramHovered]  = accent_hover;

    c[ImGuiCol_TextSelectedBg]        = accent_bg;
    c[ImGuiCol_NavHighlight]          = accent;

    s.WindowPadding     = ImVec2(12, 12);
    s.FramePadding      = ImVec2(8, 4);
    s.ItemSpacing       = ImVec2(10, 8);
    s.ItemInnerSpacing  = ImVec2(6, 6);
    s.IndentSpacing     = 20.0f;
    s.ScrollbarSize     = 6.0f;
    s.GrabMinSize       = 10.0f;

    s.WindowBorderSize  = 1.0f;
    s.ChildBorderSize   = 1.0f;
    s.PopupBorderSize   = 1.0f;
    s.FrameBorderSize   = 0.0f;

    s.WindowRounding    = 10.0f;
    s.ChildRounding     = 8.0f;
    s.FrameRounding     = 4.0f;
    s.PopupRounding     = 6.0f;
    s.ScrollbarRounding = 4.0f;
    s.GrabRounding      = 4.0f;
    s.TabRounding       = 4.0f;

    s.AntiAliasedLines  = true;
    s.AntiAliasedFill   = true;
}
static ImFont* SafeLoadFont(const char* Path, float Size, const ImFontConfig* Cfg = nullptr, const ImWchar* Ranges = nullptr) {
    if (!Path) return nullptr;
    DWORD Attr = GetFileAttributesA(Path);
    if (Attr == INVALID_FILE_ATTRIBUTES) return nullptr;
    if (Attr & FILE_ATTRIBUTE_DIRECTORY) return nullptr;
    return ImGui::GetIO().Fonts->AddFontFromFileTTF(Path, Size, Cfg, Ranges);
}

static void init_imgui(IDirect3DDevice9* pDevice) {
    D3DDEVICE_CREATION_PARAMETERS cp = {};
    pDevice->GetCreationParameters(&cp);

    HWND hwnd = cp.hFocusWindow;
    if (!hwnd) {
        __try { hwnd = *(HWND*)0x00C97C1C; } __except (EXCEPTION_EXECUTE_HANDLER) { hwnd = nullptr; }
    }
    if (!hwnd) hwnd = FindWindowA("Grand theft auto San Andreas", nullptr);
    if (!hwnd || !IsWindow(hwnd)) return;
    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != GetCurrentProcessId()) return;
    g_game_hwnd = hwnd;
    g_stream_proof_ready = true;

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;

    char win_dir[MAX_PATH] = { 0 };
    GetWindowsDirectoryA(win_dir, MAX_PATH);
    char arial_r[MAX_PATH], arial_b[MAX_PATH];
    snprintf(arial_r, sizeof(arial_r), "%s\\Fonts\\arial.ttf",   win_dir);
    snprintf(arial_b, sizeof(arial_b), "%s\\Fonts\\arialbd.ttf", win_dir);

    g_font_regular = SafeLoadFont(arial_r, 16.0f);
    if (!g_font_regular) g_font_regular = io.Fonts->AddFontDefault();
    g_font_header  = SafeLoadFont(arial_b, 22.0f);
    if (!g_font_header)  g_font_header  = g_font_regular;

    g_font_esp_name = SafeLoadFont(arial_b, ESP_NAME_FONT_SIZE);
    if (!g_font_esp_name)
        g_font_esp_name = g_font_header ? g_font_header : g_font_regular;

    ImFontConfig icon_cfg;
    static const ImWchar icon_ranges[] = { 0xf000, 0xf8ff, 0 };
    icon_cfg.GlyphRanges = icon_ranges;
    icon_cfg.PixelSnapH  = true;

    g_font_icons = io.Fonts->AddFontFromMemoryCompressedTTF(
        (const void*)FA_solid_900_data,
        (int)FA_solid_900_size,
        20.0f,
        &icon_cfg,
        icon_ranges);

    if (!g_font_icons) {
        g_font_icons = io.Fonts->AddFontFromMemoryCompressedTTF(
            (const void*)FA_regular_400_data,
            (int)FA_regular_400_size,
            20.0f,
            &icon_cfg,
            icon_ranges);
    }
    if (!g_font_icons) g_font_icons = g_font_regular;
    g_icon_font_size = 20.0f;

    ImGui_ImplWin32_Init(hwnd);

    ImGui_ImplDX9_Init(pDevice);

    ImGui::StyleColorsDark();
    apply_theme();

    g_o_wndproc = (WNDPROC)SetWindowLongPtrA(hwnd, GWLP_WNDPROC, (LONG_PTR)hk_wndproc);
    g_imgui_init = true;
    mta_logf("ui", "ImGui pronto: hwnd=%p regular=%p header=%p esp=%p icons=%p",
             (void*)g_game_hwnd, (void*)g_font_regular, (void*)g_font_header,
             (void*)g_font_esp_name, (void*)g_font_icons);
}

struct Vec3 { float x, y, z; };

#define ADDR_LOCAL_PLAYER_PRIMARY   0xB6F5F0
#define ADDR_LOCAL_PLAYER_FALLBACK  0xB7CD98
#define PED_OFF_MATRIX       0x14
#define PED_OFF_HEALTH       0x540
#define PED_OFF_MAX_HEALTH   0x544
#define PED_OFF_ARMOR        0x548
#define PED_OFF_PHYS_FLAGS   0x40
#define PED_OFF_MOVE_SPEED   0x44
#define PED_OFF_TURN_SPEED   0x50
#define CMTX_OFF_POS         0x30

using CPed_GetBonePosition_t = Vec3* (__thiscall*)(void* thisptr, Vec3* out, int boneId, bool includeAnim);
static const CPed_GetBonePosition_t CPed_GetBonePosition = (CPed_GetBonePosition_t)0x5E4280;

static inline bool is_valid_ptr(uint32_t p) {
    return p >= 0x10000 && p <= 0x7FFFFFFF;
}

static uint32_t get_local_ped() {
    auto validate = [](uint32_t p) -> bool {
        if (!is_valid_ptr(p)) return false;
        __try {
            uint32_t matrix = *(uint32_t*)(p + PED_OFF_MATRIX);
            if (!is_valid_ptr(matrix)) return false;
            float hp = *(float*)(p + PED_OFF_HEALTH);
            if (hp < 0.0f || hp > 10000.0f) return false;
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
    };

    __try {
        uint32_t p = *(uint32_t*)ADDR_LOCAL_PLAYER_FALLBACK;
        if (validate(p)) return p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try {
        uint32_t p = *(uint32_t*)ADDR_LOCAL_PLAYER_PRIMARY;
        if (validate(p)) return p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    return 0;
}	

static void fly_physics_end() {
    if (!g_fly_phys_saved) return;
    g_fly_phys_saved = false;
    g_fly_hover_valid = false;
    uint32_t ped = get_local_ped();
    if (!is_valid_ptr(ped) || ped != g_fly_phys_ped) {
        g_fly_hover_valid = false;
        return;
    }
    __try {
        uint32_t* flags = (uint32_t*)(uintptr_t)(ped + PED_OFF_PHYS_FLAGS);
        float* mv = (float*)(uintptr_t)(ped + PED_OFF_MOVE_SPEED);
        float* tv = (float*)(uintptr_t)(ped + PED_OFF_TURN_SPEED);
        uint32_t f = *flags;
        *flags = (f & ~0x00000006u) | (g_fly_phys_flags & 0x00000006u);
        mv[0] = mv[1] = mv[2] = 0.0f;
        tv[0] = tv[1] = tv[2] = 0.0f;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void fly_physics_apply(uint32_t ped, float fdx, float fdy, float fdz, float dt) {
    if (!is_valid_ptr(ped)) return;
    __try {
        uint32_t* flags = (uint32_t*)(uintptr_t)(ped + PED_OFF_PHYS_FLAGS);
        float* mv = (float*)(uintptr_t)(ped + PED_OFF_MOVE_SPEED);
        float* tv = (float*)(uintptr_t)(ped + PED_OFF_TURN_SPEED);
        float* hp = (float*)(uintptr_t)(ped + PED_OFF_HEALTH);
        float* ar = (float*)(uintptr_t)(ped + PED_OFF_ARMOR);
        uint32_t f = *flags;
        if (g_fly_phys_saved && g_fly_phys_ped != ped) g_fly_phys_saved = false;
        if (!g_fly_phys_saved) {
            g_fly_phys_ped     = ped;
            g_fly_phys_flags   = f & 0x00000006u;
            g_fly_hp_saved     = *hp;
            g_fly_armor_saved  = *ar;
            if (!(g_fly_hp_saved > 0.0f && g_fly_hp_saved < 10000.0f)) g_fly_hp_saved = 100.0f;
            if (!(g_fly_armor_saved >= 0.0f && g_fly_armor_saved < 1000.0f)) g_fly_armor_saved = 0.0f;
            g_fly_phys_saved = true;
            mta_logf("fly", "fisica OFF flags=%08X hp=%.0f armor=%.0f",
                     (unsigned)f, g_fly_hp_saved, g_fly_armor_saved);
        }
        *flags = (f & ~0x00000002u) | 0x00000004u;
        // FIX streaming: preserva "velocidade aparente" para o GTA SA pre-carregar
        // setores. Zerar mv/tv fazia o jogador teleportar em setores nao carregados,
        // travando a thread principal 100-600ms (queda de FPS). Cap em 40 u/s
        // (velocidade de carro rapido) para nao sobrecarregar o streaming.
        float vmag = sqrtf(fdx*fdx + fdy*fdy + fdz*fdz);
        if (vmag > 0.0001f && dt > 0.0001f) {
            float v = vmag / dt;
            if (v > 40.0f) v = 40.0f;
            mv[0] = fdx / vmag * v;
            mv[1] = fdy / vmag * v;
            mv[2] = fdz / vmag * v;
        } else {
            mv[0] = mv[1] = mv[2] = 0.0f;
        }
        tv[0] = tv[1] = tv[2] = 0.0f;
        if (*hp < g_fly_hp_saved && *hp > -1000.0f) *hp = g_fly_hp_saved;
        if (*ar < g_fly_armor_saved && *ar > -1000.0f) *ar = g_fly_armor_saved;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void fly_camera_axes(const float* pos, float* fwd, float* right, bool& ok) {
    ok = false;
    if (!g_have_3d) return;
    const D3DMATRIX& v = g_3d_view;
    D3DMATRIX m = {};
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            m.m[i][j] = v.m[i][0]*g_3d_proj.m[0][j] + v.m[i][1]*g_3d_proj.m[1][j]
                      + v.m[i][2]*g_3d_proj.m[2][j] + v.m[i][3]*g_3d_proj.m[3][j];
    float cand[4][3] = {
        {  v.m[0][2],  v.m[1][2],  v.m[2][2] },
        { -v.m[0][2], -v.m[1][2], -v.m[2][2] },
        {  v.m[2][0],  v.m[2][1],  v.m[2][2] },
        { -v.m[2][0], -v.m[2][1], -v.m[2][2] }
    };
    float best = 1.0e30f;
    int bi = -1;
    for (int k = 0; k < 4; ++k) {
        float d[3] = { cand[k][0], cand[k][1], cand[k][2] };
        float l = sqrtf(d[0]*d[0] + d[1]*d[1] + d[2]*d[2]);
        if (l < 0.0001f) continue;
        d[0] /= l; d[1] /= l; d[2] /= l;
        float qx = pos[0] + d[0]*64.0f;
        float qy = pos[1] + d[1]*64.0f;
        float qz = pos[2] + d[2]*64.0f;
        float cx = qx*m.m[0][0] + qy*m.m[1][0] + qz*m.m[2][0] + m.m[3][0];
        float cy = qx*m.m[0][1] + qy*m.m[1][1] + qz*m.m[2][1] + m.m[3][1];
        float cw = qx*m.m[0][3] + qy*m.m[1][3] + qz*m.m[2][3] + m.m[3][3];
        if (cw < 0.05f) continue;
        float nx = cx / cw, ny = cy / cw;
        float score = nx*nx + ny*ny;
        if (score < best) { best = score; bi = k; }
    }
    if (bi < 0 || best > 25.0f) bi = 0;
    if (bi != g_fly_axis_idx) {
        g_fly_axis_idx = bi;
        mta_logf("fly", "eixo camera conv=%d sign=%d score=%.2f",
                 bi < 2 ? 0 : 1, (bi % 2) ? -1 : 1, best);
    }
    float sg = (bi % 2) ? -1.0f : 1.0f;
    if (bi < 2) {
        fwd[0]   = sg*v.m[0][2]; fwd[1]   = sg*v.m[1][2]; fwd[2]   = sg*v.m[2][2];
        right[0] =    v.m[0][0]; right[1] =    v.m[1][0]; right[2] =    v.m[2][0];
    } else {
        fwd[0]   = sg*v.m[2][0]; fwd[1]   = sg*v.m[2][1]; fwd[2]   = sg*v.m[2][2];
        right[0] =    v.m[0][0]; right[1] =    v.m[0][1]; right[2] =    v.m[0][2];
    }
    float lf = sqrtf(fwd[0]*fwd[0] + fwd[1]*fwd[1] + fwd[2]*fwd[2]);
    if (lf < 0.0001f) return;
    fwd[0] /= lf; fwd[1] /= lf; fwd[2] /= lf;
    float dot = right[0]*fwd[0] + right[1]*fwd[1] + right[2]*fwd[2];
    right[0] -= fwd[0]*dot; right[1] -= fwd[1]*dot; right[2] -= fwd[2]*dot;
    float lr = sqrtf(right[0]*right[0] + right[1]*right[1] + right[2]*right[2]);
    if (lr < 0.0001f) return;
    right[0] /= lr; right[1] /= lr; right[2] /= lr;
    ok = true;
}

static float fly_camera_pitch() {
    __try {
        uint8_t active = *(uint8_t*)0xB6F081u;
        if (active >= 3) return 1000.0f;
        uint32_t cam = 0xB6F19Cu + (uint32_t)active * 0x238u;
        volatile float* pitch = (volatile float*)(cam + 0xACu);
        float cp = *pitch;
        if (cp > -20.0f && cp < 20.0f) return cp;
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
    return 1000.0f;
}

static bool get_ped_world_pos(uint32_t ped, Vec3& out) {
    if (!is_valid_ptr(ped)) return false;
    __try {
        uint32_t matrix = *(uint32_t*)(ped + PED_OFF_MATRIX);
        float* pos = is_valid_ptr(matrix) ? (float*)(matrix + CMTX_OFF_POS)
                                          : (float*)(ped + 0x04);
        float x = pos[0], y = pos[1], z = pos[2];
        if (x == 0.0f && y == 0.0f && z == 0.0f) {
            if (is_valid_ptr(matrix)) {
                float* fallback_pos = (float*)(ped + 0x04);
                x = fallback_pos[0]; y = fallback_pos[1]; z = fallback_pos[2];
            }
            if (x == 0.0f && y == 0.0f && z == 0.0f) return false;
        }
        if (!(x > -16000.0f && x < 16000.0f)) return false;
        if (!(y > -16000.0f && y < 16000.0f)) return false;
        if (!(z > -5000.0f  && z < 10000.0f)) return false;
        out.x = x; out.y = y; out.z = z;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool get_local_player_pos(Vec3& out, float& hp, float& max_hp, float& armor) {
    __try {
        uint32_t ped = get_local_ped();
        if (!is_valid_ptr(ped)) return false;
        if (!get_ped_world_pos(ped, out)) return false;
        hp     = *(float*)(ped + PED_OFF_HEALTH);
        max_hp = *(float*)(ped + PED_OFF_MAX_HEALTH);
        if (max_hp < 1.0f || max_hp > 10000.0f) max_hp = 100.0f;
        if (hp < 0.0f || hp > max_hp * 2.0f) hp = max_hp;
        armor = *(float*)(ped + PED_OFF_ARMOR);
        if (armor < 0.0f || armor > 500.0f) armor = 0.0f;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool get_bone_pos(uint32_t ped, int bone_id, Vec3& out) {
    __try {
        uint32_t rw_obj = *(uint32_t*)(ped + 0x18);
        if (!is_valid_ptr(rw_obj)) return false;
        Vec3 tmp = {};
        Vec3* ret = CPed_GetBonePosition((void*)ped, &tmp, bone_id, true);
        if (!ret) return false;
        if (!(tmp.x > -16000.0f && tmp.x < 16000.0f &&
              tmp.y > -16000.0f && tmp.y < 16000.0f &&
              tmp.z > -5000.0f  && tmp.z < 10000.0f)) return false;
        out = tmp;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool world_to_screen(IDirect3DDevice9* dev, const Vec3& w, float& sx, float& sy) {
    D3DVIEWPORT9 vp;
    if (FAILED(dev->GetViewport(&vp)) || vp.Width == 0 || vp.Height == 0) return false;

    __try {
        const float* cm = (const float*)0xB6FA2C;
        float m11 = cm[0],  m12 = cm[1],  m13 = cm[2];
        float m21 = cm[4],  m22 = cm[5],  m23 = cm[6];
        float m31 = cm[8],  m32 = cm[9],  m33 = cm[10];
        float m41 = cm[12], m42 = cm[13], m43 = cm[14];

        if (m11 != 0.0f || m22 != 0.0f || m33 != 0.0f) {
            float rx = w.z * m31 + w.y * m21 + w.x * m11 + m41;
            float ry = w.z * m32 + w.y * m22 + w.x * m12 + m42;
            float rz = w.z * m33 + w.y * m23 + w.x * m13 + m43;
            if (rz < 0.05f) return false;

            float inv = 1.0f / rz;
            sx = rx * inv * (float)vp.Width  + (float)vp.X;
            sy = ry * inv * (float)vp.Height + (float)vp.Y;
            return (sx > -1.0e6f && sx < 1.0e6f && sy > -1.0e6f && sy < 1.0e6f);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    D3DMATRIX view, proj;
    if (g_have_3d) { view = g_3d_view; proj = g_3d_proj; }
    else {
        if (FAILED(dev->GetTransform(D3DTS_VIEW, &view))) return false;
        if (FAILED(dev->GetTransform(D3DTS_PROJECTION, &proj))) return false;
    }
    D3DMATRIX m;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            m.m[i][j] = view.m[i][0]*proj.m[0][j] + view.m[i][1]*proj.m[1][j]
                      + view.m[i][2]*proj.m[2][j] + view.m[i][3]*proj.m[3][j];
    float cx = w.x*m.m[0][0] + w.y*m.m[1][0] + w.z*m.m[2][0] + m.m[3][0];
    float cy = w.x*m.m[0][1] + w.y*m.m[1][1] + w.z*m.m[2][1] + m.m[3][1];
    float cw = w.x*m.m[0][3] + w.y*m.m[1][3] + w.z*m.m[2][3] + m.m[3][3];
    if (cw < 0.05f) return false;
    float inv = 1.0f / cw;
    sx = (cx * inv * 0.5f + 0.5f) * vp.Width  + vp.X;
    sy = (-cy * inv * 0.5f + 0.5f) * vp.Height + vp.Y;
    return (sx > -1.0e6f && sx < 1.0e6f && sy > -1.0e6f && sy < 1.0e6f);
}

struct BonePair { int a; int b; };
static const BonePair SKELETON_PAIRS[] = {
    { 4, 5 }, { 5, 6 },
    { 4, 21 }, { 21, 22 }, { 22, 23 }, { 23, 24 }, { 24, 25 },
    { 4, 31 }, { 31, 32 }, { 32, 33 }, { 33, 34 }, { 34, 35 },
    { 2, 3 }, { 3, 4 },
    { 2, 41 }, { 41, 42 }, { 42, 43 }, { 43, 44 },
    { 2, 51 }, { 51, 52 }, { 52, 53 }, { 53, 54 },
};

static ImU32 health_color_dynamic(float hp_pct) {
    if (hp_pct >= 0.65f) return IM_COL32(  0, 255,   0, 230);
    if (hp_pct >= 0.40f) return IM_COL32(255, 255,   0, 230);
    if (hp_pct >= 0.20f) return IM_COL32(255, 165,   0, 230);
    return                     IM_COL32(255,   0,   0, 230);
}

static void fly_update(float dt) {
    g_fly_active = false;
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) { fly_physics_end(); return; }
    if (!session_live()) return;
    if (!g_fly_enable) {
        g_fly_toggle_on = false;
        g_fly_key_edge = false;
        g_fly_pitch_init = false;
        g_fly_pitch_axis = -1;
        fly_physics_end();
        return;
    }
    if (g_fly_mode != FLY_MODE_TOGGLE) g_fly_mode = FLY_MODE_HOLD;

    bool down = bind_is_down(g_fly_key_vk);
    bool flying;
    if (g_fly_mode == FLY_MODE_TOGGLE) {
        if (down && !g_fly_key_edge) {
            g_fly_toggle_on = !g_fly_toggle_on;
            g_fly_hover_valid = false;
            if (mta_log_tick(5, 300))
                mta_logf("fly", "toggle %s", g_fly_toggle_on ? "ON" : "OFF");
            notify_push("Fly", TROLL_ICON_GLYPH, true,
                        g_fly_toggle_on ? "Fly Habilitado" : "Fly Desabilitado");
        }
        g_fly_key_edge = down;
        flying = g_fly_toggle_on;
    } else {
        g_fly_toggle_on = false;
        g_fly_key_edge = down;
        flying = down;
    }
    if (!flying) {
        g_fly_pitch_init = false;
        g_fly_pitch_axis = -1;
        fly_physics_end();
        return;
    }
    g_fly_active = true;

    float f = 0.0f, s = 0.0f, u = 0.0f;
    if (bind_is_down('W')) f += 1.0f;
    if (bind_is_down('S')) f -= 1.0f;
    if (bind_is_down('D')) s += 1.0f;
    if (bind_is_down('A')) s -= 1.0f;
    if (bind_is_down(VK_SPACE))   u += 1.0f;
    if (bind_is_down(VK_CONTROL)) u -= 1.0f;
    bool has_input = (f != 0.0f || s != 0.0f || u != 0.0f);
    float boost = bind_is_down(VK_SHIFT) ? 2.0f : 1.0f;

    if (dt <= 0.0f || dt > 0.1f) dt = 1.0f / 60.0f;
    uint32_t ped = get_local_ped();
    if (!is_valid_ptr(ped)) { fly_physics_end(); return; }
    __try {
        uint32_t matrix = *(uint32_t*)(uintptr_t)(ped + PED_OFF_MATRIX);
        bool has_mtx = is_valid_ptr(matrix);
        float* pos = has_mtx ? (float*)(uintptr_t)(matrix + CMTX_OFF_POS)
                             : (float*)(uintptr_t)(ped + 0x04);
        if (!pos[0] && !pos[1] && !pos[2]) return;
        if (!(pos[0] > -16000.0f && pos[0] < 16000.0f &&
              pos[1] > -16000.0f && pos[1] < 16000.0f &&
              pos[2] > -5000.0f  && pos[2] < 10000.0f)) return;

        float ddx = pos[0] - g_fly_hover_pos[0];
        float ddy = pos[1] - g_fly_hover_pos[1];
        float ddz = pos[2] - g_fly_hover_pos[2];
        if (!g_fly_hover_valid || (ddx*ddx + ddy*ddy + ddz*ddz) > 160000.0f) {
            g_fly_hover_pos[0] = pos[0];
            g_fly_hover_pos[1] = pos[1];
            g_fly_hover_pos[2] = pos[2];
            g_fly_hover_valid = true;
        }

        float fwd[3]   = { 0.0f, 1.0f, 0.0f };
        float right[3] = { 1.0f, 0.0f, 0.0f };
        bool cam_ok = false;
        fly_camera_axes(g_fly_hover_pos, fwd, right, cam_ok);
        if (!cam_ok && has_mtx) {
            float* rv = (float*)(uintptr_t)(matrix + 0x00);
            float* fv = (float*)(uintptr_t)(matrix + 0x10);
            fwd[0] = fv[0]; fwd[1] = fv[1]; fwd[2] = fv[2];
            right[0] = rv[0]; right[1] = rv[1]; right[2] = rv[2];
            float lf = sqrtf(fwd[0]*fwd[0] + fwd[1]*fwd[1] + fwd[2]*fwd[2]);
            if (lf > 0.0001f) {
                fwd[0] /= lf; fwd[1] /= lf; fwd[2] /= lf;
                cam_ok = true;
            }
        }
        if (!cam_ok && has_input && mta_log_tick(6, 3000))
            mta_logf("fly", "sem view matrix: direcao pela matriz do ped");

        float raw_fwd_z = cam_ok ? fwd[2] : 0.0f;
        float cam_pitch  = fly_camera_pitch();
        if (cam_ok && g_fly_pitch_axis != g_fly_axis_idx) {
            g_fly_pitch_axis = g_fly_axis_idx;
            g_fly_pitch_init = false;
        }
        if (cam_ok && cam_pitch > -0.03f && cam_pitch < 0.03f && !g_fly_pitch_init) {
            // FIX: com camera horizontal, raw_fwd_z deveria ser ~sin(cam_pitch) ≈ cam_pitch.
            // Se estiver muito longe, a view matrix esta stale (transicao de camera).
            // Aceitar o valor envenenava o pitch_base e o fly voava na direcao errada
            // (ex: -0.325 vs -0.030 no log), ampliando o streaming e travando a thread.
            if (fabsf(raw_fwd_z - cam_pitch) < 0.15f) {
                g_fly_pitch_base = raw_fwd_z;
                g_fly_pitch_init = true;
                mta_logf("fly", "pitch base=%.3f cp=%.3f (W horizontal; subir = olhar para cima ou Espaco)",
                         (double)raw_fwd_z, (double)cam_pitch);
            }
        }

        if (has_input) {
            float dx = 0.0f, dy = 0.0f, dz = 0.0f;
            float flat_len = sqrtf(fwd[0]*fwd[0] + fwd[1]*fwd[1]);
            float pitch_delta = g_fly_pitch_init ? (raw_fwd_z - g_fly_pitch_base) : raw_fwd_z;
            // FIX: delta de pitch fora da faixa plausivel = base corrompida.
            // Reseta para re-init no proximo frame com camera horizontal.
            if (g_fly_pitch_init && (pitch_delta > 0.8f || pitch_delta < -0.8f)) {
                g_fly_pitch_init = false;
                pitch_delta = 0.0f;
            }
            if (pitch_delta >  1.0f) pitch_delta =  1.0f;
            if (pitch_delta < -1.0f) pitch_delta = -1.0f;
            if (cam_ok && flat_len > 0.0001f) {
                float hx = fwd[0] / flat_len, hy = fwd[1] / flat_len;
                dx = hx*f + right[0]*s;
                dy = hy*f + right[1]*s;
                dz = u + right[2]*s + f * pitch_delta * 1.5f;
            } else { dx = s; dy = f; dz = u + f * pitch_delta * 1.5f; }
            float len = sqrtf(dx*dx + dy*dy + dz*dz);
            if (len >= 0.0001f) {
                dx /= len; dy /= len; dz /= len;
                if (!(dx > -3.0f && dx < 3.0f)) dx = 0.0f;
                if (!(dy > -3.0f && dy < 3.0f)) dy = 0.0f;
                if (!(dz > -3.0f && dz < 3.0f)) dz = 0.0f;
                float step = g_fly_speed * boost * dt;
                g_fly_hover_pos[0] += dx * step;
                g_fly_hover_pos[1] += dy * step;
                g_fly_hover_pos[2] += dz * step;
            }
        }

        {
            static float prev_hover[3] = { 0.0f, 0.0f, 0.0f };
            static bool  prev_ok = false;
            // FIX streaming: limita o step por frame para o streaming do GTA SA
            // acompanhar. Voar 24 u/s teleporta em setores nao carregados.
            float mx = g_fly_hover_pos[0] - pos[0];
            float my = g_fly_hover_pos[1] - pos[1];
            float mz = g_fly_hover_pos[2] - pos[2];
            float mlen = sqrtf(mx*mx + my*my + mz*mz);
            float max_step = 60.0f * dt;
            if (max_step < 1.0f) max_step = 1.0f;
            if (mlen > max_step) {
                float s = max_step / mlen;
                g_fly_hover_pos[0] = pos[0] + mx * s;
                g_fly_hover_pos[1] = pos[1] + my * s;
                g_fly_hover_pos[2] = pos[2] + mz * s;
            }
            // FIX streaming: delta real do fly (cap em 20 u para descartar
            // teleport/reset do hover) vira velocidade aparente do ped.
            float fdx = 0.0f, fdy = 0.0f, fdz = 0.0f;
            if (prev_ok) {
                fdx = g_fly_hover_pos[0] - prev_hover[0];
                fdy = g_fly_hover_pos[1] - prev_hover[1];
                fdz = g_fly_hover_pos[2] - prev_hover[2];
                float fmag = sqrtf(fdx*fdx + fdy*fdy + fdz*fdz);
                if (fmag > 20.0f) { fdx = fdy = fdz = 0.0f; }
            }
            prev_hover[0] = g_fly_hover_pos[0];
            prev_hover[1] = g_fly_hover_pos[1];
            prev_hover[2] = g_fly_hover_pos[2];
            prev_ok = true;
            pos[0] = g_fly_hover_pos[0];
            pos[1] = g_fly_hover_pos[1];
            pos[2] = g_fly_hover_pos[2];
            fly_physics_apply(ped, fdx, fdy, fdz, dt);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { g_fly_active = false; }
}


#define ADDR_PED_POOL        0xB74490
#define POOL_OBJ_OFF         0x00
#define POOL_FLAG_OFF        0x04
#define POOL_SIZE_OFF        0x08
#define PED_STRIDE           0x7C4

//            codigo-fonte oficial do MTA:SA
//            https://github.com/multitheftauto/mtasa-blue

#define MTA_MAX_VEHICLES       110
#define MTA_MAX_PEDS           140
#define MTA_MAX_OBJECTS        1200
#define MTA_SCLIENT_SIZE       8
#define MTA_SPOOL_DATA(n)      ((n) * MTA_SCLIENT_SIZE + 4)
#define MTA_VPTR_SIZE          4
#define MTA_PED_ARRAY_OFF      (MTA_VPTR_SIZE + MTA_SPOOL_DATA(MTA_MAX_VEHICLES))
#define MTA_POOL_PTRS_OFF      (MTA_PED_ARRAY_OFF + MTA_SPOOL_DATA(MTA_MAX_PEDS) + \
                                MTA_SPOOL_DATA(MTA_MAX_OBJECTS))
#define MTA_PED_STRIDE         1988
#define MTA_CLASS_CPOOL_OBJECT  0xB7449C
#define MTA_CLASS_CPOOL_VEHICLE 0xB74494
#define MTA_VT_GETPLAYERNAMES  10
#define MTA_SSTRING_SIZE       24
#define MTA_MAX_NAMES          256
#define MTA_NICK_SCAN_END      0x1000

static uint32_t g_mta_client_obj    = 0;
static uint32_t g_mta_client_vt     = 0;
static uint32_t g_mta_pools_ptr     = 0;
static uint32_t g_mta_nick_off      = 0;
static bool     g_mta_type_relaxed = false;
static int      g_mta_calib_ents   = 0;
static uint32_t g_mta_last_refresh  = 0;
static uint32_t g_mta_last_calib    = 0;
static uint32_t g_mta_pool_sig_off   = 0;
static uint32_t g_mta_pools_fail_tick = 0;
static bool     g_mta_official_disable = false;

#define NICK_CACHE_SIZE   256
#define NICK_CACHE_TTL    400
struct MtaNickEntry { uint32_t ped; uint32_t tick; char nick[48]; bool valid; };
static MtaNickEntry g_mta_nick_ttl[NICK_CACHE_SIZE] = {};

struct MtaNameVector { uint32_t first, last, end; };
static uint8_t       g_mta_name_storage[MTA_MAX_NAMES * 32];
static MtaNameVector g_mta_name_vec = {};
static bool          g_mta_name_vec_inited = false;
static char          g_mta_official_names[MTA_MAX_NAMES][48];
static int           g_mta_official_count = 0;

static uint32_t rd32(uint32_t addr) {
    if (!is_valid_ptr(addr)) return 0;
    __try { return *(uint32_t*)(uintptr_t)addr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static bool get_module_bounds(const char* mod_name, uint32_t& base_out, uint32_t& end_out) {
    HMODULE hMod = GetModuleHandleA(mod_name);
    if (!hMod) return false;
    __try {
        uint32_t base = (uint32_t)(uintptr_t)hMod;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        base_out = base;
        end_out  = base + nt->OptionalHeader.SizeOfImage;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void mta_writable_range(uint32_t base, uint32_t end, uint32_t& s_out, uint32_t& e_out) {
    s_out = e_out = 0;
    __try {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
            if ((sec[s].Characteristics & IMAGE_SCN_MEM_WRITE) &&
                (sec[s].Characteristics & IMAGE_SCN_MEM_READ)) {
                uint32_t a = base + sec[s].VirtualAddress;
                uint32_t b = a + sec[s].Misc.VirtualSize;
                if (b > end) b = end;
                if (b > a) { s_out = a; e_out = b; return; }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static bool read_msvc_string(uint32_t addr, char* out, uint32_t out_max,
                             uint32_t min_len = 1, uint32_t max_len = 63) {
    if (!is_valid_ptr(addr) || !out || out_max < 2) return false;
    __try {
        uint32_t size = *(uint32_t*)(uintptr_t)(addr + 0x10);
        uint32_t cap  = *(uint32_t*)(uintptr_t)(addr + 0x14);
        if (size < min_len || size > max_len || size >= out_max) return false;
        if (cap < 15 || cap > 255 || size > cap) return false;
        const char* str_ptr;
        if (cap == 15) {
            str_ptr = (const char*)(uintptr_t)addr;
        } else {
            uint32_t heap_ptr = *(uint32_t*)(uintptr_t)addr;
            if (!is_valid_ptr(heap_ptr)) return false;
            str_ptr = (const char*)(uintptr_t)heap_ptr;
        }
        if (str_ptr[size] != '\0') return false;
        for (uint32_t i = 0; i < size; ++i) {
            uint8_t ch = (uint8_t)str_ptr[i];
            if (ch < 0x20 || ch == 0x7F) return false;
        }
        memcpy(out, str_ptr, size);
        out[size] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool is_placeholder_nick(const char* s) {
    if (!s || !s[0]) return true;
    return strcmp(s, "Default") == 0 || strcmp(s, "player") == 0 ||
           strcmp(s, "Player")  == 0 || strcmp(s, "PLAYER") == 0 ||
           strcmp(s, "ped")     == 0 || strcmp(s, "Local")  == 0;
}

static int mta_stricmp(const char* a, const char* b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return (int)ca - (int)cb;
        ++a; ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static const char* mta_strip_color(const char* s) {
    while (s[0] == '#') {
        bool ok = true;
        for (int k = 1; k <= 6; ++k) {
            char c = s[k];
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) { ok = false; break; }
        }
        if (!ok) break;
        s += 7;
    }
    return s;
}

static uint32_t mta_client_base() {
    if (g_mta_client_obj) return g_mta_client_obj;
    uint32_t cb = 0, ce = 0;
    if (!get_module_bounds("client.dll", cb, ce)) return 0;
    uint8_t* exp = (uint8_t*)GetProcAddress((HMODULE)(uintptr_t)cb, "InitClient");
    if (!exp) return 0;
    uint32_t ds = 0, de = 0;
    mta_writable_range(cb, ce, ds, de);
    if (!ds) return 0;
    for (int i = 0; i < 192; ++i) {
        uint32_t cand = rd32((uint32_t)(uintptr_t)(exp + i));
        if (cand < ds || cand + 4 > de) continue;
        uint32_t obj = rd32(cand);
        if (!is_valid_ptr(obj)) continue;
        uint32_t vt = rd32(obj);
        if (vt < cb || vt + (MTA_VT_GETPLAYERNAMES + 1) * 4 > ce) continue;
        uint32_t fn = rd32(vt + MTA_VT_GETPLAYERNAMES * 4);
        if (fn < cb || fn >= ce) continue;
        g_mta_client_obj = obj;
        g_mta_client_vt  = vt;
        return obj;
    }
    return 0;
}

static int mta_refresh_player_names() {
    uint32_t base = mta_client_base();
    uint32_t cb = 0, ce = 0;
    if (!base || !get_module_bounds("client.dll", cb, ce)) return 0;
    if (g_mta_official_disable) return 0;
    uint32_t vt = rd32(base);
    if (vt < cb || vt >= ce) return 0;
    uint32_t fn = rd32(vt + MTA_VT_GETPLAYERNAMES * 4);
    if (fn < cb || fn >= ce) return 0;

    if (!g_mta_name_vec_inited) {
        g_mta_name_vec.first = (uint32_t)(uintptr_t)g_mta_name_storage;
        g_mta_name_vec.last  = g_mta_name_vec.first;
        g_mta_name_vec.end   = g_mta_name_vec.first + sizeof(g_mta_name_storage);
        g_mta_name_vec_inited = true;
    }

    typedef void (__thiscall* MtaGetNamesFn)(void*, void*);
    __try {
        ((MtaGetNamesFn)(uintptr_t)fn)((void*)(uintptr_t)base, &g_mta_name_vec);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    uint32_t first = g_mta_name_vec.first, last = g_mta_name_vec.last;
    if (last < first || last > g_mta_name_vec.end) { g_mta_official_disable = true; mta_logf("nick!", "layout SString divergente: lista oficial desligada"); return 0; }
    uint32_t used = last - first;
    if (used % MTA_SSTRING_SIZE != 0) {
        g_mta_official_disable = true;
        return 0;
    }
    int count = (int)(used / MTA_SSTRING_SIZE);
    if (count > MTA_MAX_NAMES) count = MTA_MAX_NAMES;

    g_mta_official_count = 0;
    for (int i = 0; i < count; ++i) {
        char raw[64] = {};
        g_mta_official_names[i][0] = '\0';
        if (!read_msvc_string(first + (uint32_t)i * MTA_SSTRING_SIZE,
                              raw, sizeof(raw), 1, 63)) continue;
        const char* s = mta_strip_color(raw);
        if (!s[0] || is_placeholder_nick(s)) continue;
        size_t len = strlen(s);
        if (len >= sizeof(g_mta_official_names[i])) len = sizeof(g_mta_official_names[i]) - 1;
        memcpy(g_mta_official_names[i], s, len);
        g_mta_official_names[i][len] = '\0';
        ++g_mta_official_count;
    }
    return g_mta_official_count;
}

static void troll_player_list_refresh() {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    static uint32_t last = 0;
    uint32_t now = GetTickCount();
    if (now - last < 1000) return;
    last = now ? now : 1;
    mta_refresh_player_names();
    int n = 0;
    for (int i = 0; i < g_mta_official_count && n < 64; ++i) {
        if (!g_mta_official_names[i][0]) continue;
        snprintf(g_troll_names[n], sizeof(g_troll_names[n]), "%s", g_mta_official_names[i]);
        ++n;
    }
    for (int i = n; i < 64; ++i) g_troll_names[i][0] = '\0';
    g_troll_count = n;
    bool found = false;
    for (int i = 0; i < g_troll_count; ++i)
        if (strcmp(g_troll_selected_name, g_troll_names[i]) == 0) { found = true; break; }
    if (!found) g_troll_selected_name[0] = '\0';
}

static bool mta_name_in_official_list(const char* s) {
    for (int i = 0; i < MTA_MAX_NAMES; ++i) {
        if (g_mta_official_names[i][0] && mta_stricmp(g_mta_official_names[i], s) == 0)
            return true;
    }
    return false;
}

static bool mta_sig_at(uint32_t pools, uint32_t off) {
    uint32_t a = pools + off;
    return rd32(a)     == ADDR_PED_POOL &&
           rd32(a + 4) == MTA_CLASS_CPOOL_OBJECT &&
           rd32(a + 8) == MTA_CLASS_CPOOL_VEHICLE;
}

static bool mta_cpools_valid(uint32_t pools, uint32_t gb, uint32_t ge) {
    if (!is_valid_ptr(pools)) return false;
    uint32_t vt = rd32(pools);
    if (vt < gb || vt >= ge) return false;
    if (g_mta_pool_sig_off) {
        if (mta_sig_at(pools, g_mta_pool_sig_off)) return true;
        g_mta_pool_sig_off = 0;
    }

    for (int32_t d = -0x1000; d <= 0x1000; d += 4) {
        uint32_t off = MTA_POOL_PTRS_OFF + (uint32_t)d;
        if (mta_sig_at(pools, off)) { g_mta_pool_sig_off = off; return true; }
    }
    for (uint32_t off = 0x400; off <= 0x8000; off += 4) {
        if (mta_sig_at(pools, off)) { g_mta_pool_sig_off = off; return true; }
    }
    return false;
}

static uint32_t mta_find_pools(uint32_t gb, uint32_t ge) {
    if (g_mta_pools_ptr && mta_cpools_valid(g_mta_pools_ptr, gb, ge)) return g_mta_pools_ptr;

    uint32_t now = GetTickCount();
    if (g_mta_pools_fail_tick && (now - g_mta_pools_fail_tick) < 3000) return 0;

    uint32_t ds = 0, de = 0;
    mta_writable_range(gb, ge, ds, de);

    uint32_t pGame = 0;
    uint8_t* exp = (uint8_t*)GetProcAddress((HMODULE)(uintptr_t)gb, "GetGameInterface");
    if (exp && ds) {
        for (int i = 0; i < 192 && !pGame; ++i) {
            uint32_t cand = rd32((uint32_t)(uintptr_t)(exp + i));
            if (cand < ds || cand + 4 > de) continue;
            uint32_t val = rd32(cand);
            if (!is_valid_ptr(val)) continue;
            uint32_t vt = rd32(val);
            if (vt >= gb && vt < ge) pGame = val;
        }
    }

    if (pGame) {
        for (uint32_t off = 4; off <= 0x800; off += 4) {
            uint32_t cand = rd32(pGame + off);
            if (!is_valid_ptr(cand)) continue;
            uint32_t vt = rd32(cand);
            if (vt < gb || vt >= ge) continue;
            if (mta_cpools_valid(cand, gb, ge)) {
                g_mta_pools_ptr = cand;
                mta_logf("pools", "CPoolsSA=%08X sigOff=%04X game_sa=%08X..%08X",
                         cand, g_mta_pool_sig_off, gb, ge);
                return cand;
            }
        }
    }

    if (ds && de) {
        uint32_t lim = de;
        if (lim > ds + 0x20000) lim = ds + 0x20000;
        for (uint32_t a = ds; a + 4 <= lim; a += 4) {
            uint32_t cand = rd32(a);
            if (!is_valid_ptr(cand)) continue;
            uint32_t vt = rd32(cand);
            if (vt < gb || vt >= ge) continue;
            if (mta_cpools_valid(cand, gb, ge)) {
                g_mta_pools_ptr = cand;
                mta_logf("pools", "CPoolsSA=%08X sigOff=%04X game_sa=%08X..%08X",
                         cand, g_mta_pool_sig_off, gb, ge);
                return cand;
            }
        }
    }
    g_mta_pools_fail_tick = now ? now : 1;
    if (mta_log_tick(3, 3000))
        mta_logf("pools!", "CPoolsSA nao encontrado; proxima tentativa em 3s");
    return 0;
}

static bool mta_is_client_player(uint32_t ent, uint32_t cb, uint32_t ce) {
    if (!is_valid_ptr(ent)) return false;
    uint32_t vt = rd32(ent);
    if (vt < cb || vt + 8 > ce) return false;
    if (g_mta_type_relaxed) return true;
    uint32_t fn = rd32(vt + 4);
    if (fn < cb || fn + 8 > ce) return false;
    uint32_t w0 = rd32(fn), w1 = rd32(fn + 4);
    uint8_t b[8];
    memcpy(b, &w0, 4); memcpy(b + 4, &w1, 4);
    bool mov1 = (b[0] == 0xB8 && b[1] == 0x01 && b[2] == 0 && b[3] == 0 && b[4] == 0);
    if (mov1 && (b[5] == 0xC3 || (b[5] == 0xC2 && b[6] == 0 && b[7] == 0))) return true;
    if (b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0x40 && b[3] == 0xC3) return true;
    return false;
}

static uint32_t mta_slot_client_entity(uint32_t slot_addr, uint32_t gb, uint32_t ge,
                                       uint32_t cb, uint32_t ce) {
    (void)gb; (void)ge;
    uint32_t pEntity       = rd32(slot_addr);
    uint32_t pClientEntity = rd32(slot_addr + 4);
    if (!pEntity || !pClientEntity) return 0;
    if (!mta_is_client_player(pClientEntity, cb, ce)) return 0;
    return pClientEntity;
}

static bool mta_ped_context(uint32_t ped, uint32_t& slot_out) {
    uint32_t gb = 0, ge = 0, cb = 0, ce = 0;
    if (!get_module_bounds("game_sa.dll", gb, ge)) return false;
    if (!get_module_bounds("client.dll",  cb, ce)) return false;
    uint32_t pools = mta_find_pools(gb, ge);
    if (!pools) return false;
    uint32_t pool = rd32(ADDR_PED_POOL);
    if (!is_valid_ptr(pool)) return false;
    uint32_t objects = rd32(pool + POOL_OBJ_OFF);
    if (!is_valid_ptr(objects) || ped < objects) return false;
    uint32_t idx = (ped - objects) / MTA_PED_STRIDE;
    if (idx >= MTA_MAX_PEDS) return false;
    slot_out = pools + MTA_PED_ARRAY_OFF + idx * MTA_SCLIENT_SIZE;
    return true;
}

static uint32_t mta_client_entity_for_ped(uint32_t ped) {
    uint32_t slot = 0;
    if (!mta_ped_context(ped, slot)) return 0;
    uint32_t gb = 0, ge = 0, cb = 0, ce = 0;
    if (!get_module_bounds("game_sa.dll", gb, ge)) return 0;
    if (!get_module_bounds("client.dll",  cb, ce)) return 0;
    return mta_slot_client_entity(slot, gb, ge, cb, ce);
}

static int mta_collect_player_entities(uint32_t* out, int cap) {
    if (!out || cap <= 0) return 0;
    uint32_t gb = 0, ge = 0, cb = 0, ce = 0;
    if (!get_module_bounds("game_sa.dll", gb, ge)) return 0;
    if (!get_module_bounds("client.dll",  cb, ce)) return 0;
    uint32_t pools = mta_find_pools(gb, ge);
    if (!pools) return 0;
    for (int pass = 0; pass < 2; ++pass) {
        int n = 0;
        for (uint32_t i = 0; i < MTA_MAX_PEDS && n < cap; ++i) {
            uint32_t slot = pools + MTA_PED_ARRAY_OFF + i * MTA_SCLIENT_SIZE;
            uint32_t e = mta_slot_client_entity(slot, gb, ge, cb, ce);
            if (!e) continue;
            bool dup = false;
            for (int j = 0; j < n; ++j) if (out[j] == e) { dup = true; break; }
            if (!dup) out[n++] = e;
        }
        if (n >= 2) { g_mta_calib_ents = n; return n; }
        if (pass == 0) g_mta_type_relaxed = true;
    }
    g_mta_calib_ents = 0;
    return 0;
}

static bool mta_calibrate_nick_off() {
    uint32_t ents[64];
    int n = mta_collect_player_entities(ents, 64);
    if (n < 1) return false;
    if (n > 10) n = 10;
    bool single = (n < 2);
    if (single && g_mta_official_count < 1) return false;

    uint32_t best_off = 0;
    int      best_score = 0;
    for (uint32_t off = 0x40; off <= MTA_NICK_SCAN_END; off += 4) {
        char vals[10][40];
        int valid = 0, distinct = 0, official = 0;
        for (int j = 0; j < n; ++j) {
            vals[j][0] = '\0';
            if (read_msvc_string(ents[j] + off, vals[j], sizeof(vals[j]), 1, 32) &&
                !is_placeholder_nick(vals[j])) ++valid;
            else vals[j][0] = '\0';
        }
        if (single) {
            if (valid < 1 || !vals[0][0]) continue;
            if (!mta_name_in_official_list(vals[0])) continue;
            int score = 100 + valid;
            if (score > best_score) { best_score = score; best_off = off; }
            continue;
        }
        if (valid < 2) continue;
        for (int j = 0; j < n; ++j) {
            if (!vals[j][0]) continue;
            bool seen = false;
            for (int k = 0; k < j; ++k)
                if (vals[k][0] && mta_stricmp(vals[k], vals[j]) == 0) { seen = true; break; }
            if (!seen) ++distinct;
        }
        if (distinct < 2) continue;
        for (int j = 0; j < n; ++j)
            if (vals[j][0] && mta_name_in_official_list(vals[j])) ++official;
        int score = valid + distinct * 3 + official * 8;
        if (g_mta_official_count > 0 && official == 0) score -= 12;
        if (score > best_score) { best_score = score; best_off = off; }
    }
    if (!best_off) return false;
    g_mta_nick_off = best_off;
    mta_logf("nick", "calibrado: off=%04X score=%d ents=%d nomes=%d",
             best_off, best_score, g_mta_calib_ents, g_mta_official_count);
    return true;
}

static bool nick_cache_lookup(uint32_t ped, char* out, uint32_t sz, bool& hit) {
    hit = false;
    MtaNickEntry& c = g_mta_nick_ttl[(ped >> 4) & (NICK_CACHE_SIZE - 1)];
    if (c.tick == 0 || c.ped != ped) return false;
    if (GetTickCount() - c.tick > NICK_CACHE_TTL) return false;
    hit = true;
    if (!c.valid || !c.nick[0]) return false;
    size_t n = strlen(c.nick);
    if (n >= sz) n = sz - 1;
    memcpy(out, c.nick, n);
    out[n] = '\0';
    return true;
}

static void nick_cache_store(uint32_t ped, const char* nick, bool valid) {
    MtaNickEntry& c = g_mta_nick_ttl[(ped >> 4) & (NICK_CACHE_SIZE - 1)];
    if (c.ped != ped || c.tick == 0) c.nick[0] = '\0';
    c.ped   = ped;
    c.tick  = GetTickCount(); if (!c.tick) c.tick = 1;
    c.valid = valid;
    if (c.ped != ped || c.tick == 0) c.nick[0] = '\0';
    if (valid && nick && nick[0]) {
        size_t n = strlen(nick);
        if (n >= sizeof(c.nick)) n = sizeof(c.nick) - 1;
        memcpy(c.nick, nick, n);
        c.nick[n] = '\0';
    }
}

static bool nick_cache_last(uint32_t ped, char* out, uint32_t sz) {
    MtaNickEntry& c = g_mta_nick_ttl[(ped >> 4) & (NICK_CACHE_SIZE - 1)];
    if (c.tick == 0 || c.ped != ped || !c.nick[0]) return false;
    size_t n = strlen(c.nick);
    if (n >= sz) n = sz - 1;
    memcpy(out, c.nick, n);
    out[n] = '\0';
    return true;
}

static bool get_ped_nickname(int pool_idx, uint32_t ped_interface, bool is_local,
                             char* out_nick, uint32_t out_max) {
    (void)pool_idx; (void)is_local;
    if (!out_nick || out_max < 2) return false;
    out_nick[0] = '\0';
    if (!is_valid_ptr(ped_interface)) return false;
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return false;

    bool hit = false;
    if (nick_cache_lookup(ped_interface, out_nick, out_max, hit)) return true;
    if (hit) return nick_cache_last(ped_interface, out_nick, out_max);

    bool result = false;
    uint32_t now = GetTickCount();
    if (!g_mta_last_refresh || now - g_mta_last_refresh > 1000) {
        g_mta_last_refresh = now;
        mta_refresh_player_names();
    }

    if (!g_mta_nick_off) {
        if (!g_mta_last_calib || now - g_mta_last_calib > 2000) {
            g_mta_last_calib = now;
            if (!mta_calibrate_nick_off()) {
                if (nick_cache_last(ped_interface, out_nick, out_max)) return true;
                nick_cache_store(ped_interface, "", false);
                return false;
            }
        } else {
            if (nick_cache_last(ped_interface, out_nick, out_max)) return true;
            nick_cache_store(ped_interface, "", false);
            return false;
        }
    }

    uint32_t ent = mta_client_entity_for_ped(ped_interface);
    if (ent) {
        if (read_msvc_string(ent + g_mta_nick_off, out_nick, out_max, 1, 32) &&
            !is_placeholder_nick(out_nick)) {
            result = true;
        }
    }
    if (!result) {
        if (nick_cache_last(ped_interface, out_nick, out_max)) return true;
        out_nick[0] = '\0';
    }

    if (mta_log_tick(0, 2000))
        mta_logf("nick", "ped=%08X pools=%08X off=%04X ents=%d nomes=%d ent=%08X ok=%d",
                 ped_interface, g_mta_pools_ptr, g_mta_nick_off, g_mta_calib_ents,
                 g_mta_official_count, ent, result ? 1 : 0);
    nick_cache_store(ped_interface, out_nick, result);
    return result;
}

static void esp_draw_text_outlined(ImDrawList* dl, ImFont* font, float size,
                                   const ImVec2& p, ImU32 col, const char* txt) {
    if (!dl || !txt || !*txt) return;
    if (!font) font = ImGui::GetIO().FontDefault;
    if (!font) return;

    const ImU32 black = IM_COL32(0, 0, 0, ESP_TEXT_STROKE_ALPHA);
    const float o = ESP_TEXT_STROKE;
    static const float ox[4] = { -o,  o,  0,  0 };
    static const float oy[4] = {  0,  0, -o,  o };
    for (int i = 0; i < 4; ++i)
        dl->AddText(font, size, ImVec2(p.x + ox[i], p.y + oy[i]), black, txt);
    dl->AddText(font, size, p, col, txt);
}

static void draw_esp_for_ped(IDirect3DDevice9* dev, uint32_t ped, bool is_local, const char* name,
                             bool show_box, float col_box[4], bool show_box_filled,
                             bool show_lines, float col_lines[3],
                             bool show_names, float col_names[3],
                             bool show_health, float col_health[3], bool show_health_dynamic,
                             bool show_armor, float col_armor[3],
                             bool show_skeleton, float col_skeleton[3],
                             bool show_distance, float col_distance[3]) {
    Vec3 pos;
    float hp = 100.f, max_hp = 100.f, armor = 0.f;

    __try {
        if (!get_ped_world_pos(ped, pos)) return;

        hp     = *(float*)(ped + PED_OFF_HEALTH);
        max_hp = *(float*)(ped + PED_OFF_MAX_HEALTH);
        if (max_hp < 1.0f || max_hp > 10000.0f) max_hp = 100.0f;
        if (hp < 0.0f || hp > max_hp * 2.0f) hp = max_hp;

        armor = *(float*)(ped + PED_OFF_ARMOR);
        if (armor < 0.0f || armor > 500.0f) armor = 0.0f;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    if (hp <= 0.0f) return;

    Vec3 head_w = { pos.x, pos.y, pos.z + 0.85f };
    Vec3 foot_w = { pos.x, pos.y, pos.z - 1.00f };

    float hx, hy, fx, fy;
    bool head_ok = world_to_screen(dev, head_w, hx, hy);
    bool foot_ok = world_to_screen(dev, foot_w, fx, fy);

    if (!head_ok && !foot_ok) return;

    if (head_ok && !foot_ok) {
        float approx_h = 220.0f;
        fx = hx;
        fy = hy + approx_h;
    } else if (!head_ok && foot_ok) {
        float approx_h = 220.0f;
        hx = fx;
        hy = fy - approx_h;
    }

    ImDrawList* dl = ImGui::GetForegroundDrawList();
    ImGuiIO& io = ImGui::GetIO();

    float box_h = fy - hy;
    if (!(box_h >= 0.5f && box_h < 1.0e6f)) return;

    float bx    = (hx + fx) * 0.5f;
    float top   = hy;
    float bottom = fy;

    if (box_h < 6.0f) {
        float cy = (top + bottom) * 0.5f;
        top    = cy - 3.0f;
        bottom = cy + 3.0f;
        box_h  = 6.0f;
    }

    float box_w = box_h * 0.45f;
    if (box_w < 4.0f) box_w = 4.0f;

    float left  = bx - box_w * 0.5f;
    float right = bx + box_w * 0.5f;

    float margin = 300.0f;
    if (right  < -margin || left > io.DisplaySize.x + margin) return;
    if (bottom < -margin || top  > io.DisplaySize.y + margin) return;

    ImU32 c_box  = IM_COL32((int)(col_box[0]*255),      (int)(col_box[1]*255),      (int)(col_box[2]*255),      (int)(col_box[3]*255));
    ImU32 c_line = IM_COL32((int)(col_lines[0]*255),    (int)(col_lines[1]*255),    (int)(col_lines[2]*255),    200);
    ImU32 c_name = IM_COL32((int)(col_names[0]*255),    (int)(col_names[1]*255),    (int)(col_names[2]*255),    255);
    ImU32 c_hp   = IM_COL32((int)(col_health[0]*255),   (int)(col_health[1]*255),   (int)(col_health[2]*255),   230);
    ImU32 c_arm  = IM_COL32((int)(col_armor[0]*255),    (int)(col_armor[1]*255),    (int)(col_armor[2]*255),    230);
    ImU32 c_skel = IM_COL32((int)(col_skeleton[0]*255), (int)(col_skeleton[1]*255), (int)(col_skeleton[2]*255), 255);
    ImU32 c_dist = IM_COL32((int)(col_distance[0]*255), (int)(col_distance[1]*255), (int)(col_distance[2]*255), 255);

    if (show_box) {
        if (show_box_filled) {
            dl->AddRectFilled(ImVec2(left, top), ImVec2(right, bottom), c_box);
        } else {
            dl->AddRect(ImVec2(left, top), ImVec2(right, bottom), c_box, 0.0f, 0, 1.5f);
        }
    }

    if (show_lines) {
        dl->AddLine(ImVec2(io.DisplaySize.x * 0.5f, 0.0f),
                    ImVec2(bx, top), c_line, 1.0f);
    }

    float dist_m = 0.0f;
    if (show_names || show_distance) {
        Vec3 lp;
        uint32_t lped = get_local_ped();
        if (is_valid_ptr(lped) && get_ped_world_pos(lped, lp)) {
            float ddx = pos.x - lp.x;
            float ddy = pos.y - lp.y;
            float ddz = pos.z - lp.z;
            dist_m = sqrtf(ddx * ddx + ddy * ddy + ddz * ddz);
            if (!(dist_m >= 0.0f && dist_m < 100000.0f)) dist_m = 0.0f;
        }
    }

    ImFont* esp_font = g_font_esp_name ? g_font_esp_name
                     : (g_font_regular ? g_font_regular : io.FontDefault);
    const float esp_fs = ESP_NAME_FONT_SIZE;

    if (show_names && name && name[0]) {
        if (esp_font) {
            ImVec2 sz = esp_font->CalcTextSizeA(esp_fs, FLT_MAX, 0.0f, name);
            ImVec2 p(bx - sz.x * 0.5f, top - sz.y - 4.0f);
            esp_draw_text_outlined(dl, esp_font, esp_fs, p, c_name, name);
        }
    }

    if (show_distance && esp_font) {
        char dbuf[32] = {};
        snprintf(dbuf, sizeof(dbuf), "%.0fm", dist_m);
        ImVec2 sz = esp_font->CalcTextSizeA(esp_fs, FLT_MAX, 0.0f, dbuf);
        ImVec2 p(bx - sz.x * 0.5f, bottom + 4.0f);
        esp_draw_text_outlined(dl, esp_font, esp_fs, p, c_dist, dbuf);
    }

    if (show_health && max_hp > 0.0f) {
        float f = hp / max_hp;
        if (f < 0.0f) f = 0.0f;
        if (f > 1.0f) f = 1.0f;
        float bar_w = 3.0f, pad = 3.0f, bx_l = left - bar_w - pad;

        ImU32 hp_fill = show_health_dynamic ? health_color_dynamic(f) : c_hp;

        dl->AddRectFilled(ImVec2(bx_l, top), ImVec2(bx_l + bar_w, bottom),
                          IM_COL32(0, 0, 0, 180));

        float h = (bottom - top) * f;
        dl->AddRectFilled(ImVec2(bx_l, bottom - h), ImVec2(bx_l + bar_w, bottom), hp_fill);

        dl->AddRect(ImVec2(bx_l - 0.5f, top - 0.5f),
                    ImVec2(bx_l + bar_w + 0.5f, bottom + 0.5f),
                    IM_COL32(0, 0, 0, 255), 0.0f, 0, 1.0f);
    }

    if (show_armor && armor > 0.0f) {
        float f = armor / 100.0f;
        if (f > 1.0f) f = 1.0f;
        float bar_w = 3.0f, pad = 3.0f, bx_r = right + pad;
        dl->AddRectFilled(ImVec2(bx_r, top), ImVec2(bx_r + bar_w, bottom), IM_COL32(20, 20, 20, 200));
        float h = (bottom - top) * f;
        dl->AddRectFilled(ImVec2(bx_r, bottom - h), ImVec2(bx_r + bar_w, bottom), c_arm);
    }

    if (show_skeleton) {
        Vec3 bp[64] = {}; bool ok[64] = {};
        for (const BonePair& pair : SKELETON_PAIRS) {
            if (pair.a < 64 && !ok[pair.a]) {
                if (get_bone_pos(ped, pair.a, bp[pair.a])) {
                    float dx = bp[pair.a].x - pos.x, dy = bp[pair.a].y - pos.y, dz = bp[pair.a].z - pos.z;
                    ok[pair.a] = (dx*dx + dy*dy + dz*dz < 12.25f);
                }
            }
            if (pair.b < 64 && !ok[pair.b]) {
                if (get_bone_pos(ped, pair.b, bp[pair.b])) {
                    float dx = bp[pair.b].x - pos.x, dy = bp[pair.b].y - pos.y, dz = bp[pair.b].z - pos.z;
                    ok[pair.b] = (dx*dx + dy*dy + dz*dz < 12.25f);
                }
            }
        }
        for (const BonePair& pair : SKELETON_PAIRS) {
            if (!ok[pair.a] || !ok[pair.b]) continue;
            float ax, ay, bx2, by2;
            if (!world_to_screen(dev, bp[pair.a], ax, ay)) continue;
            if (!world_to_screen(dev, bp[pair.b], bx2, by2)) continue;
            dl->AddLine(ImVec2(ax, ay), ImVec2(bx2, by2), c_skel, ESP_SKELETON_THICKNESS);
        }
    }
}

static void draw_esp_all_players(IDirect3DDevice9* dev) {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    if (!g_esp_local_enable && !g_esp_players_enable) return;

    uint32_t local_ped = get_local_ped();

    auto draw_one = [&](uint32_t ped, bool is_local, const char* name) {
        if (is_local) {
            if (g_esp_local_enable)
                draw_esp_for_ped(dev, ped, true, name,
                    g_esp_local_box,    g_col_local_box,    g_esp_local_box_filled,
                    g_esp_local_lines,  g_col_local_lines,
                    g_esp_local_names,  g_col_local_names,
                    g_esp_local_health, g_col_local_health, g_esp_local_health_dynamic,
                    g_esp_local_armor,  g_col_local_armor,
                    g_esp_local_skeleton,g_col_local_skeleton,
                    g_esp_local_distance, g_col_local_distance);
        } else {
            if (g_esp_players_enable)
                draw_esp_for_ped(dev, ped, false, name,
                    g_esp_players_box,    g_col_players_box,    g_esp_players_box_filled,
                    g_esp_players_lines,  g_col_players_lines,
                    g_esp_players_names,  g_col_players_names,
                    g_esp_players_health, g_col_players_health, g_esp_players_health_dynamic,
                    g_esp_players_armor,  g_col_players_armor,
                    g_esp_players_skeleton,g_col_players_skeleton,
                    g_esp_players_distance, g_col_players_distance);
        }
    };

    bool local_ok = false;
    if (is_valid_ptr(local_ped)) {
        char local_nick[64] = {};
        const char* disp_name = get_ped_nickname(-1, local_ped, true, local_nick, sizeof(local_nick))
                              ? local_nick : "Local";
        draw_one(local_ped, true, disp_name);
        local_ok = true;
    }

    if (!g_esp_players_enable) return;

    int drawn_players = 0;
    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (is_valid_ptr(pool)) {
            uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
            uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
            uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);

            if (is_valid_ptr(objects) && is_valid_ptr(flags) && size > 0) {
                if (size > 256) size = 256;

                for (uint32_t i = 0; i < size; ++i) {
                    uint8_t flag = *(uint8_t*)(flags + i);
                    if (flag & 0x80) continue;

                    uint32_t ped = objects + i * PED_STRIDE;
                    if (!is_valid_ptr(ped)) continue;

                    if (ped == local_ped) continue;

                    Vec3 ped_pos;
                    if (!get_ped_world_pos(ped, ped_pos)) continue;

                    char player_nick[64] = {};
                    const char* disp_name = get_ped_nickname((int)i, ped, false, player_nick, sizeof(player_nick))
                                          ? player_nick : (ESP_SHOW_UNRESOLVED_NAME ? "?" : "");
                    draw_one(ped, false, disp_name);
                    ++drawn_players;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    if (mta_log_tick(1, 2000))
        mta_logf("esp", "local=%s players=%d",
                 local_ok ? "ok" : "none", drawn_players);

}

#define AIMBOT_USE_LIVE_CROSSHAIR 0

static ImVec2 get_gta_sa_crosshair(const ImVec2& display) {
    float mx = 0.53f;
    float my = 0.40f;
    __try {
        float vx = *(float*)0xB6EC14u;
        float vy = *(float*)0xB6EC10u;
        if (vx == vx && vx > 0.25f && vx < 0.75f) mx = vx;
        if (vy == vy && vy > 0.20f && vy < 0.70f) my = vy;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

#if AIMBOT_USE_LIVE_CROSSHAIR
    __try {
        const uint32_t info = 0xB7CD98u;
        uint32_t active = *(uint32_t*)(info + 0x158);
        float nx = *(float*)(info + 0x15C);
        float ny = *(float*)(info + 0x160);
        if (active && nx == nx && ny == ny &&
            nx >= -1.0f && nx <= 1.0f && ny >= -1.0f && ny <= 1.0f) {
            float px = mx * display.x + nx * display.x * 0.5f;
            float py = my * display.y + ny * display.y * 0.5f;
            if (px >= 0.0f && px <= display.x && py >= 0.0f && py <= display.y)
                return ImVec2(px, py);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
    return ImVec2(mx * display.x, my * display.y);
}

static void draw_aimbot_fov() {
    if (!g_aimbot_enable || !g_aimbot_show_fov) return;

    ImGuiIO& io = ImGui::GetIO();
    ImVec2 c = get_gta_sa_crosshair(io.DisplaySize);

    ImU32 col = IM_COL32((int)(g_aimbot_fov_col[0] * 255.0f),
                         (int)(g_aimbot_fov_col[1] * 255.0f),
                         (int)(g_aimbot_fov_col[2] * 255.0f), 255);

    float r = g_aimbot_fov_size;
    if (r < 1.0f)   r = 1.0f;
    if (r > 900.0f) r = 900.0f;

    ImDrawList* dl = ImGui::GetForegroundDrawList();
    dl->AddCircle(c, r, col, 96, 1.5f);
    if (g_aimbot_center_dot)
        dl->AddCircleFilled(c, AIMBOT_CENTER_DOT_RADIUS, col, 12);

    if (g_aimbot_show_target && g_aimbot_aim_on && g_aimbot_has_target) {
        ImVec2 t(g_aimbot_target_sx, g_aimbot_target_sy);
        dl->AddLine(c, t, IM_COL32(255, 255, 255, 90), 1.0f);
        dl->AddCircle(t, 7.0f, col, 20, 2.0f);
    }
}

static float silent_effective_fov() {
    float r = g_silent_fov_size;
    if (r < 1.0f)   r = 1.0f;
    if (r > 900.0f) r = 900.0f;
    return r;
}

static void draw_silent_fov() {
    if (!g_silent_enable || !g_silent_show_fov) return;
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 c = get_gta_sa_crosshair(io.DisplaySize);
    ImU32 col = IM_COL32((int)(g_silent_fov_col[0] * 255.0f),
                         (int)(g_silent_fov_col[1] * 255.0f),
                         (int)(g_silent_fov_col[2] * 255.0f), 255);
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    dl->AddCircle(c, silent_effective_fov(), col, 64, 1.5f);
    if (g_silent_center_dot)
        dl->AddCircleFilled(c, AIMBOT_CENTER_DOT_RADIUS, col, 12);
    if (g_silent_show_target && g_silent_aim_on && g_silent_has_target) {
        ImVec2 t(g_silent_target_sx, g_silent_target_sy);
        dl->AddLine(c, t, IM_COL32(255, 60, 60, 90), 1.0f);
        dl->AddCircle(t, 5.0f, col, 16, 2.0f);
    }
}

static const int AIMBOT_BONE_IDS[7] = {
    5,
    4,
    3,
    22,
    32,
    42,
    52
};

typedef bool (__cdecl *fn_world_los)(const Vec3*, const Vec3*,
    int, int, int, int, int, int, int);

static bool los_available() {
    uint32_t now = GetTickCount();
    if (g_los_avail_tick && now - g_los_avail_tick < 2000) return g_los_avail;
    g_los_avail_tick = now ? now : 1;
    g_los_avail = false;
    __try {
        MEMORY_BASIC_INFORMATION mbi = {};
        void* fn = (void*)(uintptr_t)FUNC_WORLD_IS_LOS_CLEAR;
        if (VirtualQuery(fn, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            uint8_t b = *(uint8_t*)fn;
            g_los_avail = b != 0xE9 && b != 0xE8 && b != 0x00 && b != 0xCC;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { g_los_avail = false; }
    return g_los_avail;
}

static bool los_same_target(const Vec3& a, const Vec3& b) {
    return g_los_have_cache &&
        fabsf(g_los_cache_a[0] - a.x) < 0.25f &&
        fabsf(g_los_cache_a[1] - a.y) < 0.25f &&
        fabsf(g_los_cache_a[2] - a.z) < 0.25f &&
        fabsf(g_los_cache_b[0] - b.x) < 0.25f &&
        fabsf(g_los_cache_b[1] - b.y) < 0.25f &&
        fabsf(g_los_cache_b[2] - b.z) < 0.25f;
}

static bool los_clear(const Vec3& a, const Vec3& b) {
    if (!los_available()) {
        if (!g_los_logged) {
            g_los_logged = true;
            mta_logf("silent", "LOS %08X indisponivel: alvo bloqueado por seguranca",
                     (unsigned)FUNC_WORLD_IS_LOS_CLEAR);
        }
        g_los_have_cache = false;
        return false;
    }
    uint32_t now = GetTickCount();
    if (los_same_target(a, b) && g_los_tick &&
        now - g_los_tick < LOS_RECHECK_MS) return g_los_cached;
    g_los_cached = false;
    __try {
        fn_world_los f = (fn_world_los)(uintptr_t)FUNC_WORLD_IS_LOS_CLEAR;
        g_los_cached = f(&a, &b, 1, 1, 0, 1, 1, 0, 0) ? true : false;
    } __except (EXCEPTION_EXECUTE_HANDLER) { g_los_cached = false; }
    g_los_tick = now ? now : 1;
    g_los_cache_a[0] = a.x; g_los_cache_a[1] = a.y; g_los_cache_a[2] = a.z;
    g_los_cache_b[0] = b.x; g_los_cache_b[1] = b.y; g_los_cache_b[2] = b.z;
    g_los_have_cache = true;
    return g_los_cached;
}

static void silent_update(IDirect3DDevice9* dev) {
    g_silent_has_target = false;
    InterlockedExchange(&g_silent_send_ok, 0);
    if (!session_live()) { g_silent_aim_on = false; return; }
    g_silent_aim_on = g_silent_enable &&
        ((GetAsyncKeyState(g_silent_key_vk) & 0x8000) != 0);
    if (!g_silent_enable || !g_silent_aim_on || g_menu_open ||
        g_silent_capturing || !dev) return;
    HWND fg = GetForegroundWindow();
    HWND game_root = GetAncestor(g_game_hwnd, GA_ROOT);
    if (!fg || !game_root || GetAncestor(fg, GA_ROOT) != game_root) return;

    ImGuiIO& io = ImGui::GetIO();
    const ImVec2 cross = get_gta_sa_crosshair(io.DisplaySize);
    const float radius = silent_effective_fov();
    const int bone = AIMBOT_BONE_IDS[
        (g_silent_bone >= 0 && g_silent_bone < 7) ? g_silent_bone : 0];
    const uint32_t local_ped = get_local_ped();
    float best_d2 = radius * radius;
    bool found = false;

    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (is_valid_ptr(pool)) {
            uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
            uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
            uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
            if (is_valid_ptr(objects) && is_valid_ptr(flags) && size > 0) {
                if (size > 256) size = 256;
                for (uint32_t i = 0; i < size; ++i) {
                    uint8_t flag = *(uint8_t*)(flags + i);
                    if (flag & 0x80) continue;
                    uint32_t ped = objects + i * PED_STRIDE;
                    if (!is_valid_ptr(ped) || ped == local_ped) continue;
                    float hp = *(float*)(ped + PED_OFF_HEALTH);
                    if (!(hp > 0.0f && hp < 10000.0f)) continue;
                    Vec3 pos;
                    if (!get_ped_world_pos(ped, pos)) continue;
                    Vec3 aim;
                    if (!get_bone_pos(ped, bone, aim)) {
                        aim = pos;
                        aim.z += 1.0f;
                    }
                    float sx = 0.0f, sy = 0.0f;
                    if (!world_to_screen(dev, aim, sx, sy)) continue;
                    float ddx = sx - cross.x, ddy = sy - cross.y;
                    float d2 = ddx * ddx + ddy * ddy;
                    if (d2 < best_d2) {
                        best_d2 = d2;
                        g_silent_target_sx = sx;
                        g_silent_target_sy = sy;
                        g_silent_aim_point[0] = aim.x;
                        g_silent_aim_point[1] = aim.y;
                        g_silent_aim_point[2] = aim.z;
                        found = true;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    if (found && !g_silent_ignore_walls) {
        Vec3 src;
        Vec3 dst;
        dst.x = g_silent_aim_point[0];
        dst.y = g_silent_aim_point[1];
        dst.z = g_silent_aim_point[2];
        if (!get_ped_world_pos(local_ped, src)) found = false;
        else {
            src.z += 1.0f;
            if (!los_clear(src, dst)) found = false;
        }
    }
    g_silent_has_target = found;
    InterlockedExchange(&g_silent_send_ok,
        (found && session_live() && !conn_handshake_active() && !g_menu_open &&
         !InterlockedCompareExchange(&g_shutdown_all, 0, 0)) ? 1 : 0);
}


static __declspec(naked) void hk_mta_fire_mid() {
    __asm {
        cmp dword ptr [g_session_live], 0
        je  short pass_fire_mid
        cmp dword ptr [g_silent_send_ok], 0
        je  short pass_fire_mid
        mov eax, offset g_silent_aim_point
        mov ecx, dword ptr [eax]
        mov edx, dword ptr [eax + 4]
        mov eax, dword ptr [eax + 8]
        mov dword ptr [esp + 10h], ecx
        mov dword ptr [esp + 14h], edx
        mov dword ptr [esp + 18h], eax
      pass_fire_mid:
        jmp dword ptr [g_o_mta_fire_mid]
    }
}

static __declspec(naked) void hk_mta_sniper_mid() {
    __asm {
        cmp dword ptr [g_session_live], 0
        je  short pass_sniper_mid
        cmp dword ptr [g_silent_send_ok], 0
        je  short pass_sniper_mid
        mov eax, offset g_silent_aim_point
        mov ecx, dword ptr [eax]
        mov edx, dword ptr [eax + 4]
        mov eax, dword ptr [eax + 8]
        mov dword ptr [esp + 3Ch], ecx
        mov dword ptr [esp + 40h], edx
        mov dword ptr [esp + 44h], eax
      pass_sniper_mid:
        jmp dword ptr [g_o_mta_sniper_mid]
    }
}

static bool silent_patch_mid(uint32_t pos, void* detour, void** mta_hook) {
    uint8_t* p = (uint8_t*)(uintptr_t)pos;
    __try {
        if (p[0] != 0xE9) return false;
        int32_t rel = *(int32_t*)(p + 1);
        uint32_t dest = pos + 5 + (uint32_t)rel;
        if (dest < 0x10000u || dest > 0x7FFFFFFFu) return false;
        *mta_hook = (void*)(uintptr_t)dest;
        if (g_patch_count >= 60) return false;
        DWORD oldp = 0;
        if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &oldp)) return false;
        PatchRecord& pr = g_patches[g_patch_count];
        pr.addr = p;
        memcpy(pr.original, p, 5);
        pr.detour = detour;
        p[0] = 0xE9;
        *(int32_t*)(p + 1) = (int32_t)((uintptr_t)detour - pos - 5);
        VirtualProtect(p, 5, oldp, &oldp);
        FlushInstructionCache(GetCurrentProcess(), p, 5);
        ++g_patch_count;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void silent_install_mid_hooks() {
    if (!g_silent_mid_ok) {
        void* det = (void*)(uintptr_t)&hk_mta_fire_mid;
        if (silent_patch_mid(MTA_FIRE_MID_POS, det, &g_o_mta_fire_mid)) {
            g_silent_mid_ok = true;
            mta_logf("silent", "bulletsync instanthit %08X -> MTA %08X: end=esp+%02X start intacto",
                     (unsigned)MTA_FIRE_MID_POS,
                     (unsigned)(uintptr_t)g_o_mta_fire_mid,
                     (unsigned)MTA_FIRE_MID_END);
        } else if (!g_silent_mid_logged) {
            g_silent_mid_logged = true;
            mta_logf("silent", "mid %08X sem JMP do MTA: bulletsync nao redirecionado",
                     (unsigned)MTA_FIRE_MID_POS);
        }
    }
    if (!g_silent_sniper_ok) {
        void* det = (void*)(uintptr_t)&hk_mta_sniper_mid;
        if (silent_patch_mid(MTA_SNIPER_MID_POS, det, &g_o_mta_sniper_mid)) {
            g_silent_sniper_ok = true;
            mta_logf("silent", "bulletsync sniper %08X -> MTA %08X: end=esp+%02X",
                     (unsigned)MTA_SNIPER_MID_POS,
                     (unsigned)(uintptr_t)g_o_mta_sniper_mid,
                     (unsigned)MTA_SNIPER_MID_END);
        } else if (!g_silent_sniper_logged) {
            g_silent_sniper_logged = true;
            mta_logf("silent", "mid %08X sem JMP do MTA: sniper nao redirecionado",
                     (unsigned)MTA_SNIPER_MID_POS);
        }
    }
}

using fn_fire_instant_hit = void (__fastcall *)(void*, void*);

static __declspec(naked) void hk_fire_instant_hit() {
    __asm {
        pushad
        cmp dword ptr [g_session_live], 0
        je  short pass_silent
        cmp dword ptr [g_silent_send_ok], 0
        je  short pass_silent
        cmp byte ptr [g_silent_enable], 0
        je  short pass_silent
        cmp byte ptr [g_silent_aim_on], 0
        je  short pass_silent
        cmp byte ptr [g_silent_has_target], 0
        je  short pass_silent
        cmp dword ptr [g_shutdown_all], 0
        jne short pass_silent
        mov eax, offset g_silent_aim_point
        mov dword ptr [esp + 34h], eax
      pass_silent:
        popad
        jmp dword ptr [g_o_FireInstantHit]
    }
}

static void silent_retire_hooks() {
    int w = 0;
    for (int i = 0; i < g_patch_count && i < 64; ++i) {
        PatchRecord pr = g_patches[i];
        uint32_t a = (uint32_t)(uintptr_t)pr.addr;
        if (a != SILENT_FIRE_INSTANT_HIT && a != MTA_FIRE_MID_POS &&
            a != MTA_SNIPER_MID_POS) {
            if (w != i) g_patches[w] = pr;
            ++w;
            continue;
        }
        __try {
            DWORD oldp = 0;
            if (VirtualProtect(pr.addr, 5, PAGE_EXECUTE_READWRITE, &oldp)) {
                memcpy(pr.addr, pr.original, 5);
                VirtualProtect(pr.addr, 5, oldp, &oldp);
                FlushInstructionCache(GetCurrentProcess(), pr.addr, 5);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    g_patch_count = w;
    g_o_FireInstantHit = nullptr;
    g_o_mta_fire_mid = nullptr;
    g_o_mta_sniper_mid = nullptr;
    g_silent_hook_ok = false;
    g_silent_mid_ok = false;
    g_silent_sniper_ok = false;
    g_silent_mid_logged = false;
    g_silent_sniper_logged = false;
}

static void silent_install_hook() {
    if (g_silent_hook_ok) return;
    if (g_patch_count >= 60) return;
    uint8_t* p = (uint8_t*)(uintptr_t)SILENT_FIRE_INSTANT_HIT;
    __try {
        uint8_t b = p[0];
        uint8_t q[5] = { p[0], p[1], p[2], p[3], p[4] };
        mta_logf("silent", "FireInstantHit prologo %02X %02X %02X %02X %02X",
                 (unsigned)q[0], (unsigned)q[1], (unsigned)q[2],
                 (unsigned)q[3], (unsigned)q[4]);
        if (b == 0xE9 || b == 0xE8 || b == 0xEB || b == 0x00 || b == 0xCC) {
            mta_logf("silent", "FireInstantHit ja modificado (byte=%02X): hook nao instalado", (unsigned)b);
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    fn_fire_instant_hit tramp = nullptr;
    if (patch_jmp((void*)(uintptr_t)SILENT_FIRE_INSTANT_HIT,
                  reinterpret_cast<fn_fire_instant_hit>(&hk_fire_instant_hit), tramp)) {
        g_o_FireInstantHit = (void*)(uintptr_t)tramp;
        g_silent_hook_ok = true;
        mta_logf("silent", "trajetoria local instalada em %08X; pacote via mid %08X (id=%d)",
                 (unsigned)SILENT_FIRE_INSTANT_HIT,
                 (unsigned)MTA_FIRE_MID_POS, (int)MTA_PACKET_BULLETSYNC);
    } else {
        mta_logf("silent", "falha ao instalar redirecionamento de trajetoria");
    }
}

static void aimbot_run(IDirect3DDevice9* dev) {
    g_aimbot_has_target = false;
    if (!session_live()) return;
    if (!g_aimbot_enable || !g_aimbot_aim_on ||
        g_menu_open || g_aimbot_capturing || !dev) return;

    HWND fg = GetForegroundWindow();
    HWND game_root = GetAncestor(g_game_hwnd, GA_ROOT);
    if (!fg || !game_root || GetAncestor(fg, GA_ROOT) != game_root) return;

    ImGuiIO& io = ImGui::GetIO();
    const ImVec2 cross = get_gta_sa_crosshair(io.DisplaySize);

    float radius = g_aimbot_fov_size;
    if (radius < 1.0f)   radius = 1.0f;
    if (radius > 900.0f) radius = 900.0f;

    const int bone = AIMBOT_BONE_IDS[
        (g_aimbot_bone >= 0 && g_aimbot_bone < 7) ? g_aimbot_bone : 0];

    const uint32_t local_ped = get_local_ped();
    float best_d2 = radius * radius;
    float best_sx = 0.0f, best_sy = 0.0f;
    bool  found   = false;

    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (is_valid_ptr(pool)) {
            uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
            uint32_t flags   = *(uint32_t*)(pool + POOL_FLAG_OFF);
            uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
            if (is_valid_ptr(objects) && is_valid_ptr(flags) && size > 0) {
                if (size > 256) size = 256;
                for (uint32_t i = 0; i < size; ++i) {
                    uint8_t flag = *(uint8_t*)(flags + i);
                    if (flag & 0x80) continue;

                    uint32_t ped = objects + i * PED_STRIDE;
                    if (!is_valid_ptr(ped) || ped == local_ped) continue;

                    float hp = *(float*)(ped + PED_OFF_HEALTH);
                    if (!(hp > 0.0f && hp < 10000.0f)) continue;

                    Vec3 pos;
                    if (!get_ped_world_pos(ped, pos)) continue;

#if AIMBOT_ONLY_REAL_PLAYERS
                    char nick[64] = {};
                    if (!get_ped_nickname((int)i, ped, false, nick, sizeof(nick))) continue;
#endif
                    Vec3 aim;
                    if (!get_bone_pos(ped, bone, aim)) {
                        aim = pos;
                        aim.z += 1.0f;
                    }

                    float sx = 0.0f, sy = 0.0f;
                    if (!world_to_screen(dev, aim, sx, sy)) continue;

                    float ddx = sx - cross.x;
                    float ddy = sy - cross.y;
                    float d2  = ddx * ddx + ddy * ddy;
                    if (d2 < best_d2) {
                        best_d2 = d2;
                        best_sx = sx;
                        best_sy = sy;
                        found = true;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return; }

    if (!found) return;
    g_aimbot_has_target = true;
    g_aimbot_target_sx  = best_sx;
    g_aimbot_target_sy  = best_sy;

    const float sm = g_aimbot_smooth;
    const bool  snap = (sm <= 0.001f);
    const float step = snap ? 1.0f : 1.0f / (1.0f + sm * 0.1f);
    const float cap  = snap ? AIMBOT_SNAP_MAX_PIXELS : 600.0f;
    float dx = (best_sx - cross.x) * step * AIMBOT_MOUSE_SENS;
    float dy = (best_sy - cross.y) * step * AIMBOT_MOUSE_SENS;
    if (dx >  cap) dx =  cap;
    if (dx < -cap) dx = -cap;
    if (dy >  cap) dy =  cap;
    if (dy < -cap) dy = -cap;

#if AIMBOT_AIM_MODE == 0
    static float acc_x = 0.0f, acc_y = 0.0f;
    if (snap) {
        acc_x = 0.0f;
        acc_y = 0.0f;
        float rx = dx, ry = dy;
        if (rx == rx && ry == ry) {
            for (int guard = 0; guard < 16; ++guard) {
                int ix = (int)rx;
                int iy = (int)ry;
                if (ix >  300) ix =  300;
                if (ix < -300) ix = -300;
                if (iy >  300) iy =  300;
                if (iy < -300) iy = -300;
                if (!ix && !iy) break;
                mouse_event(MOUSEEVENTF_MOVE, (DWORD)(LONG)ix, (DWORD)(LONG)iy, 0, 0);
                rx -= (float)ix;
                ry -= (float)iy;
            }
        }
    } else {
        acc_x += dx;
        acc_y += dy;
        int ix = (int)acc_x;
        int iy = (int)acc_y;
        acc_x -= (float)ix;
        acc_y -= (float)iy;
        if (ix >  300) ix =  300;
        if (ix < -300) ix = -300;
        if (iy >  300) iy =  300;
        if (iy < -300) iy = -300;
        if (ix || iy)
            mouse_event(MOUSEEVENTF_MOVE, (DWORD)(LONG)ix, (DWORD)(LONG)iy, 0, 0);
    }
#else
    __try {
        uint8_t active = *(uint8_t*)0xB6F081u;
        if (active < 3) {
            uint32_t cam = 0xB6F19Cu + (uint32_t)active * 0x238u;
            volatile float* yaw   = (volatile float*)(cam + 0xBCu);
            volatile float* pitch = (volatile float*)(cam + 0xACu);
            const float cy = *yaw;
            const float cp = *pitch;
            if (cy > -20.0f && cy < 20.0f && cp > -20.0f && cp < 20.0f &&
                io.DisplaySize.x > 0.0f && io.DisplaySize.y > 0.0f) {
                const float fov_rad = 70.0f * 3.14159265f / 180.0f;
                *yaw   = cy - dx * (fov_rad / io.DisplaySize.x) * AIMBOT_CAM_YAW_SIGN;
                *pitch = cp + dy * (fov_rad / io.DisplaySize.y) * AIMBOT_CAM_PITCH_SIGN;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
}

static HRESULT __stdcall hk_Reset(IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* pParams) {
    g_have_3d = false;
    // Reset pode trocar o modo (windowed <-> fullscreen): forca reaplicar WDA
    g_stream_proof_hwnd    = nullptr;
    g_stream_proof_applied = WDA_NONE_VALUE;
    g_stream_proof_last_try = 0;
    if (g_imgui_init) ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_o_Reset(pDevice, pParams);
    if (SUCCEEDED(hr) && g_imgui_init) {
        ImGui_ImplDX9_CreateDeviceObjects();
        InterlockedExchange(&g_imgui_invalidated, 0);
    }
    return hr;
}

static HRESULT __stdcall hk_Present(IDirect3DDevice9* pDevice,
                                    const RECT* pSrc, const RECT* pDst,
                                    HWND hWnd, const RGNDATA* pDirty) {
    if (g_imgui_init) {
        HRESULT coop = pDevice->TestCooperativeLevel();
        if (coop == D3DERR_DEVICENOTRESET) {
            if (InterlockedCompareExchange(&g_imgui_invalidated, 1, 0) == 0)
                ImGui_ImplDX9_InvalidateDeviceObjects();
        } else if (coop == D3D_OK) {
            InterlockedExchange(&g_imgui_invalidated, 0);
        }
    }
    return g_o_Present(pDevice, pSrc, pDst, hWnd, pDirty);
}

static HRESULT __stdcall hk_SetTransform(IDirect3DDevice9* dev, D3DTRANSFORMSTATETYPE state, const D3DMATRIX* m) {
    if (m) {
        if (state == D3DTS_VIEW) {
            g_current_view = *m;
        } else if (state == D3DTS_PROJECTION) {
            if (is_perspective(m)) {
                g_3d_view = g_current_view;
                g_3d_proj = *m;
                g_have_3d = true;
            }
        }
    }
    return g_o_SetTransform(dev, state, m);
}

static int      g_sess_state     = 0;
static int      g_sess_stable    = 0;
static bool     g_sess_last_raw  = false;
static uint32_t g_sess_tick      = 0;
static uint32_t g_sess_lost      = 0;
static bool     g_sess_saved     = false;
static bool     g_sess_menu_open = false;
static bool     g_sess_prev_menu = false;
static bool     g_sess_prev_ins  = false;
static unsigned char g_sess_snap[CFG_ENTRY_COUNT][16] = {};

static size_t sess_entry_size(int type) {
    if (type == CFG_BOOL)  return sizeof(bool);
    if (type == CFG_INT)   return sizeof(int);
    if (type == CFG_FLOAT) return sizeof(float);
    if (type == CFG_COL3)  return 3 * sizeof(float);
    if (type == CFG_COL4)  return 4 * sizeof(float);
    return 0;
}

static bool sess_probe() {
    uint32_t ped = get_local_ped();
    if (!is_valid_ptr(ped)) return false;
    __try {
        uint32_t pool = *(uint32_t*)ADDR_PED_POOL;
        if (!is_valid_ptr(pool)) return false;
        uint32_t objects = *(uint32_t*)(pool + POOL_OBJ_OFF);
        uint32_t size    = *(uint32_t*)(pool + POOL_SIZE_OFF);
        if (size == 0 || size > 512 || !is_valid_ptr(objects)) return false;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void sess_disable_all() {
    if (g_sess_saved) return;
    fly_physics_end();
    rapid_fire_restore();
    g_silent_aim_on = g_silent_has_target = false;
    g_silent_capturing = false;
    InterlockedExchange(&g_silent_send_ok, 0);
    for (int i = 0; i < CFG_ENTRY_COUNT; ++i) {
        if (strcmp(CFG_ENTRIES[i].key, "misc.streamproof") == 0) continue;
        size_t n = sess_entry_size(CFG_ENTRIES[i].type);
        if (n && n <= 16) memcpy(g_sess_snap[i], CFG_ENTRIES[i].ptr, n);
    }
    g_sess_menu_open = g_menu_open;
    g_sess_prev_menu = g_prev_menu_open;
    g_sess_prev_ins  = g_prev_insert;
    g_sess_saved = true;

    for (int i = 0; i < CFG_ENTRY_COUNT; ++i)
        if (CFG_ENTRIES[i].type == CFG_BOOL &&
            strcmp(CFG_ENTRIES[i].key, "misc.streamproof") != 0)
            *(bool*)CFG_ENTRIES[i].ptr = false;

    g_aimbot_aim_on = g_aimbot_has_target = false;
    g_aimbot_capturing = g_aimbot_key_held = false;
    g_bind_capture = 0; g_bind_capture_tick = 0;
    g_menu_key_latch = (GetAsyncKeyState(g_menu_key_vk) & 0x8000) != 0;
    InterlockedExchange(&g_menu_toggle_pending, 0);
    g_fly_key_prev = g_fly_key_held = false;
    g_fly_active = false;
    g_fly_toggle_on = false; g_fly_key_edge = false;
    g_fly_hover_valid = false;
    g_menu_open = false; g_prev_menu_open = false; g_prev_insert = false;
    g_cfg_pending_overwrite = false; g_cfg_pending_delete = false;

    session_fail_closed(5);
    silent_retire_hooks();
    ClipCursor(nullptr);
    mta_logf("conn", "desconectado/main menu: %d opcoes desligadas (snapshot salvo)", CFG_ENTRY_COUNT);
}

static void sess_restore_all() {
    if (!g_sess_saved) return;
    for (int i = 0; i < CFG_ENTRY_COUNT; ++i) {
        if (strcmp(CFG_ENTRIES[i].key, "misc.streamproof") == 0) continue;
        size_t n = sess_entry_size(CFG_ENTRIES[i].type);
        if (n && n <= 16) memcpy(CFG_ENTRIES[i].ptr, g_sess_snap[i], n);
    }
    g_menu_open = g_sess_menu_open;
    g_prev_menu_open = g_sess_prev_menu;
    g_prev_insert = g_sess_prev_ins;
    g_sess_saved = false;

    if (g_menu_key_vk <= 0 || g_menu_key_vk > 255) g_menu_key_vk = VK_INSERT;
    if (g_fly_key_vk  <= 0 || g_fly_key_vk  > 255) g_fly_key_vk  = VK_F8;
    if (g_aimbot_key_vk <= 0 || g_aimbot_key_vk > 255) g_aimbot_key_vk = VK_XBUTTON1;
    if (g_silent_key_vk <= 0 || g_silent_key_vk > 255) g_silent_key_vk = VK_XBUTTON2;
    g_silent_fov_size = cfg_clampf(g_silent_fov_size, 1.0f, 900.0f);
    g_silent_bone = g_silent_bone < 0 ? 0 : (g_silent_bone > 6 ? 6 : g_silent_bone);
    g_fly_mode = (g_fly_mode == FLY_MODE_TOGGLE) ? FLY_MODE_TOGGLE : FLY_MODE_HOLD;
    g_fly_speed = cfg_clampf(g_fly_speed, 1.0f, 60.0f);
    bind_format_key(g_menu_key_vk, g_menu_key_name, sizeof(g_menu_key_name));
    bind_format_key(g_fly_key_vk,  g_fly_key_name,  sizeof(g_fly_key_name));
    bind_format_key(g_silent_key_vk, g_silent_key_name, sizeof(g_silent_key_name));
    aimbot_set_key(g_aimbot_key_vk);
    g_silent_aim_on = g_silent_has_target = false;
    g_silent_capturing = false;
    InterlockedExchange(&g_silent_send_ok, 0);
    session_fail_closed(10);
    g_fly_toggle_on = false; g_fly_key_edge = false;
    g_fly_hover_valid = false;
    mta_logf("conn", "conectado: %d opcoes restauradas do snapshot", CFG_ENTRY_COUNT);
}

static void reconnect_guard() {
    HMODULE cur = GetModuleHandleA("netc.dll");
    uint32_t base = (uint32_t)(uintptr_t)cur;
    uint32_t size = netc_image_size(cur);
    uint32_t old_base = g_netc_base;
    uint32_t now = GetTickCount();
    if (!g_netc_base && base) {
        g_netc_base = base;
        g_netc_size = size;
        return;
    }
    if (old_base && !base) {
        if (!g_netc_needs_reinstall) {
            session_fail_closed(1);
            arm_switch_park(now);
            netc_retire_stale_patches(0, 0);
            g_conn_grace = 0;
            if (!g_netc_unload_logged) {
                g_netc_unload_logged = true;
                mta_logf("conn", "netc descarregado: hooks restaurados e park iniciado, aguardando reload");
            }
        }
    } else if (old_base && base && (g_netc_needs_reinstall || base != old_base)) {
        if (!g_switch_rebase_seen) {
            session_fail_closed(2);
            arm_switch_park(now);
            bool moved = (base != old_base);
            netc_rebase_patches(base, size);
            if (moved) {
                ++g_install_generation;
                install_all();
            }
            g_switch_rebase_seen = true;
            g_conn_grace = now ? now : 1;
            g_session_fail_logged = false;
            if (!g_netc_rebase_logged) {
                g_netc_rebase_logged = true;
                mta_logf("conn", "netc %s %08X -> %08X: reinstall adiado para depois do handshake",
                         moved ? "realocado" : "recarregado",
                         (unsigned)old_base, (unsigned)base);
            }
        }
    }
    if (g_conn_grace && !conn_handshake_active())
        mta_logf("conn", "handshake concluido: recursos liberados sem tocar no send_packet");
}

static void session_monitor() {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) return;
    uint32_t now = GetTickCount();
    if (now - g_sess_tick < 200) return;
    g_sess_tick = now ? now : 1;
    bool active = sess_probe();
    reconnect_guard();
    g_server_kick_seen = 0;
    bool quarantined = g_quarantine_until &&
        (now - g_quarantine_until < RECONNECT_QUARANTINE_MS);
    bool parked = g_switch_park_until &&
        (int32_t)(g_switch_park_until - now) > 0;
    if (!parked && g_netc_needs_reinstall && g_netc_base) {
        g_netc_needs_reinstall = false;
        g_switch_rebase_seen = false;
        unpark_netc_hooks();
        mta_logf("safe", "troca de servidor: handshake concluido, trajetoria pode voltar");
    }
    if (!parked) g_switch_park_until = 0;
    bool live = active && !parked && !conn_handshake_active() && !quarantined &&
        !g_sess_saved && !g_netc_needs_reinstall &&
        g_netc_base && g_sess_stable >= 8 &&
        !InterlockedCompareExchange(&g_emergency_done, 0, 0);
    if (live) {
        InterlockedExchange(&g_session_live, 1);
        g_session_live_tick = now ? now : 1;
        g_fail_clean_done = false;
        if (!g_silent_hook_ok) silent_install_hook();
        if (!g_silent_mid_ok || !g_silent_sniper_ok) silent_install_mid_hooks();
    } else {
        session_fail_closed(active ? 8u : 9u);
    }
    if (active && !g_conn_prev_active) {
        g_conn_grace = now ? now : 1;
        g_sess_stable = 0;
        mta_logf("conn", "conectado: janela de handshake iniciada");
    } else if (!active && g_conn_prev_active) {
        g_conn_grace = 0;
        rapid_fire_restore();
        fly_physics_end();
        session_fail_closed(3);
        silent_retire_hooks();
        g_silent_capturing = false;
        mta_logf("conn", "desconectado: trajetoria, animacao e fisica restauradas antes do proximo servidor");
    }
    g_conn_prev_active = active;
    if (active == g_sess_last_raw) {
        if (g_sess_stable < 100) ++g_sess_stable;
    } else {
        g_sess_stable = 0;
        g_sess_last_raw = active;
    }
    if (g_game_hwnd && !IsWindow(g_game_hwnd)) {
        if (!g_sess_lost) g_sess_lost = now ? now : 1;
        else if (!active && (now - g_sess_lost) > 3000) {
            emergency_disable_all();
            return;
        }
    } else g_sess_lost = 0;
    if (g_sess_stable < 8) return;
    int want = active ? 1 : 2;
    g_sess_state = want;
    if (want == 2 && !g_sess_saved) sess_disable_all();
    else if (want == 1 && g_sess_saved && !conn_handshake_active() &&
             !quarantined) sess_restore_all();
}

static void quit_early_probe() {
}

static const uint32_t RF_TABLE_CANDIDATES[] = { ADDR_WEAPON_INFO_ARRAY, ADDR_WEAPON_INFO_ALT };

typedef void* (__cdecl *rf_get_wi_fn)(int, int);

static uint32_t rf_wi_addr(int type) {
    return g_rf_table + (uint32_t)type * WEAPON_INFO_STRIDE;
}

static bool rf_readable(uint32_t addr, uint32_t size) {
    __try {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        uint32_t region_end = (uint32_t)(uintptr_t)mbi.BaseAddress + (uint32_t)mbi.RegionSize;
        return addr + size <= region_end;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool rf_entry_valid(uint32_t b) {
    __try {
        short    clip = *(short*)(b + WI_OFF_AMMO_CLIP);
        uint32_t slot = *(uint32_t*)(b + WI_OFF_SLOT);
        float    st   = *(float*)(b + WI_OFF_ANIM_LOOP_START);
        float    en   = *(float*)(b + WI_OFF_ANIM_LOOP_END);
        float    fi   = *(float*)(b + WI_OFF_ANIM_LOOP_FIRE);
        if (!(clip > 0 && clip <= 100 && slot < 13)) return false;
        return st >= 0.0f && fi >= st - 0.0001f && en > fi && en < 20.0f;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static bool rf_table_valid(uint32_t base) {
    if (!rf_readable(base, RF_TABLE_MAX_ENTRIES * WEAPON_INFO_STRIDE)) return false;
    int hits = 0;
    for (int t = RF_FIRE_ANIM_MIN; t <= RF_FIRE_ANIM_MAX; ++t)
        if (rf_entry_valid(base + (uint32_t)t * WEAPON_INFO_STRIDE)) ++hits;
    return hits >= 9;
}

static uint32_t rf_find_table() {
    for (int i = 0; i < 2; ++i)
        if (rf_table_valid(RF_TABLE_CANDIDATES[i])) return RF_TABLE_CANDIDATES[i];
    for (uint32_t a = 0xC89000; a <= 0xC8C000; a += 4)
        if (rf_table_valid(a)) return a;
    if (!g_rf_probe_logged) {
        g_rf_probe_logged = true;
        __try {
            uint8_t* b = (uint8_t*)(RF_TABLE_CANDIDATES[0] + 31 * WEAPON_INFO_STRIDE);
            mta_logf("rf", "tabela nao encontrada base=%08X clip=%d slot=%u start=%.4f fire=%.4f end=%.4f",
                     (unsigned)RF_TABLE_CANDIDATES[0],
                     (int)*(short*)(b + WI_OFF_AMMO_CLIP),
                     *(uint32_t*)(b + WI_OFF_SLOT),
                     (double)*(float*)(b + WI_OFF_ANIM_LOOP_START),
                     (double)*(float*)(b + WI_OFF_ANIM_LOOP_FIRE),
                     (double)*(float*)(b + WI_OFF_ANIM_LOOP_END));
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    return 0;
}

static uint32_t rf_resolve(int type, int skill) {
    __try {
        if (rf_readable(FUNC_GET_WEAPON_INFO, 8)) {
            rf_get_wi_fn fn = (rf_get_wi_fn)(uintptr_t)FUNC_GET_WEAPON_INFO;
            uint32_t p = (uint32_t)(uintptr_t)fn(type, skill);
            if (p && rf_readable(p, WEAPON_INFO_STRIDE) && rf_entry_valid(p)) {
                g_rf_src_fn = true;
                return p;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
    if (!g_rf_table) return 0;
    int idx = type;
    if (skill == 0) idx = type + 25;
    else if (skill == 2) idx = type + 36;
    else if (skill == 3) idx = type + 47;
    uint32_t p = g_rf_table + (uint32_t)idx * WEAPON_INFO_STRIDE;
    if (rf_readable(p, WEAPON_INFO_STRIDE) && rf_entry_valid(p)) return p;
    return 0;
}

static void rf_write_float(uint32_t b, uint32_t off, float v) {
    uint32_t a = b + off;
    if (*(float*)(uintptr_t)a == v) return;
    DWORD oldp = 0, tmp = 0;
    uint32_t page = a & ~0xFFFu;
    bool prot = VirtualProtect((void*)(uintptr_t)page, 0x1000, PAGE_READWRITE, &oldp) != 0;
    *(float*)(uintptr_t)a = v;
    if (prot) VirtualProtect((void*)(uintptr_t)page, 0x1000, oldp, &tmp);
}

static bool rf_copy_snapshot(uint32_t p, RFWeaponSave& dst) {
    for (int a = 0; a < RF_SKILL_COUNT; ++a) {
        for (int b = RF_FIRE_ANIM_MIN; b <= RF_FIRE_ANIM_MAX; ++b) {
            RFWeaponSave& s = g_rf_save[a][b];
            if (&s == &dst || !s.ok || s.ptr != p) continue;
            dst.ptr    = p;
            dst.start  = s.start;
            dst.end    = s.end;
            dst.start2 = s.start2;
            dst.end2   = s.end2;
            dst.fire   = s.fire;
            dst.fire2  = s.fire2;
            dst.ok     = true;
            return true;
        }
    }
    return false;
}

static void rapid_fire_restore() {
    if (!g_rf_patched) return;
    g_rf_patched = false;
    __try {
        int n = 0;
        for (int sk = 0; sk < RF_SKILL_COUNT; ++sk) {
            for (int t = RF_FIRE_ANIM_MIN; t <= RF_FIRE_ANIM_MAX; ++t) {
                RFWeaponSave& s = g_rf_save[sk][t];
                if (!s.ok || !s.ptr || !rf_readable(s.ptr, WEAPON_INFO_STRIDE)) continue;
                rf_write_float(s.ptr, WI_OFF_ANIM_LOOP_START,  s.start);
                rf_write_float(s.ptr, WI_OFF_ANIM_LOOP_END,    s.end);
                rf_write_float(s.ptr, WI_OFF_ANIM_LOOP2_START, s.start2);
                rf_write_float(s.ptr, WI_OFF_ANIM_LOOP2_END,   s.end2);
                s.ok = false;
                ++n;
            }
        }
        mta_logf("rf", "janela de animacao restaurada: %d entradas", n);
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

static void rapid_fire_update() {
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0)) {
        rapid_fire_restore();
        return;
    }
    if (!session_live()) return;
    if (!g_rapid_fire_enable) {
        rapid_fire_restore();
        return;
    }
    float rate = cfg_clampf(g_rapid_fire_rate, 1.0f, 100.0f);
    if (rate <= 1.0f) { rapid_fire_restore(); return; }
    uint32_t now = GetTickCount();
    bool rate_changed = fabsf(rate - g_rf_applied_rate) >= 0.5f;
    if (g_rf_patched && !rate_changed && now - g_rf_tick < 200) return;
    g_rf_tick = now;

    if (!g_rf_table_tried) {
        g_rf_table_tried = true;
        g_rf_table = rf_find_table();
    }
    __try {
        float mul = 1.0f / rate;
        if (mul > 1.0f) mul = 1.0f;
        int n = 0, changed = 0;
        for (int sk = 0; sk < RF_SKILL_COUNT; ++sk) {
            for (int t = RF_FIRE_ANIM_MIN; t <= RF_FIRE_ANIM_MAX; ++t) {
                RFWeaponSave& s = g_rf_save[sk][t];
                if (!s.ok || !s.ptr || !rf_readable(s.ptr, WEAPON_INFO_STRIDE)) {
                    uint32_t p = rf_resolve(t, sk);
                    if (!p) { s.ok = false; continue; }
                    s.ptr = p;
                    if (!rf_copy_snapshot(p, s)) {
                        s.start  = *(float*)(p + WI_OFF_ANIM_LOOP_START);
                        s.end    = *(float*)(p + WI_OFF_ANIM_LOOP_END);
                        s.start2 = *(float*)(p + WI_OFF_ANIM_LOOP2_START);
                        s.end2   = *(float*)(p + WI_OFF_ANIM_LOOP2_END);
                        s.fire   = *(float*)(p + WI_OFF_ANIM_LOOP_FIRE);
                        s.fire2  = *(float*)(p + WI_OFF_ANIM_LOOP2_FIRE);
                        s.ok     = true;
                    }
                }
                float ns  = s.fire  - (s.fire  - s.start)  * mul;
                float ne  = s.fire  + (s.end   - s.fire)   * mul;
                float ns2 = s.fire2 - (s.fire2 - s.start2) * mul;
                float ne2 = s.fire2 + (s.end2  - s.fire2)  * mul;
                if (!(ne  > s.fire))  ne  = s.fire  + 0.001f;
                if (!(ne2 > s.fire2)) ne2 = s.fire2 + 0.001f;
                if (*(float*)(s.ptr + WI_OFF_ANIM_LOOP_START) != ns)  ++changed;
                if (*(float*)(s.ptr + WI_OFF_ANIM_LOOP_END)   != ne)  ++changed;
                rf_write_float(s.ptr, WI_OFF_ANIM_LOOP_START,  ns);
                rf_write_float(s.ptr, WI_OFF_ANIM_LOOP_END,    ne);
                rf_write_float(s.ptr, WI_OFF_ANIM_LOOP2_START, ns2);
                rf_write_float(s.ptr, WI_OFF_ANIM_LOOP2_END,   ne2);
                if (sk == 1 && t == 31) g_rf_last_window = ne - ns;
                ++n;
            }
        }
        if (!n) {
            rapid_fire_restore();
            if (mta_log_tick(6, 2000)) mta_logf("rf", "nenhuma entrada de arma resolvida");
            return;
        }
        bool was_new = !g_rf_patched;
        g_rf_patched = true;
        g_rf_applied_rate = rate;
        if (was_new)
            mta_logf("rf", "janela de tiro rate=%.0f entradas=%d src=%s m4_janela=%.4f",
                     (double)rate, n, g_rf_src_fn ? "GetWeaponInfo 0x743C60" : "indice",
                     (double)g_rf_last_window);
        else if (changed) {
            g_rf_rewrites += (uint32_t)changed;
            if (mta_log_tick(6, 2000))
                mta_logf("rf", "stats reaplicados: %u campos divergentes", (unsigned)g_rf_rewrites);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { rapid_fire_restore(); }
}

static bool     g_focus_skip     = false;
static int      g_focus_no_draw  = 0;

static void focus_set_skip(bool v) {
    if (g_focus_skip == v) return;
    g_focus_skip = v;
    if (v) mta_logf("foco", "sem foco: frames da DLL suspensos");
    else { g_focus_no_draw = 0; mta_logf("foco", "em foco: retomado"); }
}

static bool render_frame_ok() {
    if (!g_game_hwnd || !IsWindow(g_game_hwnd)) { focus_set_skip(false); return true; }
    if (IsIconic(g_game_hwnd)) { focus_set_skip(true); return false; }
    HWND fg   = GetForegroundWindow();
    HWND root = GetAncestor(g_game_hwnd, GA_ROOT);
    if (!fg || !root || GetAncestor(fg, GA_ROOT) == root) { focus_set_skip(false); return true; }
    if (++g_focus_no_draw < 3) return true;
    focus_set_skip(true);
    return false;
}

static HRESULT __stdcall hk_EndScene(IDirect3DDevice9* pDevice) {
    quit_early_probe();
    if (InterlockedCompareExchange(&g_shutdown_all, 0, 0))
        return g_o_EndScene(pDevice);

    HRESULT coop = pDevice->TestCooperativeLevel();
    if (coop != D3D_OK) {
        g_have_3d = false;
        InterlockedExchange(&g_silent_send_ok, 0);
        return g_o_EndScene(pDevice);
    }

    session_monitor();

    if (!render_frame_ok()) {
        g_have_3d = false;
        InterlockedExchange(&g_silent_send_ok, 0);
        return g_o_EndScene(pDevice);
    }

    if (!g_imgui_init) {
        init_imgui(pDevice);
        if (!g_imgui_init) return g_o_EndScene(pDevice);
    }

    {
        HWND fg = GetForegroundWindow();
        HWND game_root = GetAncestor(g_game_hwnd, GA_ROOT);
        bool game_focused = (fg != nullptr) && (game_root != nullptr)
                            && (GetAncestor(fg, GA_ROOT) == game_root);
        uint32_t now = GetTickCount();
        bool pending = InterlockedExchange(&g_menu_toggle_pending, 0) != 0;
        bool key_down = game_focused && bind_is_down(g_menu_key_vk);
        bool edge = key_down && !g_menu_key_latch;
        if ((pending || edge) && now - g_menu_toggle_tick > 180) {
            g_menu_open = !g_menu_open;
            g_menu_toggle_tick = now ? now : 1;
            g_menu_key_latch = true;
        }
        if (!key_down) g_menu_key_latch = false;
    }

    menu_cursor_sync(g_menu_open);
    if (g_menu_prev != g_menu_open) {
        g_menu_prev = g_menu_open;
        mta_logf("menu", "%s fps=%.1f size=%.0fx%.0f",
                 g_menu_open ? "aberto" : "fechado",
                 (double)ImGui::GetIO().Framerate,
                 (double)ImGui::GetIO().DisplaySize.x,
                 (double)ImGui::GetIO().DisplaySize.y);
    }

    stream_proof_apply();
    ImGui::GetIO().MouseDrawCursor = g_menu_open;
    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    if (ImGui::GetIO().DisplaySize.x < 64.0f || ImGui::GetIO().DisplaySize.y < 64.0f)
        return g_o_EndScene(pDevice);
    if (ImGui::GetIO().DeltaTime > 0.1f) ImGui::GetIO().DeltaTime = 0.1f;
    ImGui::NewFrame();
    if (mta_log_tick(2, 5000)) {
        ImGuiIO& io = ImGui::GetIO();
        mta_logf("fps", "fps=%.1f dt=%.1fms patches=%d repatch=%d menu=%d shutdown=%d",
                 (double)io.Framerate, (double)(io.DeltaTime * 1000.0f),
                 (int)g_patch_count,
                 (int)InterlockedCompareExchange(&g_watchdog_repatch_count, 0, 0),
                 g_menu_open ? 1 : 0,
                 (int)InterlockedCompareExchange(&g_shutdown_all, 0, 0));
    }

    const bool handshake = conn_handshake_active();
    if (!handshake) {
        draw_esp_all_players(pDevice);
        fly_update(ImGui::GetIO().DeltaTime);
        rapid_fire_update();
        aimbot_run(pDevice);
        silent_update(pDevice);
    } else {
        g_silent_aim_on = g_silent_has_target = false;
        g_aimbot_aim_on = g_aimbot_has_target = false;
        InterlockedExchange(&g_silent_send_ok, 0);
    }
    aimbot_update_key();
    aimbot_poll_capture();
    misc_bind_poll_capture();
    draw_aimbot_fov();
    draw_silent_fov();
    if (g_menu_open && g_current_tab == TAB_TROLL) troll_player_list_refresh();
    if (g_menu_open) draw_menu();
    notify_draw();

    ImGui::EndFrame();
    ImGui::Render();
    ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());

    return g_o_EndScene(pDevice);
}

static void install_d3d9_hooks() {
    HWND hwnd = CreateWindowExA(0, "STATIC", "dummy",
        WS_POPUP, 0, 0, 1, 1, NULL, NULL, NULL, NULL);
    if (!hwnd) return;

    IDirect3D9* d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) { DestroyWindow(hwnd); return; }

    D3DPRESENT_PARAMETERS pp = {};
    pp.Windowed         = TRUE;
    pp.SwapEffect       = D3DSWAPEFFECT_DISCARD;
    pp.hDeviceWindow    = hwnd;
    pp.BackBufferFormat = D3DFMT_UNKNOWN;

    IDirect3DDevice9* dev = nullptr;
    HRESULT hr = d3d->CreateDevice(
        D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &dev);

    if (FAILED(hr)) {
        d3d->Release();
        DestroyWindow(hwnd);
        return;
    }

    void** vt = *(void***)dev;
    void* pEndScene     = vt[42];
    void* pReset        = vt[16];
    void* pPresent      = vt[17];
    void* pSetTransform = vt[44];

    dev->Release();
    d3d->Release();
    DestroyWindow(hwnd);

    patch_jmp(pEndScene,     &hk_EndScene,     g_o_EndScene);
    patch_jmp(pReset,        &hk_Reset,        g_o_Reset);
    patch_jmp(pPresent,      &hk_Present,      g_o_Present);
    patch_jmp(pSetTransform, &hk_SetTransform, g_o_SetTransform);
}

static HMODULE find_mod() { return GetModuleHandleA("netc.dll"); }

static unsigned g_ok = 0, g_miss = 0, g_fail = 0;

template<typename T>
static bool try_install_global(const char* name, const char* pat, const char* msk, unsigned occ,
                               T detour, T& original_out) {
    if (g_patch_count >= 60) { ++g_fail; return false; }
    void* addr = scan_mask(find_mod(), pat, msk, occ);
    if (!addr) { ++g_miss; return false; }

    if (!patch_jmp(addr, detour, original_out)) {
        ++g_fail;
        return false;
    }
    ++g_ok;
    return true;
}

template<typename T>
static bool try_install(const char* name, const char* pat, const char* msk, unsigned occ, T detour) {
    T dummy = nullptr;
    return try_install_global<T>(name, pat, msk, occ, detour, dummy);
}

template<typename T>
static bool try_install_rva(const char* name, uint32_t rva, T detour) {
    if (g_patch_count >= 60) { ++g_fail; return false; }
    if (!g_netc_base || !g_netc_size) { ++g_miss; return false; }
    uint32_t addr = g_netc_base + rva;
    if (addr < 0x10000u || addr + 5 > 0x7FFFFFFFu) { ++g_miss; return false; }
    if (addr + 5 > g_netc_base + g_netc_size) { ++g_miss; return false; }

    void* a = (void*)(uintptr_t)addr;
    __try {
        volatile uint8_t b = *(uint8_t*)a;
        (void)b;
    } __except (EXCEPTION_EXECUTE_HANDLER) { ++g_miss; return false; }

    if (*(uint8_t*)a == 0xE9) {
        int32_t rel = *(int32_t*)((uint8_t*)a + 1);
        uint32_t dest = addr + 5 + (uint32_t)rel;
        if (dest == (uint32_t)(uintptr_t)detour) {
            mta_logf("rva", "%s rva=%05X addr=%08X ja hookado", name, rva, addr);
            return true;
        }
    }

    T tramp = nullptr;
    if (!patch_jmp(a, detour, tramp)) {
        ++g_fail;
        mta_logf("rva!", "%s rva=%05X addr=%08X: falhou", name, rva, addr);
        return false;
    }
    ++g_ok;
    mta_logf("rva", "%s rva=%05X addr=%08X", name, rva, addr);
    return true;
}

static void __fastcall w_send_client_kick(int a, int b, unsigned int c,
                                          int d, DWORD* e, int f) {
    d_send_client_kick(a, b, c, d, e, f);
}

static void __fastcall w_send_client_local_kick(int a, char b) {
    d_send_client_local_kick(a, b);
}

static void __fastcall w_send_client_ban(int a, int b, int* c, int* d,
                                        char e, int f) {
    d_send_client_ban(a, b, c, d, e, f);
}

static void install_all() {
    if (g_install_done_generation == g_install_generation) return;
    HMODULE mod = nullptr;
    for (int i = 0; i < 60; ++i) {
        mod = find_mod();
        if (mod) break;
        Sleep(500);
    }
    if (!mod) return;
    g_install_done_generation = g_install_generation;
    ++g_install_count;
    mta_logf("safe", "install_all geracao=%u tentativa=%u patches=%d: trampolins por geracao",
             (unsigned)g_install_generation, (unsigned)g_install_count,
             (int)g_patch_count);
    g_netc_base = (uint32_t)(uintptr_t)mod;
    g_netc_size = netc_image_size(mod);
    memset(g_stale_patch_sink, 0xE9, sizeof(g_stale_patch_sink));

    try_install<bool(__cdecl*)(int,int,int,DWORD*,int*,DWORD*)>(
        "advanced_memory_validator",
        PAT_ADVANCED_MEMORY_VALIDATOR, MSK_ADVANCED_MEMORY_VALIDATOR, 1,
        &d_advanced_memory_validator);

    try_install<int(__fastcall*)(DWORD*,void*,int,unsigned __int8,unsigned __int16)>(
        "network_packet_state_validator",
        PAT_NETWORK_PACKET_STATE_VALIDATOR, MSK_NETWORK_PACKET_STATE_VALIDATOR, 1,
        &d_network_packet_state_validator);

    try_install<char(__stdcall*)(int*)>(
        "animation_packet_validator",
        PAT_ANIMATION_PACKET_VALIDATOR, MSK_ANIMATION_PACKET_VALIDATOR, 1,
        &d_animation_packet_validator);

    try_install_global<fn_send_packet>(
        "send_packet",
        PAT_SEND_PACKET, MSK_SEND_PACKET, 1,
        &d_send_packet, g_o_send_packet);

    try_install<int(__cdecl*)(char,void*,int,int,int)>(
        "send_report",
        PAT_SEND_REPORT, MSK_SEND_REPORT, 1,
        &d_send_report);

    try_install<HANDLE(__stdcall*)(LPCWSTR,ACCESS_MASK,DWORD,LPSECURITY_ATTRIBUTES,ULONG,ULONG)>(
        "send_driver_report",
        PAT_SEND_DRIVER_REPORT, MSK_SEND_DRIVER_REPORT, 1,
        &d_send_driver_report);

    try_install<void(__fastcall*)(int,int,unsigned int,int,DWORD*,int)>(
        "send_client_kick",
        PAT_SEND_CLIENT_KICK, MSK_SEND_CLIENT_KICK, 1,
        &w_send_client_kick);

    try_install<void(__fastcall*)(int,char)>(
        "send_client_local_kick",
        PAT_SEND_CLIENT_LOCAL_KICK, MSK_SEND_CLIENT_LOCAL_KICK, 1,
        &w_send_client_local_kick);

    try_install<void(__fastcall*)(int,int,int*,int*,char,int)>(
        "send_client_ban",
        PAT_SEND_CLIENT_BAN, MSK_SEND_CLIENT_BAN, 1,
        &w_send_client_ban);

    try_install_global<fn_send_lua_check>(
        "send_lua_check",
        PAT_SEND_LUA_CHECK, MSK_SEND_LUA_CHECK, 1,
        &d_send_lua_check, g_o_send_lua_check);

    try_install<void(__fastcall*)(void*,void*)>(
        "sub_10056A50",
        PAT_SUB_10056A50, MSK_SUB_10056A50, 1,
        &d_sub_10056A50);

    try_install<unsigned int(__fastcall*)(void*,void*,int)>(
        "sub_10293EC0",
        PAT_SUB_10293EC0, MSK_SUB_10293EC0, 1,
        &d_sub_10293EC0);

    try_install<int(__fastcall*)(void*,void*)>(
        "sub_10159D50",
        PAT_SUB_10159D50, MSK_SUB_10159D50, 1,
        &d_sub_10159D50);

    try_install<int(__cdecl*)(void*)>(
        "sub_10141000",
        PAT_SUB_10141000, MSK_SUB_10141000, 1,
        &d_sub_10141000);

    try_install<int(__fastcall*)(void*,void*,int,void*,int,const char*,const char*)>(
        "sub_101731D0",
        PAT_SUB_101731D0, MSK_SUB_101731D0, 1,
        &d_sub_101731D0);

    try_install<bool(__cdecl*)()>(
        "sub_1028CB90",
        PAT_SUB_1028CB90, MSK_SUB_1028CB90, 2,
        &d_sub_1028CB90);

    try_install<bool(__cdecl*)(char*)>(
        "detect_hook_new2",
        PAT_DETECT_HOOK_NEW2, MSK_DETECT_HOOK_NEW2, 1,
        &d_detect_hook_new2);

    try_install<bool(__cdecl*)(char*)>(
        "detect_hook_new",
        PAT_DETECT_HOOK_NEW, MSK_DETECT_HOOK_NEW, 1,
        &d_detect_hook_new);

    try_install<char(__cdecl*)(char*)>(
        "detect_hook",
        PAT_DETECT_HOOK, MSK_DETECT_HOOK, 1,
        &d_detect_hook);

    try_install<void(__cdecl*)(const char*)>(
        "sub_1006CC80",
        PAT_SUB_1006CC80, MSK_SUB_1006CC80, 1,
        &d_sub_1006CC80);

    try_install<char(__fastcall*)(void*,void*,int,int)>(
        "bypassnew",
        PAT_BYPASSNEW, MSK_BYPASSNEW, 1,
        &d_bypassnew);

    try_install<int(__fastcall*)(void*,void*,int,int)>(
        "bypass",
        PAT_BYPASS, MSK_BYPASS, 1,
        &d_bypass);

    try_install<int(__fastcall*)(unsigned int,void*,int)>(
        "sub_new",
        PAT_SUB_NEW, MSK_SUB_NEW, 2,
        &d_sub_new);

    try_install<int(__stdcall*)(int)>(
        "send_crash_hook",
        PAT_SEND_CRASH_HOOK, MSK_SEND_CRASH_HOOK, 1,
        &d_send_crash_hook);

    try_install_global<fn_sub_102BDFDE>(
        "sub_102BDFDE",
        PAT_SUB_102BDFDE, MSK_SUB_102BDFDE, 1,
        &d_sub_102BDFDE, g_o_sub_102BDFDE);

    try_install<unsigned int(__fastcall*)(int,int,unsigned int)>(
        "sub_100D57B0",
        PAT_SUB_100D57B0, MSK_SUB_100D57B0, 1,
        &d_sub_100D57B0);

    try_install_rva<LONG(__stdcall*)(void*)>(
        "ac_veh_stack", 0x11E9C0, &d_veh_stack);
    try_install_rva<DWORD(__stdcall*)(void*)>(
        "ac_start_watchdog", 0x2A8AD0, &d_ac_start_watchdog);
}

static volatile LONG g_init = 0;

static DWORD WINAPI thread(LPVOID) {
    g_boot_tick = GetTickCount();
    HANDLE sh = CreateThread(nullptr, 0, session_heartbeat_thread, nullptr, 0, nullptr);
    if (sh) CloseHandle(sh);
    install_all();
    silent_install_hook();
    mta_logf("hook", "install_all: ok=%u miss=%u fail=%u patches=%d",
             g_ok, g_miss, g_fail, (int)g_patch_count);
    install_d3d9_hooks();
    mta_logf("d3d9", "EndScene=%p Reset=%p Present=%p SetTransform=%p",
             (void*)(uintptr_t)g_o_EndScene, (void*)(uintptr_t)g_o_Reset,
             (void*)(uintptr_t)g_o_Present, (void*)(uintptr_t)g_o_SetTransform);

    InterlockedExchange(&g_watchdog_stop, 0);
    g_watchdog_handle = CreateThread(nullptr, 0, watchdog_thread, nullptr, 0, nullptr);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        mta_logf("boot", "DLL_PROCESS_ATTACH | rev=R43 | build %s %s | log=%s",
                 __DATE__, __TIME__, mta_log_path());
        if (InterlockedCompareExchange(&g_init, 1, 0) == 0) {
            HANDLE t = CreateThread(nullptr, 0, thread, nullptr, 0, nullptr);
            if (t) CloseHandle(t);
        }
    } else if (reason == DLL_PROCESS_DETACH) {
        if (lpReserved != nullptr) {
            quit_flush();
            quit_hard_restore();
            return TRUE;
        }
        quit_flush();
        emergency_disable_all();
        unpatch_all();
        if (g_imgui_init) {
            ImGui_ImplDX9_Shutdown();
            ImGui_ImplWin32_Shutdown();
            ImGui::DestroyContext();
            g_imgui_init = false;
        }
    }
    return TRUE;
}
