#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <d3d9.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx9.h"
#include "../esp-shared/ESPShared.h"
#pragma comment(lib, "d3d9.lib")
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static HANDLE g_map = nullptr;
static EspShared* g_shm = nullptr;
static EspShared g_snap;
static bool g_haveSnap = false;
static uint32_t g_shmMagic = 0, g_shmSeq = 0;

static HWND g_hwnd = nullptr;
static IDirect3D9* g_d3d = nullptr;
static IDirect3DDevice9* g_dev = nullptr;
static int g_screenW = 0, g_screenH = 0;
static bool g_needReset = false;
static bool g_running = true, g_menuOpen = true, g_minimized = false;
static bool g_espOn = true;
static bool g_localBoxEsp = true, g_localHpEsp = true, g_localSkelEsp = false;
static bool g_playersBoxEsp = true, g_playersHpEsp = true, g_playersSkelEsp = false;
static float g_localPlayerColor[4] = {0.0f, 0.0f, 0.0f, 1.0f};
static float g_playersColor[4] = {0.0f, 0.0f, 0.0f, 1.0f};
static bool g_prevInsert = false;

static RECT g_windowRects[16];
static int  g_windowRectCount = 0;

static D3DPRESENT_PARAMETERS MakePP(){
    D3DPRESENT_PARAMETERS pp = {};
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat = D3DFMT_A8R8G8B8;
    pp.BackBufferWidth  = (UINT)(g_screenW > 0 ? g_screenW : 1);
    pp.BackBufferHeight = (UINT)(g_screenH > 0 ? g_screenH : 1);
    pp.hDeviceWindow = g_hwnd;
    pp.EnableAutoDepthStencil = TRUE;
    pp.AutoDepthStencilFormat = D3DFMT_D16;
    pp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;
    return pp;
}

static HWND FindGameWindow(){
    HWND h = FindWindowA("Grand Theft Auto San Andreas", nullptr);
    if(!h) h = FindWindowA(nullptr, "Grand Theft Auto San Andreas");
    if(!h) h = FindWindowA(nullptr, "SA-MP");
    return h;
}

static void SyncToGame(){
    HWND game = FindGameWindow();
    if(!game) return;
    if(IsIconic(game)) return;
    RECT rc;
    if(!GetClientRect(game, &rc)) return;
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;
    if(w < 16 || h < 16) return;
    POINT org = {0,0};
    if(!ClientToScreen(game, &org)) return;

    RECT cur; GetWindowRect(g_hwnd, &cur);
    if(cur.left != org.x || cur.top != org.y ||
       (cur.right - cur.left) != w || (cur.bottom - cur.top) != h){
        SetWindowPos(g_hwnd, HWND_TOPMOST, org.x, org.y, w, h,
                     SWP_NOACTIVATE | SWP_NOOWNERZORDER);
    }
    if(w != g_screenW || h != g_screenH){
        g_screenW = w;
        g_screenH = h;
        g_needReset = true;
    }
}

static void DrawESP(){
    if(!g_shm) return;

    g_shmMagic = g_shm->magic;
    g_shmSeq   = g_shm->seq;

    if(!(g_shmSeq & 1u) && g_shmMagic == ESP_MAGIC){
        EspShared tmp;
        memcpy(&tmp, g_shm, sizeof(tmp));
        if(g_shm->seq == g_shmSeq && tmp.magic == ESP_MAGIC){
            memcpy(&g_snap, &tmp, sizeof(tmp));
            g_haveSnap = true;
        }
    }
    if(!g_haveSnap || !g_espOn) return;
    if(g_snap.viewFlags & ESP_VIEW_BAD) return;

    float gw = (float)g_snap.gameW;
    float gh = (float)g_snap.gameH;
    if(!(gw > 1.0f && gh > 1.0f)){ gw = (float)g_screenW; gh = (float)g_screenH; }
    if(!(gw > 1.0f && gh > 1.0f)) return;

    const float sxScale = (float)g_screenW / gw;
    const float syScale = (float)g_screenH / gh;
    const float fov = g_snap.fovDeg;
    const float* v = g_snap.view;
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    const float HEAD_Z = 1.20f;
    const float FEET_Z = -0.70f;

    uint32_t n = g_snap.count;
    if(n > ESP_MAX_ENT) n = ESP_MAX_ENT;

    for(uint32_t i = 0; i < n; ++i){
        const EspEntity& e = g_snap.ents[i];
        if(!e.valid || !(e.hp > 0) || !(e.maxhp > 0)) continue;

        const bool isLocal = (e.flags & ESP_ENT_LOCAL) != 0;
        const bool drawBox  = isLocal ? g_localBoxEsp  : g_playersBoxEsp;
        const bool drawHp   = isLocal ? g_localHpEsp   : g_playersHpEsp;
        const bool drawSkel = isLocal ? g_localSkelEsp : g_playersSkelEsp;
        if(!drawBox && !drawHp && !drawSkel) continue;

        const float* dc = isLocal ? g_localPlayerColor : g_playersColor;
        ImU32 col = ImGui::GetColorU32(ImVec4(dc[0], dc[1], dc[2], dc[3]));

        if(drawBox || drawHp){
            float hx, hy, fx, fy;
            if(EspW2S(v, fov, e.x, e.y, e.z + HEAD_Z, gw, gh, hx, hy)){
                bool okFeet = EspW2S(v, fov, e.x, e.y, e.z + FEET_Z, gw, gh, fx, fy);

                float top = hy;
                float bottom = okFeet ? fy : (hy + 40.0f);
                float bh = bottom - top;
                if(!(bh > 8.0f)) bh = 8.0f;
                if(bh > gh * 2.0f) bh = gh * 2.0f;
                float bw = bh * 0.45f;

                const float sTop    = top * syScale;
                const float sBottom = (top + bh) * syScale;
                const float sCx     = hx * sxScale;
                const float sBw     = bw * sxScale;

                if(drawBox){
                    dl->AddRect(ImVec2(sCx - sBw*0.5f, sTop), ImVec2(sCx + sBw*0.5f, sBottom),
                                col, 0.0f, 0, 2.0f);
                }
                if(drawHp){
                    float fr = e.hp / e.maxhp;
                    if(fr > 1) fr = 1; if(fr < 0) fr = 0;
                    ImVec2 a(sCx - sBw*0.5f - 6.0f, sTop);
                    ImVec2 b(sCx - sBw*0.5f - 3.0f, sBottom);
                    dl->AddRectFilled(a, b, IM_COL32(0,0,0,180));
                    ImVec2 b2(b.x, b.y - (b.y - a.y) * fr);
                    ImU32 hc = IM_COL32((int)(255*(1-fr)), (int)(255*fr), 0, 255);
                    dl->AddRectFilled(ImVec2(a.x, b2.y), b, hc);
                }
            }
        }

        if(drawSkel && e.boneCount > 1){
            for(uint8_t b = 0; b < e.boneCount; ++b){
                const EspBone& bone = e.bones[b];
                if(bone.parent >= e.boneCount) continue;
                const EspBone& par = e.bones[bone.parent];

                float x1, y1, x2, y2;
                if(EspW2S(v, fov, bone.x, bone.y, bone.z, gw, gh, x1, y1) &&
                   EspW2S(v, fov, par.x, par.y, par.z, gw, gh, x2, y2)){
                    dl->AddLine(ImVec2(x1*sxScale, y1*syScale),
                                ImVec2(x2*sxScale, y2*syScale), col, 1.5f);
                }
            }
        }
    }
}

static void UpdateInteractiveRects(){
    g_windowRectCount = 0;
    ImGuiContext& g = *ImGui::GetCurrentContext();
    for(int i = 0; i < g.Windows.Size && g_windowRectCount < 16; ++i){
        ImGuiWindow* w = g.Windows[i];
        if(!w->WasActive) continue;
        if(w->Hidden || w->Collapsed) continue;
        ImVec2 p = w->Pos;
        ImVec2 s = w->Size;
        if(s.x < 1.0f || s.y < 1.0f) continue;
        g_windowRects[g_windowRectCount].left   = (LONG)p.x;
        g_windowRects[g_windowRectCount].top    = (LONG)p.y;
        g_windowRects[g_windowRectCount].right  = (LONG)(p.x + s.x);
        g_windowRects[g_windowRectCount].bottom = (LONG)(p.y + s.y);
        ++g_windowRectCount;
    }
}

static void RenderFrame(){
    if(!g_dev) return;

    SyncToGame();

    HRESULT hr = g_dev->TestCooperativeLevel();
    if(hr == D3DERR_DEVICELOST){ Sleep(50); return; }

    bool needReset = (hr == D3DERR_DEVICENOTRESET) || g_needReset;
    if(needReset){
        D3DPRESENT_PARAMETERS pp = MakePP();
        ImGui_ImplDX9_InvalidateDeviceObjects();
        if(SUCCEEDED(g_dev->Reset(&pp))){
            ImGui_ImplDX9_CreateDeviceObjects();
            g_needReset = false;
        } else {
            g_needReset = true;
            Sleep(50);
            return;
        }
    }

    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    DrawESP();

    if(g_menuOpen){
        if(g_minimized){
            ImGui::SetNextWindowPos(ImVec2(10,10));
            ImGui::Begin("ESP##mini", &g_menuOpen, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::Text("ESP minimized (INSERT to expand)");
            ImGui::End();
        } else {
            ImGui::SetNextWindowPos(ImVec2(10,10), ImGuiCond_FirstUseEver);
            ImGui::Begin("External ESP", &g_menuOpen, ImGuiWindowFlags_AlwaysAutoResize);
            if(!g_shm){
                ImGui::TextColored(ImVec4(1,0.4f,0.4f,1), "Injete ESPShared.dll");
            } else if(g_shmMagic != ESP_MAGIC){
                ImGui::TextColored(ImVec4(1,0.4f,0.4f,1), "Magic incompativel (%08X)", g_shmMagic);
            }
            ImGui::Separator();
            ImGui::Checkbox("ESP Enabled", &g_espOn);
            ImGui::Separator();
            if(ImGui::BeginTabBar("##tabs")){
                if(ImGui::BeginTabItem("Local Player")){
                    ImGui::Spacing();
                    ImGui::Checkbox("ESP Box##local", &g_localBoxEsp);
                    ImGui::Checkbox("ESP Health##local", &g_localHpEsp);
                    ImGui::Checkbox("ESP Skeleton##local", &g_localSkelEsp);
                    ImGui::Spacing();
                    ImGui::ColorEdit4("Color##local", g_localPlayerColor, ImGuiColorEditFlags_NoInputs);
                    ImGui::EndTabItem();
                }
                if(ImGui::BeginTabItem("Players")){
                    ImGui::Spacing();
                    ImGui::Checkbox("ESP Box##players", &g_playersBoxEsp);
                    ImGui::Checkbox("ESP Health##players", &g_playersHpEsp);
                    ImGui::Checkbox("ESP Skeleton##players", &g_playersSkelEsp);
                    ImGui::Spacing();
                    ImGui::ColorEdit4("Color##players", g_playersColor, ImGuiColorEditFlags_NoInputs);
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            ImGui::End();
        }
    }

    ImGui::Render();
    UpdateInteractiveRects();

    g_dev->SetRenderState(D3DRS_ZENABLE, FALSE);
    if(SUCCEEDED(g_dev->Clear(0, nullptr, D3DCLEAR_TARGET, D3DCOLOR_XRGB(1,1,1), 1.0f, 0))){
        if(SUCCEEDED(g_dev->BeginScene())){
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_dev->EndScene();
        }
    }
    if(g_dev->Present(nullptr, nullptr, nullptr, nullptr) == D3DERR_DEVICELOST) Sleep(50);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM wp, LPARAM lp){
    if(ImGui_ImplWin32_WndProcHandler(h, m, wp, lp)) return true;
    if(m == WM_MOUSEACTIVATE) return MA_NOACTIVATE;
    if(m == WM_NCHITTEST){
        POINT p = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        ScreenToClient(h, &p);
        for(int i = 0; i < g_windowRectCount; ++i){
            RECT& r = g_windowRects[i];
            if(p.x >= r.left && p.x < r.right && p.y >= r.top && p.y < r.bottom)
                return HTCLIENT;
        }
        return HTTRANSPARENT;
    }
    if(m == WM_DESTROY){ PostQuitMessage(0); return 0; }
    return DefWindowProcA(h, m, wp, lp);
}

static bool InitD3D(HWND hw){
    g_d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if(!g_d3d) return false;
    D3DPRESENT_PARAMETERS pp = MakePP();
    return SUCCEEDED(g_d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hw,
                                         D3DCREATE_HARDWARE_VERTEXPROCESSING, &pp, &g_dev));
}

static void CreateOverlay(){
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleA(nullptr);
    wc.lpszClassName = "ExtESP";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExA(&wc);

    int dw = GetSystemMetrics(SM_CXSCREEN);
    int dh = GetSystemMetrics(SM_CYSCREEN);
    if(dw < 16) dw = 1280;
    if(dh < 16) dh = 800;
    g_screenW = dw;
    g_screenH = dh;

    g_hwnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        "ExtESP", "External ESP", WS_POPUP,
        0, 0, g_screenW, g_screenH,
        nullptr, nullptr, wc.hInstance, nullptr);
    if(!g_hwnd) return;
    SetLayeredWindowAttributes(g_hwnd, RGB(1,1,1), 0, LWA_COLORKEY);
    ShowWindow(g_hwnd, SW_SHOWNOACTIVATE);
    UpdateWindow(g_hwnd);
}

static DWORD WINAPI ShmPoll(LPVOID){
    while(g_running){
        if(!g_shm){
            g_map = OpenFileMappingA(FILE_MAP_READ, FALSE, ESP_SHM_NAME);
            if(g_map) g_shm = (EspShared*)MapViewOfFile(g_map, FILE_MAP_READ, 0, 0, sizeof(EspShared));
        }
        Sleep(300);
    }
    return 0;
}

static DWORD WINAPI HotkeyThread(LPVOID){
    while(g_running){
        if(GetAsyncKeyState(VK_F8) & 0x8000){ g_running = false; break; }
        bool ins = (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;
        if(ins && !g_prevInsert) g_minimized = !g_minimized;
        g_prevInsert = ins;
        Sleep(25);
    }
    return 0;
}

int main(){
    AllocConsole();
    SetConsoleTitleA("ExternalESP log");
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    printf("[ExternalESP] ESP4 skeleton | INSERT = menu | F8 = quit\n");

    g_snap.fovDeg = 70.0f;
    CreateOverlay();
    if(!g_hwnd) return 1;
    if(!InitD3D(g_hwnd)){ MessageBoxA(nullptr, "D3D9 init failed", "External ESP", MB_ICONERROR); return 1; }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr; io.LogFilename = nullptr;
    ImFont* font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arial.ttf", 16.0f);
    if(!font) font = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\arialbd.ttf", 16.0f);
    if(!font) io.Fonts->AddFontDefault();
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX9_Init(g_dev);

    HANDLE p = CreateThread(nullptr,0,ShmPoll,nullptr,0,nullptr);       if(p)  CloseHandle(p);
    HANDLE hk = CreateThread(nullptr,0,HotkeyThread,nullptr,0,nullptr); if(hk) CloseHandle(hk);

    MSG msg;
    while(g_running){
        while(PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)){
            TranslateMessage(&msg); DispatchMessageA(&msg);
            if(msg.message == WM_QUIT) g_running = false;
        }
        RenderFrame();
        Sleep(1);
    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    if(g_dev) g_dev->Release();
    if(g_d3d) g_d3d->Release();
    if(g_shm){ UnmapViewOfFile(g_shm); g_shm = nullptr; }
    if(g_map){ CloseHandle(g_map); g_map = nullptr; }
    return 0;
}
