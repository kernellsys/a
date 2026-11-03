#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d9.h>
#include <cstdio>
#include <cstdint>
#include <cmath>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx9.h"
#pragma comment(lib,"d3d9.lib")
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND,UINT,WPARAM,LPARAM);

#define ESP_MAX_ENT 256
#pragma pack(push,1)
struct EspEntity { float x,y,z; float hp,maxhp; float yaw,pitch; uint32_t valid; };
struct EspShared {
    volatile uint32_t magic;
    volatile uint32_t seq;
    float view[16];
    uint32_t count;
    uint32_t poolSize;
    uint32_t poolAlloc;
    uint32_t localSkipped;
    EspEntity ents[ESP_MAX_ENT];
};
#pragma pack(pop)

static HANDLE g_map=nullptr;
static EspShared* g_shm=nullptr;
static HWND g_hwnd=nullptr;
static IDirect3D9* g_d3d=nullptr;
static IDirect3DDevice9* g_dev=nullptr;
static bool g_running=true, g_menuOpen=true, g_minimized=false;
static bool g_espOn=true, g_boxEsp=true, g_hpEsp=true, g_localPlayerEsp=true, g_playersEsp=true;
static float g_boxColor[4]={0.2f,1.0f,0.2f,1.0f};
static float g_localPlayerColor[4]={1.0f,0.5f,0.0f,1.0f};
static int g_lastW2S=0, g_validEnts=0, g_totalEnts=0; 
static float g_dbgSX=0,g_dbgSY=0,g_dbgWX=0,g_dbgWY=0,g_dbgWZ=0,g_dbgHp=0,g_dbgMaxHp=0;
static bool g_prevInsert=false;

static bool W2S(const float v[16], float wx,float wy,float wz, float sw,float sh, float& ox,float& oy){
    float rx=v[0],ry=v[1],rz=v[2], ux=v[4],uy=v[5],uz=v[6], ax=v[8],ay=v[9],az=v[10], px=v[12],py=v[13],pz=v[14];
    float dx=wx-px,dy=wy-py,dz=wz-pz;
    float cx=dx*rx+dy*ry+dz*rz;
    float cy=dx*ux+dy*uy+dz*uz;
    float cz=dx*ax+dy*ay+dz*az;
    if(cz<0.01f) return false;
    float f=(sh*0.5f)/tanf(70.0f*3.14159265f/360.0f);
    ox=sw*0.5f+(cx/cz)*f;
    oy=sh*0.5f-(cy/cz)*f;
    return true;
}

static void DrawESP(){
    g_lastW2S=0; g_validEnts=0; g_totalEnts=0;
    if(!g_espOn||!g_shm||g_shm->magic!=0x45535031) return;
    ImGuiIO& io=ImGui::GetIO();
    ImDrawList* dl=ImGui::GetBackgroundDrawList();
    float sw=io.DisplaySize.x, sh=io.DisplaySize.y;
    float v[16]; memcpy(v,(const void*)g_shm->view,sizeof(v));
    uint32_t n=g_shm->count; 
    
    static int dbgPrintCycle=0;
    if(++dbgPrintCycle >= 30) {
        dbgPrintCycle=0;
        printf("[DrawESP] count=%u n=%u shm_ents[0].valid=%u\n", g_shm->count, n, g_shm->ents[0].valid);
    }
    
    if(n>ESP_MAX_ENT) n=ESP_MAX_ENT;
    g_totalEnts=n;
    for(uint32_t i=0;i<n;i++){
        EspEntity e=g_shm->ents[i];
        if(!e.valid||e.hp<=0||e.maxhp<=0) continue;
        g_validEnts++;
        float sx,sy; if(!W2S(v,e.x,e.y,e.z+1.0f,sw,sh,sx,sy)) continue;
        g_lastW2S++; g_dbgSX=sx; g_dbgSY=sy; g_dbgWX=e.x; g_dbgWY=e.y; g_dbgWZ=e.z; g_dbgHp=e.hp; g_dbgMaxHp=e.maxhp;
        float hx,hy; bool okFeet=W2S(v,e.x,e.y,e.z-0.9f,sw,sh,hx,hy);
        float bh=okFeet?(sy-hy):40.0f; if(bh<8)bh=8; float bw=bh*0.45f;
        bool isLocalPlayer = (g_shm->localSkipped>0 && i==0);
        
        // Skip local player if local player ESP is disabled
        if(isLocalPlayer && !g_localPlayerEsp) continue;
        
        float* drawColor = isLocalPlayer ? g_localPlayerColor : g_boxColor;
        if(g_boxEsp && g_playersEsp){
            ImU32 col=ImGui::GetColorU32(ImVec4(drawColor[0],drawColor[1],drawColor[2],drawColor[3]));
            dl->AddRect(ImVec2(sx-bw*0.5f,sy-bh),ImVec2(sx+bw*0.5f,sy),col,0,0,2.0f);
        }
        if(g_hpEsp&&e.maxhp>0){
            float fr=e.hp/e.maxhp; if(fr>1)fr=1; if(fr<0)fr=0;
            ImVec2 a(sx-bw*0.5f-4,sy-bh),b(sx-bw*0.5f-1,sy);
            dl->AddRectFilled(a,b,IM_COL32(0,0,0,180));
            ImVec2 b2(b.x,b.y-(b.y-a.y)*fr);
            ImU32 hc=IM_COL32((int)(255*(1-fr)),(int)(255*fr),0,255);
            dl->AddRectFilled(ImVec2(a.x,b2.y),b,hc);
        }
    }
}

static void SetClickThrough(bool through){
    LONG_PTR ex=GetWindowLongPtrA(g_hwnd,GWL_EXSTYLE);
    if(through) ex|=WS_EX_TRANSPARENT; else ex&=~WS_EX_TRANSPARENT;
    SetWindowLongPtrA(g_hwnd,GWL_EXSTYLE,ex);
}

static void RenderFrame(){
    if(!g_dev) return;
    
    HRESULT hr = g_dev->TestCooperativeLevel();
    if(hr == D3DERR_DEVICELOST){ Sleep(50); return; }
    if(hr == D3DERR_DEVICENOTRESET){ 
        D3DPRESENT_PARAMETERS pp={};
        pp.Windowed=TRUE; pp.SwapEffect=D3DSWAPEFFECT_DISCARD; pp.BackBufferFormat=D3DFMT_A8R8G8B8;
        pp.EnableAutoDepthStencil=TRUE; pp.AutoDepthStencilFormat=D3DFMT_D16;
        pp.PresentationInterval=D3DPRESENT_INTERVAL_IMMEDIATE;
        g_dev->Reset(&pp);
        ImGui_ImplDX9_InvalidateDeviceObjects();
        ImGui_ImplDX9_CreateDeviceObjects();
    }
    
    ImGui_ImplDX9_NewFrame(); ImGui_ImplWin32_NewFrame(); ImGui::NewFrame();
    DrawESP();

    POINT pt; GetCursorPos(&pt);
    bool overMenu = g_menuOpen && !g_minimized && pt.x>=0 && pt.y>=0 && pt.x<=380 && pt.y<=420;
    SetClickThrough(!overMenu);

    if(g_menuOpen){
        if(g_minimized){
            ImGui::SetNextWindowPos(ImVec2(10,10));
            ImGui::Begin("ESP##mini",&g_menuOpen,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::Text("ESP minimized (INSERT to expand)");
            ImGui::End();
        } else {
            ImGui::SetNextWindowPos(ImVec2(10,10),ImGuiCond_FirstUseEver);
            ImGui::Begin("External ESP",&g_menuOpen,ImGuiWindowFlags_AlwaysAutoResize);
            if(g_shm){ 
                ImGui::Text("Status: magic=%08X seq=%u", g_shm->magic,g_shm->seq);
                ImGui::Text("Entities: total=%u allocated=%u local=%u", g_shm->poolSize, g_shm->poolAlloc, g_shm->localSkipped);
                ImGui::Text("ESP Data: count=%u valid=%u", g_totalEnts, g_validEnts);
                ImGui::Text("W2S Pass: %d entities projected", g_lastW2S);
                ImGui::Separator();
                if(g_lastW2S > 0) {
                    ImGui::Text("Last entity: (%.1f, %.1f, %.1f)", g_dbgWX, g_dbgWY, g_dbgWZ);
                    ImGui::Text("Screen: (%.1f, %.1f)", g_dbgSX, g_dbgSY);
                    ImGui::Text("HP: %.0f / %.0f", g_dbgHp, g_dbgMaxHp);
                    if(g_shm && g_shm->count > 0) {
                        EspEntity e = g_shm->ents[0];
                        ImGui::Text("Yaw: %.2f°, Pitch: %.2f°", e.yaw, e.pitch);
                    }
                }
            }
            else ImGui::Text("Status: shared memory not found - inject ESPShared.dll");
            ImGui::Separator();
            ImGui::Checkbox("ESP Enabled",&g_espOn); 
            ImGui::Checkbox("Draw Boxes",&g_boxEsp); 
            ImGui::Checkbox("Draw Health Bars",&g_hpEsp);
            ImGui::Checkbox("Local Player ESP",&g_localPlayerEsp);
            ImGui::Checkbox("Other Players ESP",&g_playersEsp);
            ImGui::ColorEdit4("Players Color",g_boxColor);
            ImGui::ColorEdit4("Local Player Color",g_localPlayerColor);
            ImGui::Text("INSERT = minimize/expand | F8 = quit");
            ImGui::End();
        }
    }

    ImGui::EndFrame(); ImGui::Render();
    g_dev->SetRenderState(D3DRS_ZENABLE,FALSE);
    if(g_dev->Clear(0,nullptr,D3DCLEAR_TARGET,D3DCOLOR_XRGB(1,1,1),1.0f,0)==D3D_OK){
        if(g_dev->BeginScene()==D3D_OK){ 
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData()); 
            g_dev->EndScene(); 
        }
    }
    HRESULT res = g_dev->Present(nullptr,nullptr,nullptr,nullptr);
    if(res == D3DERR_DEVICELOST) Sleep(50);
}

static LRESULT CALLBACK WndProc(HWND h,UINT m,WPARAM wp,LPARAM lp){
    if(ImGui_ImplWin32_WndProcHandler(h,m,wp,lp)) return true;
    if(m==WM_DESTROY){ PostQuitMessage(0); return 0; }
    return DefWindowProcA(h,m,wp,lp);
}

static bool InitD3D(HWND hw){
    g_d3d=Direct3DCreate9(D3D_SDK_VERSION); if(!g_d3d) return false;
    D3DPRESENT_PARAMETERS pp={};
    pp.Windowed=TRUE; pp.SwapEffect=D3DSWAPEFFECT_DISCARD; pp.BackBufferFormat=D3DFMT_A8R8G8B8;
    pp.EnableAutoDepthStencil=TRUE; pp.AutoDepthStencilFormat=D3DFMT_D16;
    pp.PresentationInterval=D3DPRESENT_INTERVAL_IMMEDIATE;
    return SUCCEEDED(g_d3d->CreateDevice(D3DADAPTER_DEFAULT,D3DDEVTYPE_HAL,hw,D3DCREATE_HARDWARE_VERTEXPROCESSING,&pp,&g_dev));
}

static void CreateOverlay(){
    WNDCLASSEXA wc={}; wc.cbSize=sizeof(wc); wc.lpfnWndProc=WndProc; wc.hInstance=GetModuleHandleA(nullptr); wc.lpszClassName="ExtESP2"; wc.hCursor=LoadCursor(nullptr,IDC_ARROW);
    RegisterClassExA(&wc);
    int sw=GetSystemMetrics(SM_CXSCREEN), sh=GetSystemMetrics(SM_CYSCREEN);
    g_hwnd=CreateWindowExA(WS_EX_TOPMOST|WS_EX_LAYERED|WS_EX_TOOLWINDOW,"ExtESP2","External ESP",WS_POPUP,0,0,sw,sh,nullptr,nullptr,wc.hInstance,nullptr);
    if(!g_hwnd) return;
    SetLayeredWindowAttributes(g_hwnd,RGB(1,1,1),0,LWA_COLORKEY);
    ShowWindow(g_hwnd,SW_SHOW); UpdateWindow(g_hwnd);
}

static DWORD WINAPI ShmPoll(LPVOID){
    int printCycle=0;
    while(g_running){
        if(!g_shm){
            g_map=OpenFileMappingA(FILE_MAP_ALL_ACCESS,FALSE,"ESPSharedMem");
            if(g_map) g_shm=(EspShared*)MapViewOfFile(g_map,FILE_MAP_ALL_ACCESS,0,0,sizeof(EspShared));
        } else {
            if(++printCycle >= 20) {
                printCycle=0;
                printf("[ShmPoll] seq=%u count=%u poolSize=%u poolAlloc=%u localSkipped=%u\n", 
                    g_shm->seq, g_shm->count, g_shm->poolSize, g_shm->poolAlloc, g_shm->localSkipped);
            }
        }
        Sleep(500);
    }
    return 0;
}

static DWORD WINAPI HotkeyThread(LPVOID){
    while(g_running){
        bool f8=(GetAsyncKeyState(VK_F8)&0x8000)!=0;
        if(f8) { g_running=false; break; }
        bool ins=(GetAsyncKeyState(VK_INSERT)&0x8000)!=0;
        if(ins && !g_prevInsert){ g_minimized=!g_minimized; }
        g_prevInsert=ins;
        Sleep(25);
    }
    return 0;
}

int main(){
    AllocConsole();
    SetConsoleTitleA("ExternalESP log");
    freopen_s((FILE**)stdout,"CONOUT$","w",stdout);
    printf("[ExternalESP] INSERT = minimize/expand menu | F8 = quit\n");
    CreateOverlay();
    if(!g_hwnd) return 1;
    if(!InitD3D(g_hwnd)){ MessageBoxA(nullptr,"D3D9 init failed","External ESP",MB_ICONERROR); return 1; }
    IMGUI_CHECKVERSION(); ImGui::CreateContext();
    ImGuiIO& io=ImGui::GetIO(); io.IniFilename=nullptr; io.LogFilename=nullptr; ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(g_hwnd); ImGui_ImplDX9_Init(g_dev);
    HANDLE p=CreateThread(nullptr,0,ShmPoll,nullptr,0,nullptr); if(p)CloseHandle(p);
    HANDLE hk=CreateThread(nullptr,0,HotkeyThread,nullptr,0,nullptr); if(hk)CloseHandle(hk);
    MSG msg;
    while(g_running){
        while(PeekMessageA(&msg,nullptr,0,0,PM_REMOVE)){ TranslateMessage(&msg); DispatchMessageA(&msg); if(msg.message==WM_QUIT) g_running=false; }
        RenderFrame(); Sleep(1);
    }
    ImGui_ImplDX9_Shutdown(); ImGui_ImplWin32_Shutdown(); ImGui::DestroyContext();
    if(g_dev)g_dev->Release(); if(g_d3d)g_d3d->Release();
    if(g_shm){ UnmapViewOfFile(g_shm); g_shm=nullptr; } if(g_map){ CloseHandle(g_map); g_map=nullptr; }
    return 0;
}
