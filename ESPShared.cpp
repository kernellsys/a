#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <cmath>
#include <atomic>
#include "ESPShared.h"

static const uintptr_t OFF_PED_POOL     = 0x00B74490;
static const uintptr_t OFF_LOCAL_PLAYER = 0x00B6F5F0;
static const uint32_t  POOL_OBJECTS     = 0x00;
static const uint32_t  POOL_FLAGS       = 0x04;
static const uint32_t  POOL_SIZE        = 0x08;
static const uint32_t  PED_STRIDE       = 0x07C4;
static const uint32_t  PED_MATRIX_PTR   = 0x0014;
static const uint32_t  PED_POS_VEC      = 0x0034;
static const uint32_t  PED_HEALTH       = 0x0540;
static const uint32_t  PED_MAXHEALTH    = 0x0544;
static const uint32_t  PED_RW_OBJECT    = 0x0018;

static const uint32_t  PED_HEADING         = 0x0010;
static const uint32_t  PED_HEADING_CURRENT = 0x0558;
static const uint32_t  PED_PLAYER_DATA     = 0x0480;
static const uint32_t  PLAYER_LOOK_PITCH   = 0x0054;
static const uint32_t  MAT_FORWARD_X       = 0x0010;
static const uint32_t  MAT_FORWARD_Y       = 0x0014;
static const uint32_t  MAT_FORWARD_Z       = 0x0018;

static const uintptr_t CAM_BASE       = 0x00B6F028;
static const uint32_t  CAM_ACTIVE     = 0x0059;
static const uint32_t  CAM_CAMS       = 0x0174;
static const uint32_t  CAM_STRIDE     = 0x0238;
static const uint32_t  CAM_FOV        = 0x00B4;
static const uint32_t  CAM_FRONT      = 0x0190;
static const uint32_t  CAM_SOURCE     = 0x019C;
static const uint32_t  CAM_UP         = 0x01B4;
static const uint32_t  CAM_MATRIX     = 0x0974;
static const uint32_t  MAT_ATTACH_PTR = 0x0040;

static const uintptr_t RS_GLOBAL_W = 0x00C17044;
static const uintptr_t RS_GLOBAL_H = 0x00C17048;

static const uint32_t CLUMP_FIRST_ATOMIC = 0x18;
static const uint32_t ATOMIC_FRAME       = 0x24;
static const uint32_t FRAME_POS          = 0x40;
static const uint32_t FRAME_ROOT         = 0xA4;
static const uint32_t FRAME_CHILD        = 0xA8;
static const uint32_t FRAME_NEXT         = 0xAC;

#define ESP_PLAYER_LOOK_PITCH 1

static HANDLE g_map = nullptr;
static EspShared* g_shm = nullptr;
static HMODULE g_self = nullptr;
static std::atomic<bool> g_stop{false};
static HANDLE g_hConsole = INVALID_HANDLE_VALUE;

static EspEntity g_tmp[ESP_MAX_ENT];

static void OutDebug(const char* fmt, ...){
    char buf[320];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if(n <= 0) return;
    if(n > (int)sizeof(buf)-1) n = (int)sizeof(buf)-1;
    if(g_hConsole != INVALID_HANDLE_VALUE){
        DWORD w = 0;
        WriteConsoleA(g_hConsole, buf, (DWORD)n, &w, nullptr);
        WriteConsoleA(g_hConsole, "\n", 1, &w, nullptr);
    }
}

static bool SRP(uintptr_t a, void** o){ if(a<0x10000||a>0x7FFFFFFF)return false; __try{*o=*(void**)a;return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;} }
static bool SRF(uintptr_t a, float* o){ if(a<0x10000||a>0x7FFFFFFF)return false; __try{*o=*(float*)a;return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;} }
static bool SRB(uintptr_t a, uint8_t* o){ if(a<0x10000||a>0x7FFFFFFF)return false; __try{*o=*(uint8_t*)a;return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;} }
static bool SRU(uintptr_t a, uint32_t* o){ if(a<0x10000||a>0x7FFFFFFF)return false; __try{*o=*(uint32_t*)a;return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;} }
static bool Read16(uintptr_t a, float* o){
    if(a<0x10000||a>0x7FFFFFFF) return false;
    __try{ for(int i=0;i<16;i++) o[i] = ((const float*)a)[i]; return true; }
    __except(EXCEPTION_EXECUTE_HANDLER){ return false; }
}
static bool ReadV3(uintptr_t a, float* o){
    if(a<0x10000||a>0x7FFFFFFF) return false;
    __try{ o[0]=*(float*)a; o[1]=*(float*)(a+4); o[2]=*(float*)(a+8); return true; }
    __except(EXCEPTION_EXECUTE_HANDLER){ return false; }
}

static inline bool Sane(float v){ return v==v && fabsf(v) < 1.0e6f; }
static inline float Dot3(const float* a, const float* b){ return a[0]*b[0]+a[1]*b[1]+a[2]*b[2]; }
static inline float Len3(const float* a){ return sqrtf(Dot3(a,a)); }
static inline void Neg3(float* a){ a[0]=-a[0]; a[1]=-a[1]; a[2]=-a[2]; }
static inline void Cross3(const float* a, const float* b, float* o){
    o[0]=a[1]*b[2]-a[2]*b[1]; o[1]=a[2]*b[0]-a[0]*b[2]; o[2]=a[0]*b[1]-a[1]*b[0];
}
static inline bool Norm3(float* a){
    float l=Len3(a);
    if(!(l>1.0e-4f) || !Sane(l) || l>1.0e5f) return false;
    a[0]/=l; a[1]/=l; a[2]/=l; return true;
}
static inline void Copy3(float* d, const float* s){ d[0]=s[0]; d[1]=s[1]; d[2]=s[2]; }

struct CamFrame { float view[16]; float fovDeg; uint32_t flags; };

static bool BuildCamFrame(CamFrame* out){
    memset(out, 0, sizeof(*out));
    uint32_t flags = 0;

    uint8_t active = 0;
    SRB(CAM_BASE + CAM_ACTIVE, &active);
    if(active > 2) active = 0;
    uintptr_t cam = CAM_BASE + CAM_CAMS + (uintptr_t)active * CAM_STRIDE;

    float fov = 0.0f;
    if(SRF(cam + CAM_FOV, &fov) && Sane(fov) && fov > 20.0f && fov < 130.0f){
        out->fovDeg = fov; flags |= ESP_VIEW_FOV;
    } else {
        out->fovDeg = 70.0f;
    }

    float frontRef[3] = {0,1,0}, upRef[3] = {0,0,1}, source[3] = {0,0,0};
    bool haveCam = ReadV3(cam + CAM_FRONT, frontRef)
                && ReadV3(cam + CAM_SOURCE, source)
                && ReadV3(cam + CAM_UP, upRef);
    if(haveCam){
        float tmp[3]; Copy3(tmp, frontRef);
        if(!Norm3(tmp)) haveCam = false; else Copy3(frontRef, tmp);
        Copy3(tmp, upRef);
        if(haveCam && !Norm3(tmp)) { upRef[0]=0; upRef[1]=0; upRef[2]=1; }
        else if(haveCam) Copy3(upRef, tmp);
    }

    uintptr_t src = CAM_BASE + CAM_MATRIX;
    float raw[16]; memset(raw, 0, sizeof(raw));
    bool readOk = Read16(src, raw);
    if(!readOk){
        void* att = nullptr;
        if(SRP(src + MAT_ATTACH_PTR, &att) && att){
            uintptr_t p = (uintptr_t)att;
            if(p > 0x10000 && p < 0x7FFFFFFF && Read16(p, raw)){
                readOk = true;
                flags |= ESP_VIEW_ATTACH;
            }
        }
    }

    float R0[3] = {raw[0],  raw[1],  raw[2]};
    float A[3]  = {raw[4],  raw[5],  raw[6]};
    float B[3]  = {raw[8],  raw[9],  raw[10]};
    float P[3]  = {raw[12], raw[13], raw[14]};

    bool matrixOk = readOk
        && Sane(R0[0]) && Sane(R0[1]) && Sane(R0[2])
        && Sane(A[0]) && Sane(A[1]) && Sane(A[2])
        && Sane(B[0]) && Sane(B[1]) && Sane(B[2])
        && Sane(P[0]) && Sane(P[1]) && Sane(P[2])
        && Len3(R0) > 0.5f && Len3(R0) < 2.0f
        && Len3(A) > 0.5f && Len3(A) < 2.0f
        && Len3(B) > 0.5f && Len3(B) < 2.0f
        && Len3(P) < 20000.0f && Len3(P) > 0.001f;

    float F[3], U[3], Rt[3], pos[3];

    if(matrixOk){
        float da = haveCam ? fabsf(Dot3(A, frontRef)) : 1.0f;
        float db = haveCam ? fabsf(Dot3(B, frontRef)) : 0.0f;
        const float* pf = (db > da) ? B : A;
        const float* pu = (db > da) ? A : B;
        if(db > da) flags |= ESP_VIEW_SWAPPED;
        Copy3(F, pf); Copy3(U, pu);

        if(haveCam && Dot3(F, frontRef) < 0.0f) Neg3(F);
        if(haveCam && fabsf(Dot3(U, upRef)) > 0.5f && Dot3(U, upRef) < 0.0f) Neg3(U);
        if(!Norm3(F)) matrixOk = false;

        if(matrixOk){
            float d = Dot3(R0, F);
            Rt[0]=R0[0]-F[0]*d; Rt[1]=R0[1]-F[1]*d; Rt[2]=R0[2]-F[2]*d;
            if(!Norm3(Rt)) matrixOk = false;
        }
        if(matrixOk){
            float c1[3], c2[3];
            Cross3(F, Rt, c1); Cross3(Rt, F, c2);
            bool pickC1 = (Dot3(c1, U) >= Dot3(c2, U));
            Copy3(U, pickC1 ? c1 : c2);
            if(!Norm3(U)) matrixOk = false;
        }
        if(matrixOk){
            float d = Dot3(U, F);
            U[0]-=F[0]*d; U[1]-=F[1]*d; U[2]-=F[2]*d;
            if(!Norm3(U)) matrixOk = false;
        }
        Copy3(pos, P);
        if(matrixOk) flags |= ESP_VIEW_MATRIX;
    }

    if(!matrixOk){
        if(!haveCam){ flags |= ESP_VIEW_BAD; out->flags = flags; return false; }
        Copy3(F, frontRef); Copy3(pos, source);
        if(!Norm3(F)){ flags |= ESP_VIEW_BAD; out->flags = flags; return false; }

        float r0[3] = {raw[0], raw[1], raw[2]};
        bool haveR = readOk && Norm3(r0);
        if(haveR){
            float d = Dot3(r0, F);
            Rt[0]=r0[0]-F[0]*d; Rt[1]=r0[1]-F[1]*d; Rt[2]=r0[2]-F[2]*d;
            if(!Norm3(Rt)){
                Cross3(F, upRef, Rt);
                if(!Norm3(Rt)){ flags |= ESP_VIEW_BAD; out->flags = flags; return false; }
            }
        } else {
            Cross3(F, upRef, Rt);
            if(!Norm3(Rt)){ flags |= ESP_VIEW_BAD; out->flags = flags; return false; }
        }

        float c1[3], c2[3];
        Cross3(F, Rt, c1); Cross3(Rt, F, c2);
        bool pickC1 = (Dot3(c1, upRef) >= Dot3(c2, upRef));
        Copy3(U, pickC1 ? c1 : c2);
        if(!Norm3(U)){
            Copy3(U, upRef);
            float d = Dot3(U, F);
            U[0]-=F[0]*d; U[1]-=F[1]*d; U[2]-=F[2]*d;
            if(!Norm3(U)){ flags |= ESP_VIEW_BAD; out->flags = flags; return false; }
        }
        flags |= ESP_VIEW_FALLBACK;
    }

    Rt[0] = -Rt[0]; Rt[1] = -Rt[1]; Rt[2] = -Rt[2];

    out->view[0]=Rt[0];    out->view[1]=Rt[1];    out->view[2]=Rt[2];    out->view[3]=0.0f;
    out->view[4]=F[0];     out->view[5]=F[1];     out->view[6]=F[2];     out->view[7]=0.0f;
    out->view[8]=U[0];     out->view[9]=U[1];     out->view[10]=U[2];    out->view[11]=0.0f;
    out->view[12]=pos[0];  out->view[13]=pos[1];  out->view[14]=pos[2];  out->view[15]=1.0f;
    out->flags = flags;
    return true;
}

static bool ReadPedAngles(uintptr_t ped, float* outYaw, float* outPitch){
    float yaw = 0.0f, pitch = 0.0f;
    bool got = false;

    void* pm = nullptr;
    if(SRP(ped + PED_MATRIX_PTR, &pm) && pm){
        uintptr_t m = (uintptr_t)pm;
        float fx=0, fy=0, fz=0;
        if(SRF(m+MAT_FORWARD_X,&fx) && SRF(m+MAT_FORWARD_Y,&fy) && SRF(m+MAT_FORWARD_Z,&fz)
           && Sane(fx) && Sane(fy) && Sane(fz)){
            float f[3] = {fx,fy,fz};
            if(Norm3(f)){
                float horiz = sqrtf(f[0]*f[0] + f[1]*f[1]);
                yaw   = atan2f(f[0], f[1]);
                pitch = atan2f(f[2], horiz);
                got = true;
            }
        }
    }
    if(!got){
        float h = 0.0f;
        if(SRF(ped + PED_HEADING, &h) && Sane(h) && fabsf(h) < 7.0f){ yaw=h; pitch=0; got=true; }
    }
    if(!got){
        float h = 0.0f;
        if(SRF(ped + PED_HEADING_CURRENT, &h) && Sane(h) && fabsf(h) < 7.0f){ yaw=h; pitch=0; got=true; }
    }
#if ESP_PLAYER_LOOK_PITCH
    if(got){
        void* pd = nullptr;
        if(SRP(ped + PED_PLAYER_DATA, &pd) && pd){
            float lp = 0.0f;
            if(SRF((uintptr_t)pd + PLAYER_LOOK_PITCH, &lp) && Sane(lp) && fabsf(lp) < 3.0f) pitch = lp;
        }
    }
#endif
    if(!got) return false;
    *outYaw = yaw; *outPitch = pitch;
    return true;
}

static void ReadGameSize(uint32_t* w, uint32_t* h){
    uint32_t gw = 0, gh = 0;
    SRU(RS_GLOBAL_W, &gw);
    SRU(RS_GLOBAL_H, &gh);
    if(gw < 64 || gw > 8192) gw = 0;
    if(gh < 64 || gh > 8192) gh = 0;
    *w = gw; *h = gh;
}

static void ReadBonesDFS(uintptr_t frame, int parentIdx, EspEntity* e, int& count, int depth, float ex, float ey, float ez){
    if(!frame || count >= ESP_MAX_BONES || depth > 12) return;

    float pos[3];
    if(!ReadV3(frame + FRAME_POS, pos)) return;
    if(!Sane(pos[0]) || !Sane(pos[1]) || !Sane(pos[2])) return;

    float dx = pos[0]-ex, dy = pos[1]-ey, dz = pos[2]-ez;
    if(dx*dx + dy*dy + dz*dz > 36.0f) return;

    int myIdx = count;
    e->bones[count].x = pos[0];
    e->bones[count].y = pos[1];
    e->bones[count].z = pos[2];
    e->bones[count].parent = (parentIdx < 0) ? 0xFF : (uint8_t)parentIdx;
    count++;

    uintptr_t child = 0;
    if(!SRP(frame + FRAME_CHILD, (void**)&child) || !child) return;

    int safety = 0;
    while(child && count < ESP_MAX_BONES && safety < 32){
        ReadBonesDFS(child, myIdx, e, count, depth+1, ex, ey, ez);
        uintptr_t next = 0;
        if(!SRP(child + FRAME_NEXT, (void**)&next) || !next) break;
        child = next;
        safety++;
    }
}

static void ReadPedBones(uintptr_t ped, EspEntity* e, float ex, float ey, float ez){
    e->boneCount = 0;

    uintptr_t clump = 0;
    if(!SRP(ped + PED_RW_OBJECT, (void**)&clump) || !clump) return;

    uint8_t type = 0;
    if(!SRB(clump, &type) || type != 1) return;

    uintptr_t atomic = 0;
    if(!SRP(clump + CLUMP_FIRST_ATOMIC, (void**)&atomic) || !atomic) return;

    uintptr_t frame = 0;
    if(!SRP(atomic + ATOMIC_FRAME, (void**)&frame) || !frame) return;

    uintptr_t root = frame;
    for(int i = 0; i < 32; ++i){
        uintptr_t up = 0;
        if(!SRP(root + FRAME_ROOT, (void**)&up) || !up) break;
        root = up;
    }

    int count = 0;
    ReadBonesDFS(root, -1, e, count, 0, ex, ey, ez);
    e->boneCount = (uint8_t)count;
}

static DWORD WINAPI ReaderThread(LPVOID){
    OutDebug("[Reader] started");
    uint32_t frame = 0;
    DWORD lastLog = 0;

    while(!g_stop){
        if(!g_shm){ Sleep(100); continue; }

        CamFrame cf;
        bool camOk = BuildCamFrame(&cf);

        uint32_t gw = 0, gh = 0;
        ReadGameSize(&gw, &gh);

        void* lp = nullptr;
        if(!SRP(OFF_LOCAL_PLAYER, &lp) || !lp){ Sleep(50); continue; }
        uintptr_t localPed = (uintptr_t)lp;

        void* poolRaw = nullptr;
        if(!SRP(OFF_PED_POOL, &poolRaw) || !poolRaw){ Sleep(50); continue; }
        uintptr_t pool = (uintptr_t)poolRaw;

        void* objsRaw = nullptr, *flagsRaw = nullptr;
        uint32_t size = 0;
        if(!SRP(pool+POOL_OBJECTS,&objsRaw) || !objsRaw
        || !SRP(pool+POOL_FLAGS,&flagsRaw) || !flagsRaw
        || !SRU(pool+POOL_SIZE,&size) || size==0 || size>512){ Sleep(50); continue; }
        uintptr_t objs = (uintptr_t)objsRaw, flg = (uintptr_t)flagsRaw;
        if(size > ESP_MAX_ENT) size = ESP_MAX_ENT;

        memset(g_tmp, 0, sizeof(g_tmp));
        uint32_t n = 0, poolAlloc = 0;

        float camX = cf.view[12], camY = cf.view[13], camZ = cf.view[14];

        for(uint32_t i = 0; i < size; ++i){
            uint8_t ff = 0;
            if(!SRB(flg+i, &ff)) break;
            if(ff & 0x80) continue;
            ++poolAlloc;
            uintptr_t ped = objs + (uintptr_t)i * PED_STRIDE;

            float wx=0, wy=0, wz=0;
            void* pm = nullptr;
            bool gotPos = false;
            if(SRP(ped+PED_MATRIX_PTR,&pm) && pm){
                uintptr_t m = (uintptr_t)pm;
                gotPos = SRF(m+0x30,&wx) && SRF(m+0x34,&wy) && SRF(m+0x38,&wz);
            }
            if(!gotPos)
                gotPos = SRF(ped+PED_POS_VEC+0,&wx) && SRF(ped+PED_POS_VEC+4,&wy) && SRF(ped+PED_POS_VEC+8,&wz);
            if(!gotPos) continue;

            float hp=0, mx=0;
            if(!SRF(ped+PED_HEALTH,&hp) || !SRF(ped+PED_MAXHEALTH,&mx)) continue;
            if(!(hp>0) || !(mx>0)) continue;

            float yaw=0, pitch=0;
            bool gotAng = ReadPedAngles(ped, &yaw, &pitch);

            EspEntity& e = g_tmp[n];
            e.x=wx; e.y=wy; e.z=wz;
            e.hp=hp; e.maxhp=mx;
            e.yaw = gotAng ? yaw : 0.0f;
            e.pitch = gotAng ? pitch : 0.0f;
            e.valid = 1;
            e.flags = (ped == localPed) ? ESP_ENT_LOCAL : 0;
            e.boneCount = 0;

            float ddx = wx-camX, ddy = wy-camY, ddz = wz-camZ;
            if(ddx*ddx + ddy*ddy + ddz*ddz < 300.0f * 300.0f){
                ReadPedBones(ped, &e, wx, wy, wz);
            }

            ++n;
        }

        uint32_t seq = (frame * 2u) + 1u;
        g_shm->seq = seq;
        memcpy((void*)g_shm->view, cf.view, sizeof(cf.view));
        g_shm->fovDeg    = cf.fovDeg;
        g_shm->viewFlags = camOk ? cf.flags : (uint32_t)ESP_VIEW_BAD;
        g_shm->count        = n;
        g_shm->poolSize     = size;
        g_shm->poolAlloc    = poolAlloc;
        g_shm->localSkipped = 0;
        g_shm->gameW        = gw;
        g_shm->gameH        = gh;
        memcpy((void*)g_shm->ents, g_tmp, n * sizeof(EspEntity));
        g_shm->magic = ESP_MAGIC;
        g_shm->seq = seq + 1u;
        ++frame;

        DWORD now = GetTickCount();
        if(now - lastLog >= 2000){
            lastLog = now;
            uint32_t bonesTotal = 0;
            for(uint32_t i = 0; i < n; ++i) bonesTotal += g_tmp[i].boneCount;
            OutDebug("[Reader] frame=%u cam=%s fov=%.1f flags=0x%02X game=%ux%u ents=%u bones=%u",
                frame, camOk?"ok":"BAD", cf.fovDeg, cf.flags, gw, gh, n, bonesTotal);
        }
        Sleep(16);
    }
    OutDebug("[Reader] stopped");
    return 0;
}

static DWORD WINAPI WatchThread(LPVOID){
    bool prev = false;
    while(!g_stop){
        bool c=(GetAsyncKeyState(VK_CONTROL)&0x8000)!=0,
             s=(GetAsyncKeyState(VK_SHIFT)&0x8000)!=0,
             z=(GetAsyncKeyState(0x30)&0x8000)!=0;
        bool combo = c && s && z;
        if(combo && !prev){
            g_stop.store(true, std::memory_order_relaxed);
            Sleep(200);
            if(g_shm){ UnmapViewOfFile(g_shm); g_shm=nullptr; }
            if(g_map){ CloseHandle(g_map); g_map=nullptr; }
            HMODULE self=g_self; Sleep(50);
            FreeLibraryAndExitThread(self,0);
            return 0;
        }
        prev = combo; Sleep(30);
    }
    return 0;
}

static DWORD WINAPI InitThread(LPVOID){
    AllocConsole();
    SetConsoleTitleA("ESPShared Debug");
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    OutDebug("[ESPShared] ESP4 skeleton");

    g_map = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                               0, sizeof(EspShared), ESP_SHM_NAME);
    if(!g_map){ OutDebug("CreateFileMapping failed"); return 0; }
    g_shm = (EspShared*)MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(EspShared));
    if(!g_shm){ OutDebug("MapViewOfFile failed"); return 0; }

    memset((void*)g_shm, 0, sizeof(EspShared));
    g_shm->magic = ESP_MAGIC;
    g_shm->fovDeg = 70.0f;

    HANDLE t = CreateThread(nullptr,0,ReaderThread,nullptr,0,nullptr);
    if(t) CloseHandle(t);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID){
    if(reason == DLL_PROCESS_ATTACH){
        g_self = h; DisableThreadLibraryCalls(h);
        HANDLE t = CreateThread(nullptr,0,InitThread,nullptr,0,nullptr); if(t) CloseHandle(t);
        HANDLE w = CreateThread(nullptr,0,WatchThread,nullptr,0,nullptr); if(w) CloseHandle(w);
    } else if(reason == DLL_PROCESS_DETACH){
        g_stop = true;
        if(g_shm){ UnmapViewOfFile(g_shm); g_shm=nullptr; }
        if(g_map){ CloseHandle(g_map); g_map=nullptr; }
    }
    return TRUE;
}
