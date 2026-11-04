#pragma once
#include <cstdint>
#include <cmath>

#define ESP_SHM_NAME   "ESPSharedMem"
#define ESP_MAGIC      0x45535034u
#define ESP_MAX_ENT    256
#define ESP_MAX_BONES  24

#define ESP_ENT_LOCAL  0x00000001u

#define ESP_VIEW_MATRIX   0x1u
#define ESP_VIEW_ATTACH   0x2u
#define ESP_VIEW_SWAPPED  0x4u
#define ESP_VIEW_FALLBACK 0x8u
#define ESP_VIEW_FOV      0x10u
#define ESP_VIEW_BAD      0x80u

enum { ESP_V_RIGHT = 0, ESP_V_FORWARD = 4, ESP_V_UP = 8, ESP_V_POS = 12 };

#pragma pack(push, 1)
struct EspBone {
    float x, y, z;
    uint8_t parent;
};
struct EspEntity {
    float    x, y, z;
    float    hp, maxhp;
    float    yaw, pitch;
    uint32_t valid;
    uint32_t flags;
    uint8_t  boneCount;
    EspBone  bones[ESP_MAX_BONES];
};
struct EspShared {
    volatile uint32_t magic;
    volatile uint32_t seq;
    float    view[16];
    float    fovDeg;
    uint32_t viewFlags;
    uint32_t count;
    uint32_t poolSize;
    uint32_t poolAlloc;
    uint32_t localSkipped;
    uint32_t gameW;
    uint32_t gameH;
    EspEntity ents[ESP_MAX_ENT];
};
#pragma pack(pop)

static_assert(sizeof(EspBone) == 13, "");
static_assert(sizeof(EspEntity) == 36 + 1 + sizeof(EspBone) * ESP_MAX_BONES, "");
static_assert(sizeof(EspShared) == 104 + sizeof(EspEntity) * ESP_MAX_ENT, "");

static inline bool EspW2S(const float v[16], float fovDeg,
                          float wx, float wy, float wz, float sw, float sh,
                          float& ox, float& oy, float* outDepth = nullptr) {
    if (!(sw > 1.0f && sh > 1.0f)) return false;
    if (!(fovDeg > 20.0f && fovDeg < 130.0f)) fovDeg = 70.0f;
    const float* R = v + ESP_V_RIGHT;
    const float* F = v + ESP_V_FORWARD;
    const float* U = v + ESP_V_UP;
    const float* P = v + ESP_V_POS;
    for (int i = 0; i < 3; ++i)
        if (!(v[i] == v[i]) || !(v[4+i] == v[4+i]) || !(v[8+i] == v[8+i]) || !(v[12+i] == v[12+i]))
            return false;
    const float dx = wx - P[0], dy = wy - P[1], dz = wz - P[2];
    const float cx = dx*R[0] + dy*R[1] + dz*R[2];
    const float cy = dx*U[0] + dy*U[1] + dz*U[2];
    const float cz = dx*F[0] + dy*F[1] + dz*F[2];
    if (!(cz > 0.05f) || !(cz < 1.0e6f)) return false;
    const float tanHalf = tanf(fovDeg * 3.14159265358979323846f / 360.0f);
    const float focal = (sw * 0.5f) / tanHalf;
    ox = sw * 0.5f + (cx / cz) * focal;
    oy = sh * 0.5f - (cy / cz) * focal;
    if (outDepth) *outDepth = cz;
    return (ox == ox) && (oy == oy);
}
