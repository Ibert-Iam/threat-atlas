#ifndef THREAT_ATLAS_UPDATE_H
#define THREAT_ATLAS_UPDATE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct TaUpdateResult {
    int32_t outcome; /* 0 unavailable, 1 up-to-date, 2 available, 3 withdrawn, 4 failed */
    uint32_t build;
    uint64_t size;
    char version[64];
    char tag[128];
    char url[1024];
    char sha256[65];
    char message[256];
} TaUpdateResult;

/* Returns 0 on valid input, -1 on invalid pointers/strings/enums. The result may still be Failed. */
int32_t ta_update_check(const uint8_t *feed, size_t feed_len,
                        const uint8_t *signature, size_t signature_len,
                        const char *installed_version, const char *product, const char *platform,
                        int32_t channel /* 0 stable, 1 rc, 2 beta */,
                        int32_t kind /* 0 auto, 1 installer, 2 portable */,
                        int64_t now_unix, const char *state_in,
                        TaUpdateResult *out, char *state_out, size_t state_cap);

#ifdef __cplusplus
}
#endif
#endif
