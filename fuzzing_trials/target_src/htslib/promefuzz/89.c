// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// ed_swap_8 at hts.h:1591:24 in hts.h
// ed_swap_4 at hts.h:1581:24 in hts.h
// ed_swap_2 at hts.h:1572:24 in hts.h
// ed_swap_8p at hts.h:1597:21 in hts.h
// ed_swap_4p at hts.h:1586:21 in hts.h
// ed_swap_2p at hts.h:1576:21 in hts.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "hts.h"

int LLVMFuzzerTestOneInput_89(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0; // Ensure there's enough data for 64-bit operations

    // Test ed_swap_8
    uint64_t val64;
    memcpy(&val64, Data, sizeof(uint64_t));
    uint64_t swapped64 = ed_swap_8(val64);

    // Test ed_swap_4
    if (Size >= 4) {
        uint32_t val32;
        memcpy(&val32, Data, sizeof(uint32_t));
        uint32_t swapped32 = ed_swap_4(val32);
    }

    // Test ed_swap_2
    if (Size >= 2) {
        uint16_t val16;
        memcpy(&val16, Data, sizeof(uint16_t));
        uint16_t swapped16 = ed_swap_2(val16);
    }

    // Test ed_swap_8p
    if (Size >= 8) {
        uint64_t val64p;
        memcpy(&val64p, Data, sizeof(uint64_t));
        ed_swap_8p(&val64p);
    }

    // Test ed_swap_4p
    if (Size >= 4) {
        uint32_t val32p;
        memcpy(&val32p, Data, sizeof(uint32_t));
        ed_swap_4p(&val32p);
    }

    // Test ed_swap_2p
    if (Size >= 2) {
        uint16_t val16p;
        memcpy(&val16p, Data, sizeof(uint16_t));
        ed_swap_2p(&val16p);
    }

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
