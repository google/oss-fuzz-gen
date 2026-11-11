// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_xpatch at icalcomponent.c:2179:16 in icalcomponent.h
// icalcomponent_new_vresource at icalcomponent.c:2194:16 in icalcomponent.h
// icalcomponent_new_vvoter at icalcomponent.c:2164:16 in icalcomponent.h
// icalcomponent_new at icalcomponent.c:108:16 in icalcomponent.h
// icalcomponent_new_xstandard at icalcomponent.c:2124:16 in icalcomponent.h
// icalcomponent_new_vquery at icalcomponent.c:2139:16 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Test icalcomponent_new with different kinds
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);
    icalcomponent *comp = icalcomponent_new(kind);
    if (comp) {
        icalcomponent_free(comp);
    }

    // Test icalcomponent_new_vresource
    icalcomponent *vresourceComp = icalcomponent_new_vresource();
    if (vresourceComp) {
        icalcomponent_free(vresourceComp);
    }

    // Test icalcomponent_new_xpatch
    icalcomponent *xpatchComp = icalcomponent_new_xpatch();
    if (xpatchComp) {
        icalcomponent_free(xpatchComp);
    }

    // Test icalcomponent_new_vvoter
    icalcomponent *vvoterComp = icalcomponent_new_vvoter();
    if (vvoterComp) {
        icalcomponent_free(vvoterComp);
    }

    // Test icalcomponent_new_vquery
    icalcomponent *vqueryComp = icalcomponent_new_vquery();
    if (vqueryComp) {
        icalcomponent_free(vqueryComp);
    }

    // Test icalcomponent_new_xstandard
    icalcomponent *xstandardComp = icalcomponent_new_xstandard();
    if (xstandardComp) {
        icalcomponent_free(xstandardComp);
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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    