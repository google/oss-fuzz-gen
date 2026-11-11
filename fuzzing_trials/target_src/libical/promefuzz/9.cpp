// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_vjournal at icalcomponent.c:2104:16 in icalcomponent.h
// icalcomponent_new_xvote at icalcomponent.c:2169:16 in icalcomponent.h
// icalcomponent_new_xpatch at icalcomponent.c:2179:16 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_new_valarm at icalcomponent.c:2109:16 in icalcomponent.h
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
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz icalcomponent_new_xpatch
    icalcomponent *xpatch_comp = icalcomponent_new_xpatch();
    if (xpatch_comp) {
        icalcomponent_free(xpatch_comp);
    }

    // Fuzz icalcomponent_new_vjournal
    icalcomponent *vjournal_comp = icalcomponent_new_vjournal();

    // Fuzz icalcomponent_new_xvote
    icalcomponent *xvote_comp = icalcomponent_new_xvote();
    if (xvote_comp) {
        icalcomponent_free(xvote_comp);
    }

    // Fuzz icalcomponent_new_valarm
    icalcomponent *valarm_comp = icalcomponent_new_valarm();
    if (valarm_comp) {
        icalcomponent_free(valarm_comp);
    }

    // Fuzz icalcomponent_set_parent
    if (vjournal_comp) {
        icalcomponent *parent_comp = icalcomponent_new_vjournal();
        if (parent_comp) {
            icalcomponent_set_parent(vjournal_comp, parent_comp);
            icalcomponent_free(parent_comp);
        }
        icalcomponent_set_parent(vjournal_comp, nullptr);
        icalcomponent_free(vjournal_comp);
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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    