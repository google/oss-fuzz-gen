// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_xdaylight at icalcomponent.c:2129:16 in icalcomponent.h
// icalcomponent_new_xpatch at icalcomponent.c:2179:16 in icalcomponent.h
// icalcomponent_new_vjournal at icalcomponent.c:2104:16 in icalcomponent.h
// icalcomponent_new_xvote at icalcomponent.c:2169:16 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_new_xstandard at icalcomponent.c:2124:16 in icalcomponent.h
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
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    // Create components using the target API functions
    icalcomponent *xpatch = icalcomponent_new_xpatch();
    icalcomponent *vjournal = icalcomponent_new_vjournal();
    icalcomponent *xstandard = icalcomponent_new_xstandard();
    icalcomponent *xvote = icalcomponent_new_xvote();
    icalcomponent *xdaylight = icalcomponent_new_xdaylight();

    // Explore different states by setting parent relationships
    if (Size > 0) {
        switch (Data[0] % 5) {
            case 0:
                icalcomponent_set_parent(xpatch, vjournal);
                break;
            case 1:
                icalcomponent_set_parent(vjournal, xstandard);
                break;
            case 2:
                icalcomponent_set_parent(xstandard, xvote);
                break;
            case 3:
                icalcomponent_set_parent(xvote, xdaylight);
                break;
            case 4:
                icalcomponent_set_parent(xdaylight, xpatch);
                break;
        }
    }

    // Cleanup: free all components
    if (xpatch) icalcomponent_free(xpatch);
    if (vjournal) icalcomponent_free(vjournal);
    if (xstandard) icalcomponent_free(xstandard);
    if (xvote) icalcomponent_free(xvote);
    if (xdaylight) icalcomponent_free(xdaylight);

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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    