// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_xdaylight at icalcomponent.c:2129:16 in icalcomponent.h
// icalcomponent_strip_errors at icalcomponent.c:1188:6 in icalcomponent.h
// icalcomponent_set_sequence at icalcomponent.c:2019:6 in icalcomponent.h
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
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
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a new VQUERY component
    icalcomponent *vquery = icalcomponent_new_vquery();
    if (!vquery) {
        return 0;
    }

    // Create a new XDAYLIGHT component
    icalcomponent *xdaylight = icalcomponent_new_xdaylight();
    if (!xdaylight) {
        icalcomponent_free(vquery);
        return 0;
    }

    // Set a sequence number using the first byte of the data
    int sequence = Data[0];
    icalcomponent_set_sequence(vquery, sequence);

    // Merge components if there is enough data to decide
    if (Size > 1) {
        icalcomponent *vcalendar1 = icalcomponent_vanew(
            ICAL_VCALENDAR_COMPONENT, 0);
        icalcomponent *vcalendar2 = icalcomponent_vanew(
            ICAL_VCALENDAR_COMPONENT, 0);
        
        if (vcalendar1 && vcalendar2) {
            icalcomponent_merge_component(vcalendar1, vcalendar2);
            vcalendar2 = nullptr; // Avoid accidental use after merge
            // Do not free vcalendar1 here since it may be used later
        }

        // Do not free vcalendar1 here since it may be used later
        if (vcalendar2) icalcomponent_free(vcalendar2);
    }

    // Get parent of the XDAYLIGHT component
    icalcomponent *parent = icalcomponent_get_parent(xdaylight);

    // Strip errors from the VQUERY component
    icalcomponent_strip_errors(vquery);

    // Clean up
    icalcomponent_free(vquery);
    icalcomponent_free(xdaylight);

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

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    