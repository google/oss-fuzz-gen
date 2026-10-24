// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_xdaylight at icalcomponent.c:2129:16 in icalcomponent.h
// icalcomponent_strip_errors at icalcomponent.c:1188:6 in icalcomponent.h
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
// icalcomponent_set_sequence at icalcomponent.c:2019:6 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
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

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Create a new XDAYLIGHT component
    icalcomponent *xdaylight = icalcomponent_new_xdaylight();
    if (!xdaylight) {
        return 0;
    }

    // Create a new VCALENDAR component
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    if (!vcalendar1 || !vcalendar2) {
        icalcomponent_free(xdaylight);
        if (vcalendar1) icalcomponent_free(vcalendar1);
        if (vcalendar2) icalcomponent_free(vcalendar2);
        return 0;
    }

    // Add the XDAYLIGHT component to the first VCALENDAR component
    icalcomponent_add_component(vcalendar1, xdaylight);

    // Set sequence to the first VCALENDAR component
    int sequence = *reinterpret_cast<const int*>(Data);
    icalcomponent_set_sequence(vcalendar1, sequence);

    // Merge the second VCALENDAR into the first one
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Avoid using or freeing vcalendar2 after merge

    // Strip errors from the VCALENDAR component
    icalcomponent_strip_errors(vcalendar1);

    // Get the parent of the XDAYLIGHT component
    icalcomponent *parent = icalcomponent_get_parent(xdaylight);

    // Free the components
    icalcomponent_free(vcalendar1);

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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    