// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
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

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create two VCALENDAR components for merging
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Create a VTODO component
    icalcomponent *vtodo = icalcomponent_new_vtodo();

    // Set vtodo as a child of vcalendar2
    icalcomponent_add_component(vcalendar2, vtodo);

    // Use some of the data to create a icaltimetype
    struct icaltimetype dtstamp;
    if (Size >= sizeof(dtstamp.year)) {
        memcpy(&dtstamp.year, Data, sizeof(dtstamp.year));
        dtstamp.zone = nullptr; // Simplified for this test
    } else {
        dtstamp.year = 2023; // Default year if not enough data
        dtstamp.zone = nullptr;
    }

    // Set the DTSTAMP of vtodo
    icalcomponent_set_dtstamp(vtodo, dtstamp);

    // Merge vcalendar2 into vcalendar1
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // vcalendar2 is no longer valid after merging

    // Create another VCALENDAR component and add vtodo to it
    icalcomponent *vcalendar3 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent_add_component(vcalendar3, vtodo);

    // Remove vtodo from vcalendar3
    icalcomponent_remove_component(vcalendar3, vtodo);

    // Set vcalendar1 as the parent of vtodo
    icalcomponent_set_parent(vtodo, vcalendar1);

    // Clean up
    icalcomponent_free(vcalendar1);
    icalcomponent_free(vcalendar3);
    // vtodo is freed by icalcomponent_free(vcalendar1)

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

        LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    