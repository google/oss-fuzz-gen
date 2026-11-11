// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
#include <iostream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least one byte of data

    // Prepare environment
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Create a new VTODO component
    icalcomponent *vtodo = icalcomponent_new_vtodo();

    // Set DTSTAMP for the VTODO component using the provided data
    struct icaltimetype dtstamp;
    dtstamp.year = 2023; // Example year
    dtstamp.zone = nullptr; // No specific timezone
    icalcomponent_set_dtstamp(vtodo, dtstamp);

    // Add the VTODO to the first VCALENDAR
    icalcomponent_add_component(vcalendar1, vtodo);

    // Merge the second VCALENDAR into the first
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr;

    // Set parent-child relationship
    icalcomponent_set_parent(vtodo, vcalendar1);

    // Remove the VTODO from its parent
    icalcomponent_remove_component(vcalendar1, vtodo);

    // Cleanup
    icalcomponent_free(vcalendar1);
    if (vcalendar2) {
        icalcomponent_free(vcalendar2);
    }
    icalcomponent_free(vtodo);

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

        LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    