// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_get_iana_name at icalcomponent.c:378:13 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
#include <iostream>
#include <cstdint>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create two VCALENDAR components
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Merge components
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Ensure the merged component pointer is set to nullptr

    // Create a VTIMEZONE component
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();

    // Set parent-child relationship
    icalcomponent_set_parent(vtimezone, vcalendar1);

    // Get IANA name of the VTIMEZONE component
    const char *iana_name = icalcomponent_get_x_name(vtimezone);
    if (iana_name) {
        std::cout << "IANA Name: " << iana_name << std::endl;
    }

    // Remove VTIMEZONE component from VCALENDAR
    icalcomponent_remove_component(vcalendar1, vtimezone);

    // Set a DTSTAMP for the VCALENDAR component
    struct icaltimetype dtstamp = icaltime_current_time_with_zone(nullptr);
    icalcomponent_set_dtstamp(vcalendar1, dtstamp);

    // Clean up
    icalcomponent_free(vcalendar1);
    icalcomponent_free(vtimezone);

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

        LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    