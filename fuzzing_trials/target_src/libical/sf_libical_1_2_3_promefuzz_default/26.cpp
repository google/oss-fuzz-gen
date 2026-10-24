// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_property at icalcomponent.c:443:6 in icalcomponent.h
// icalcomponent_get_current_property at icalcomponent.c:506:15 in icalcomponent.h
// icalcomponent_add_property at icalcomponent.c:428:6 in icalcomponent.h
// icalcomponent_as_ical_string_r at icalcomponent.c:245:7 in icalcomponent.h
// icalcomponent_convert_errors at icalcomponent.c:1211:6 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy VCALENDAR component
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Create a dummy VEVENT component
    icalcomponent *vevent = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Create a dummy property
    icalproperty *property = icalproperty_new(ICAL_SUMMARY_PROPERTY);

    // Attempt to add a property to the vevent
    icalcomponent_add_property(vevent, property);

    // Merge two VCALENDAR components
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Prevent accidental reuse

    // Remove the property from vevent
    icalcomponent_remove_property(vevent, property);

    // Convert errors in vevent
    icalcomponent_convert_errors(vevent);

    // Get current property from vevent
    icalproperty *current_property = icalcomponent_get_current_property(vevent);

    // Generate iCalendar string from vevent
    char *ical_string = icalcomponent_as_ical_string_r(vevent);
    if (ical_string) {
        free(ical_string);
    }

    // Clean up
    icalcomponent_free(vcalendar1);
    icalcomponent_free(vevent);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    