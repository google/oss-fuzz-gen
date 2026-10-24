// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_foreach_tzid at icalcomponent.c:2456:6 in icalcomponent.h
// icalcomponent_strip_errors at icalcomponent.c:1188:6 in icalcomponent.h
// icalcomponent_as_ical_string_r at icalcomponent.c:245:7 in icalcomponent.h
// icalcomponent_get_dtstamp at icalcomponent.c:1786:21 in icalcomponent.h
// icalcomponent_get_dtstart at icalcomponent.c:1617:21 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"
}

#include <cstddef>
#include <cstdint>
#include <cstring>

static icalcomponent* create_vcalendar_component() {
    icalcomponent* comp = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    return comp;
}

static void dummy_tzid_callback(icalparameter *param, void *data) {
    // Dummy callback function for TZID iteration
}

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare two VCALENDAR components
    icalcomponent* vcalendar1 = create_vcalendar_component();
    icalcomponent* vcalendar2 = create_vcalendar_component();

    // Merge the second component into the first
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Prevent accidental reuse

    // Attempt to retrieve the DTSTART property
    icaltimetype dtstart = icalcomponent_get_dtstart(vcalendar1);

    // Create a string representation of the vcalendar
    char* ical_str = icalcomponent_as_ical_string_r(vcalendar1);
    if (ical_str) {
        // Normally, you would do something with the string
        icalmemory_free_buffer(ical_str);
    }

    // Iterate over TZID parameters
    icalcomponent_foreach_tzid(vcalendar1, dummy_tzid_callback, nullptr);

    // Strip errors from the component
    icalcomponent_strip_errors(vcalendar1);

    // Retrieve the DTSTAMP property
    icaltimetype dtstamp = icalcomponent_get_dtstamp(vcalendar1);

    // Clean up the vcalendar component
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    