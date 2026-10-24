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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

// Helper function to create a dummy VCALENDAR component
static icalcomponent* create_dummy_vcalendar() {
    icalcomponent* vcalendar = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent* vevent = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    icalcomponent_add_component(vcalendar, vevent);
    return vcalendar;
}

// Callback function for icalcomponent_foreach_tzid
static void tzid_callback(icalparameter *param, void *data) {
    // Dummy callback function to satisfy the API requirement
    (void)param;
    (void)data;
}

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    // Prepare two dummy VCALENDAR components
    icalcomponent* vcalendar1 = create_dummy_vcalendar();
    icalcomponent* vcalendar2 = create_dummy_vcalendar();

    // 1. Fuzz icalcomponent_merge_component
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Avoid accidental reuse

    // 2. Fuzz icalcomponent_get_dtstart
    icaltimetype dtstart = icalcomponent_get_dtstart(vcalendar1);

    // 3. Fuzz icalcomponent_as_ical_string_r
    char *ical_str = icalcomponent_as_ical_string_r(vcalendar1);
    if (ical_str) {
        free(ical_str);
    }

    // 4. Fuzz icalcomponent_foreach_tzid
    icalcomponent_foreach_tzid(vcalendar1, tzid_callback, nullptr);

    // 5. Fuzz icalcomponent_strip_errors
    icalcomponent_strip_errors(vcalendar1);

    // 6. Fuzz icalcomponent_get_dtstamp
    icaltimetype dtstamp = icalcomponent_get_dtstamp(vcalendar1);

    // Cleanup
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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    