// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_get_iana_name at icalcomponent.c:378:13 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icalcomponent.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icaltimezone.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

static icalcomponent* create_vcalendar_component() {
    icalcomponent* vcalendar = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    return vcalendar;
}

static icalcomponent* create_random_component() {
    icalcomponent_kind kinds[] = {
        ICAL_VEVENT_COMPONENT,
        ICAL_VTODO_COMPONENT,
        ICAL_VJOURNAL_COMPONENT,
        ICAL_VFREEBUSY_COMPONENT,
        ICAL_VALARM_COMPONENT
    };
    int kind_index = rand() % (sizeof(kinds) / sizeof(kinds[0]));
    icalcomponent* component = icalcomponent_new(kinds[kind_index]);
    return component;
}

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icaltimetype)) {
        return 0;
    }

    // Create VCALENDAR components for merging
    icalcomponent* vcalendar1 = create_vcalendar_component();
    icalcomponent* vcalendar2 = create_vcalendar_component();

    // Merge components
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Prevent accidental reuse

    // Create a random component and set it as a child
    icalcomponent* random_component = create_random_component();
    icalcomponent_set_parent(random_component, vcalendar1);

    // Get IANA name
    const char* iana_name = icalcomponent_get_x_name(random_component);

    // Create a VTIMEZONE component
    icalcomponent* vtimezone = icalcomponent_new_vtimezone();

    // Set DTSTAMP using part of the input data
    struct icaltimetype dtstamp;
    memcpy(&dtstamp, Data, sizeof(icaltimetype));
    icalcomponent_set_dtstamp(vcalendar1, dtstamp);

    // Remove the random component from vcalendar1
    icalcomponent_remove_component(vcalendar1, random_component);

    // Cleanup
    icalcomponent_free(vcalendar1);
    icalcomponent_free(random_component);
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

        LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    