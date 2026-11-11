// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_set_method at icalcomponent.c:1561:6 in icalcomponent.h
// icalcomponent_get_status at icalcomponent.c:2066:26 in icalcomponent.h
// icalcomponent_get_dtstamp at icalcomponent.c:1786:21 in icalcomponent.h
// icalcomponent_set_recurrenceid at icalcomponent.c:1903:6 in icalcomponent.h
// icalcomponent_count_properties at icalcomponent.c:490:5 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <fstream>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_dummy_component(icalcomponent_kind kind) {
    return icalcomponent_new(kind);
}

static icaltimetype create_dummy_icaltimetype() {
    icaltimetype dummy_time;
    memset(&dummy_time, 0, sizeof(dummy_time));
    return dummy_time;
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create dummy components
    icalcomponent* comp1 = create_dummy_component(ICAL_VCALENDAR_COMPONENT);
    icalcomponent* comp2 = create_dummy_component(ICAL_VCALENDAR_COMPONENT);
    icaltimetype dummy_time = create_dummy_icaltimetype();

    // Fuzz icalcomponent_set_recurrenceid
    icalcomponent_set_recurrenceid(comp1, dummy_time);

    // Fuzz icalcomponent_merge_component
    icalcomponent_merge_component(comp1, comp2);
    comp2 = nullptr; // comp2 is now merged and should not be used

    // Fuzz icalcomponent_get_status
    icalproperty_status status = icalcomponent_get_status(comp1);

    // Fuzz icalcomponent_get_dtstamp
    icaltimetype dtstamp = icalcomponent_get_dtstamp(comp1);

    // Fuzz icalcomponent_count_properties
    int property_count = icalcomponent_count_properties(comp1, ICAL_ANY_PROPERTY);

    // Fuzz icalcomponent_set_method
    icalcomponent_set_method(comp1, ICAL_METHOD_NONE);

    // Clean up
    icalcomponent_free(comp1);

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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    