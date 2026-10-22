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
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdint>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_vcalendar_component() {
    return icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
}

static icalcomponent* create_vtimezone_component() {
    return icalcomponent_new_vtimezone();
}

static icaltimetype create_icaltimetype(int year) {
    icaltimetype tt;
    tt.year = year;
    tt.zone = nullptr;
    return tt;
}

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data

    // Create two VCALENDAR components
    icalcomponent* vcalendar1 = create_vcalendar_component();
    icalcomponent* vcalendar2 = create_vcalendar_component();

    // Create a VTIMEZONE component
    icalcomponent* vtimezone = create_vtimezone_component();

    // Set DTSTAMP using the first 4 bytes of Data as a year
    int year = *reinterpret_cast<const int*>(Data);
    icaltimetype dtstamp = create_icaltimetype(year);
    icalcomponent_set_dtstamp(vcalendar1, dtstamp);

    // Merge vcalendar2 into vcalendar1
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // vcalendar2 is no longer valid

    // Set vtimezone as a child of vcalendar1
    icalcomponent_set_parent(vtimezone, vcalendar1);

    // Get the IANA name of vcalendar1
    const char* iana_name = icalcomponent_get_x_name(vcalendar1);
    if (iana_name) {
        std::cout << "IANA Name: " << iana_name << std::endl;
    }

    // Remove vtimezone from vcalendar1
    icalcomponent_remove_component(vcalendar1, vtimezone);

    // Clean up
    icalcomponent_free(vcalendar1);
    if (vtimezone) {
        icalcomponent_free(vtimezone);
    }

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

        LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    