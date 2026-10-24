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
#include <cstdint>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_vcalendar_component() {
    icalcomponent* comp = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    return comp;
}

static icaltimetype create_sample_icaltimetype(int year) {
    icaltimetype tt;
    tt.year = year;
    tt.zone = nullptr; // Assuming no timezone for simplicity
    return tt;
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create two VCALENDAR components
    icalcomponent* vcalendar1 = create_vcalendar_component();
    icalcomponent* vcalendar2 = create_vcalendar_component();

    if (!vcalendar1 || !vcalendar2) {
        if (vcalendar1) icalcomponent_free(vcalendar1);
        if (vcalendar2) icalcomponent_free(vcalendar2);
        return 0;
    }

    // Merge components
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // As per API requirement, vcalendar2 should not be used anymore

    // Create a VTIMEZONE component
    icalcomponent* vtimezone = icalcomponent_new_vtimezone();

    // Set a parent-child relationship
    icalcomponent_set_parent(vtimezone, vcalendar1);

    // Get the IANA name
    const char* iana_name = icalcomponent_get_x_name(vcalendar1);
    if (iana_name) {
        std::cout << "IANA Name: " << iana_name << std::endl;
    }

    // Create a dummy file if needed
    std::ofstream dummy_file("./dummy_file");
    if (dummy_file.is_open()) {
        dummy_file.write(reinterpret_cast<const char*>(Data), Size);
        dummy_file.close();
    }

    // Set DTSTAMP
    icaltimetype dtstamp = create_sample_icaltimetype(2023);
    icalcomponent_set_dtstamp(vcalendar1, dtstamp);

    // Remove the VTIMEZONE component from the parent
    icalcomponent_remove_component(vcalendar1, vtimezone);

    // Cleanup
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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    