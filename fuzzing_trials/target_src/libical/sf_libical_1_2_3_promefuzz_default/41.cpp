// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
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
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icaltime.h>

static void init_vcalendar(icalcomponent **comp1, icalcomponent **comp2) {
    *comp1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    *comp2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
}

static void cleanup_vcalendar(icalcomponent *comp1, icalcomponent *comp2) {
    if (comp1) {
        icalcomponent_free(comp1);
    }
    if (comp2) {
        icalcomponent_free(comp2);
    }
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    // Initialize two VCALENDAR components
    icalcomponent *vcalendar1 = nullptr;
    icalcomponent *vcalendar2 = nullptr;
    init_vcalendar(&vcalendar1, &vcalendar2);

    // Create a new VTODO component
    icalcomponent *vtodo = icalcomponent_new_vtodo();

    // Set a parent-child relationship
    icalcomponent_set_parent(vtodo, vcalendar1);

    // Add the VTODO component to the first VCALENDAR
    icalcomponent_add_component(vcalendar1, vtodo);

    // Set DTSTAMP for the VTODO component
    struct icaltimetype dtstamp = icaltime_null_time();
    dtstamp.year = 2023;
    icalcomponent_set_dtstamp(vtodo, dtstamp);

    // Merge the second VCALENDAR into the first
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Ensure it's not used again

    // Remove the VTODO component from the first VCALENDAR
    icalcomponent_remove_component(vcalendar1, vtodo);

    // Cleanup
    cleanup_vcalendar(vcalendar1, vcalendar2);

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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    