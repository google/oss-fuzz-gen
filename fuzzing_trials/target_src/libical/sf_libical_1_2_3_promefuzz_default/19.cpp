// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_xdaylight at icalcomponent.c:2129:16 in icalcomponent.h
// icalcomponent_strip_errors at icalcomponent.c:1188:6 in icalcomponent.h
// icalcomponent_set_sequence at icalcomponent.c:2019:6 in icalcomponent.h
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
// icalcomponent_begin_component at icalcomponent.c:1401:14 in icalcomponent.h
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
#include <libical/icalcomponent.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    std::ofstream file("./dummy_file", std::ios::binary);
    file.write(reinterpret_cast<const char*>(Data), Size);
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write data to a dummy file
    write_dummy_file(Data, Size);

    // Initialize components
    icalcomponent *comp1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *comp2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Fuzz icalcomponent_get_parent
    icalcomponent *parent = icalcomponent_get_parent(comp1);
    if (parent) {
        // Do something with the parent
    }

    // Fuzz icalcomponent_merge_component
    icalcomponent_merge_component(comp1, comp2);
    comp2 = nullptr; // comp2 is no longer valid after merge

    // Fuzz icalcomponent_begin_component
    icalcompiter iter = icalcomponent_begin_component(comp1, ICAL_VEVENT_COMPONENT);
    if (icalcompiter_is_valid(&iter)) {
        // Do something with the iterator
    }

    // Fuzz icalcomponent_set_sequence
    int sequence_value = static_cast<int>(Data[0]);
    icalcomponent_set_sequence(comp1, sequence_value);

    // Fuzz icalcomponent_new_xdaylight
    icalcomponent *xdaylight = icalcomponent_new_xdaylight();
    if (xdaylight) {
        // Do something with the xdaylight component
        icalcomponent_free(xdaylight);
    }

    // Fuzz icalcomponent_strip_errors
    icalcomponent_strip_errors(comp1);

    // Cleanup
    if (comp1) {
        icalcomponent_free(comp1);
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

        LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    