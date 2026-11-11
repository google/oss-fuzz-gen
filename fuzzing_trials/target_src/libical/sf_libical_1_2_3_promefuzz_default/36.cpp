// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_xdaylight at icalcomponent.c:2129:16 in icalcomponent.h
// icalcomponent_strip_errors at icalcomponent.c:1188:6 in icalcomponent.h
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
// icalcomponent_set_sequence at icalcomponent.c:2019:6 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
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
#include <cstdlib>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy file to use with functions that might require file input
    std::ofstream dummyFile("./dummy_file");
    if (dummyFile.is_open()) {
        dummyFile.write(reinterpret_cast<const char*>(Data), Size);
        dummyFile.close();
    }

    // Initialize icalcomponents
    icalcomponent* comp1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent* comp2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent* xdaylight = icalcomponent_new_xdaylight();

    // Fuzz icalcomponent_get_parent
    icalcomponent* parent = icalcomponent_get_parent(comp1);

    // Fuzz icalcomponent_merge_component
    if (comp1 && comp2) {
        icalcomponent_merge_component(comp1, comp2);
        comp2 = nullptr;  // comp2 is no longer valid after merge
    }

    // Fuzz icalcomponent_set_sequence
    int sequence = Data[0];  // Use the first byte of data as sequence number
    icalcomponent_set_sequence(comp1, sequence);

    // Fuzz icalcomponent_strip_errors
    icalcomponent_strip_errors(comp1);

    // Clean up
    icalcomponent_free(comp1);
    icalcomponent_free(comp2);
    icalcomponent_free(xdaylight);

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

        LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    