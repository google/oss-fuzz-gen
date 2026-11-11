// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_get_first_component at icalcomponent.c:654:16 in icalcomponent.h
// icalcomponent_begin_component at icalcomponent.c:1401:14 in icalcomponent.h
// icalcomponent_get_next_component at icalcomponent.c:670:16 in icalcomponent.h
// icalcomponent_get_current_component at icalcomponent.c:643:16 in icalcomponent.h
// icalcomponent_is_valid at icalcomponent.c:314:6 in icalcomponent.h
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
#include <cstdlib>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create dummy components for testing
    icalcomponent *comp1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *comp2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Write data to a dummy file if necessary
    std::ofstream dummyFile("./dummy_file", std::ios::binary);
    if (dummyFile.is_open()) {
        dummyFile.write(reinterpret_cast<const char*>(Data), Size);
        dummyFile.close();
    }

    // Fuzz icalcomponent_get_first_component
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);
    icalcomponent *firstComp = icalcomponent_get_first_component(comp1, kind);

    // Fuzz icalcomponent_merge_component
    icalcomponent_merge_component(comp1, comp2);
    comp2 = nullptr;  // Prevent accidental reuse

    // Fuzz icalcomponent_get_current_component
    icalcomponent *currentComp = icalcomponent_get_current_component(comp1);

    // Fuzz icalcomponent_begin_component
    icalcompiter compIter = icalcomponent_begin_component(comp1, kind);

    // Fuzz icalcomponent_get_next_component
    icalcomponent *nextComp = icalcomponent_get_next_component(comp1, kind);

    // Fuzz icalcomponent_is_valid
    bool isValid = icalcomponent_is_valid(comp1);

    // Clean up
    if (firstComp) icalcomponent_free(firstComp);
    if (currentComp) icalcomponent_free(currentComp);
    if (nextComp) icalcomponent_free(nextComp);
    if (comp1) icalcomponent_free(comp1);

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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    