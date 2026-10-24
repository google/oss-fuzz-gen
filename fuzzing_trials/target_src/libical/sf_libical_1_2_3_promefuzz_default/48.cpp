// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_check_restrictions at icalcomponent.c:1160:6 in icalcomponent.h
// icalcomponent_is_valid at icalcomponent.c:314:6 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_get_next_component at icalcomponent.c:670:16 in icalcomponent.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new VCALENDAR component
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Create a new VLOCATION component
    icalcomponent *vlocation = icalcomponent_new_vlocation();

    // Add VLOCATION to the first VCALENDAR
    icalcomponent_add_component(vcalendar1, vlocation);

    // Check if the components are valid
    bool isValid1 = icalcomponent_is_valid(vcalendar1);
    bool isValid2 = icalcomponent_is_valid(vcalendar2);

    // Merge the second VCALENDAR into the first
    if (isValid1 && isValid2) {
        icalcomponent_merge_component(vcalendar1, vcalendar2);
        vcalendar2 = nullptr; // Prevent accidental reuse
    }

    // Check restrictions on the first VCALENDAR
    bool hasRestrictions = icalcomponent_check_restrictions(vcalendar1);

    // Iterate over components in the first VCALENDAR
    icalcomponent *nextComponent = nullptr;
    while ((nextComponent = icalcomponent_get_next_component(vcalendar1, ICAL_VLOCATION_COMPONENT)) != nullptr) {
        // Do something with nextComponent if needed
    }

    // Cleanup
    if (vcalendar1) {
        icalcomponent_free(vcalendar1);
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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    