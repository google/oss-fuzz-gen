// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_check_restrictions at icalcomponent.c:1160:6 in icalcomponent.h
// icalcomponent_is_valid at icalcomponent.c:314:6 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_get_next_component at icalcomponent.c:670:16 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
#include <cstddef>
#include <cstdint>

extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"
}

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize libical components
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Create a VLOCATION component
    icalcomponent *vlocation = icalcomponent_new_vlocation();

    // Add the VLOCATION component to vcalendar1
    icalcomponent_add_component(vcalendar1, vlocation);

    // Check restrictions on vcalendar1
    bool has_restrictions = icalcomponent_check_restrictions(vcalendar1);

    // Merge vcalendar2 into vcalendar1
    if (icalcomponent_is_valid(vcalendar2)) {
        icalcomponent_merge_component(vcalendar1, vcalendar2);
        vcalendar2 = nullptr;  // Avoid accidental reuse
    }

    // Iterate over components in vcalendar1
    icalcomponent *next_component = icalcomponent_get_next_component(vcalendar1, ICAL_VLOCATION_COMPONENT);
    while (next_component != nullptr) {
        next_component = icalcomponent_get_next_component(vcalendar1, ICAL_VLOCATION_COMPONENT);
    }

    // Clean up
    icalcomponent_free(vcalendar1);
    if (vcalendar2) {
        icalcomponent_free(vcalendar2);
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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    