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
#include <fstream>
#include <cstdint>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_vcalendar_component() {
    icalcomponent* comp = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (comp) {
        icalcomponent* vevent = icalcomponent_new(ICAL_VEVENT_COMPONENT);
        if (vevent) {
            icalcomponent_add_component(comp, vevent);
        }
    }
    return comp;
}

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create two VCALENDAR components
    icalcomponent* vcalendar1 = create_vcalendar_component();
    icalcomponent* vcalendar2 = create_vcalendar_component();

    if (!vcalendar1 || !vcalendar2) {
        if (vcalendar1) icalcomponent_free(vcalendar1);
        if (vcalendar2) icalcomponent_free(vcalendar2);
        return 0;
    }

    // Fuzzing icalcomponent_merge_component
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr;  // vcalendar2 is no longer valid

    // Fuzzing icalcomponent_check_restrictions
    bool has_restrictions = icalcomponent_check_restrictions(vcalendar1);

    // Fuzzing icalcomponent_new_vlocation
    icalcomponent* vlocation = icalcomponent_new_vlocation();
    if (vlocation) {
        icalcomponent_add_component(vcalendar1, vlocation);
    }

    // Fuzzing icalcomponent_get_next_component
    icalcomponent* next_comp = icalcomponent_get_next_component(vcalendar1, ICAL_VEVENT_COMPONENT);

    // Fuzzing icalcomponent_is_valid
    bool is_valid = icalcomponent_is_valid(vcalendar1);

    // Cleanup
    icalcomponent_free(vcalendar1);

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

        LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    