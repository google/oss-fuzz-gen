// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_property at icalcomponent.c:443:6 in icalcomponent.h
// icalcomponent_get_current_property at icalcomponent.c:506:15 in icalcomponent.h
// icalcomponent_add_property at icalcomponent.c:428:6 in icalcomponent.h
// icalcomponent_as_ical_string_r at icalcomponent.c:245:7 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize a VCALENDAR component
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Prepare a null-terminated string for description
    char *description = static_cast<char*>(malloc(Size + 1));
    if (!description) return 0;
    memcpy(description, Data, Size);
    description[Size] = '\0';

    // Test icalcomponent_set_description
    icalcomponent_set_description(vcalendar1, description);

    // Create a property and add it to the component
    icalproperty *property = icalproperty_new(ICAL_SUMMARY_PROPERTY);
    if (property) {
        icalcomponent_add_property(vcalendar1, property);
    }

    // Merge two VCALENDAR components
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Prevent accidental use after merge

    // Get current property (if any)
    icalproperty *current_property = icalcomponent_get_current_property(vcalendar1);

    // Remove property if it exists
    if (current_property) {
        icalcomponent_remove_property(vcalendar1, current_property);
        icalproperty_free(current_property);
    }

    // Convert to string representation
    char *ical_string = icalcomponent_as_ical_string_r(vcalendar1);
    if (ical_string) {
        free(ical_string);
    }

    // Clean up
    icalcomponent_free(vcalendar1);
    free(description);

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

        LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    