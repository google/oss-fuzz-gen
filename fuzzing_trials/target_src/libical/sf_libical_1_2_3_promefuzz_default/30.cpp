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
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy VCALENDAR component
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Ensure the input string is null-terminated
    char *description = static_cast<char*>(malloc(Size + 1));
    if (!description) return 0;
    memcpy(description, Data, Size);
    description[Size] = '\0';

    // Fuzz icalcomponent_set_description
    icalcomponent_set_description(vcalendar1, description);

    // Create a dummy property
    icalproperty *property = icalproperty_new(ICAL_NO_PROPERTY);

    // Fuzz icalcomponent_add_property
    icalcomponent_add_property(vcalendar1, property);

    // Fuzz icalcomponent_merge_component
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Prevent accidental reuse

    // Fuzz icalcomponent_remove_property
    icalcomponent_remove_property(vcalendar1, property);

    // Fuzz icalcomponent_as_ical_string_r
    char *ical_string = icalcomponent_as_ical_string_r(vcalendar1);
    if (ical_string) {
        free(ical_string);
    }

    // Fuzz icalcomponent_get_current_property
    icalproperty *current_property = icalcomponent_get_current_property(vcalendar1);

    // Clean up
    free(description);
    icalcomponent_free(vcalendar1);
    if (vcalendar2) {
        icalcomponent_free(vcalendar2);
    }
    if (property) {
        icalproperty_free(property);
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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    