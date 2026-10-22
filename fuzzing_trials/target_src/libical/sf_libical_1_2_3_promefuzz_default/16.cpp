// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_get_first_component at icalcomponent.c:654:16 in icalcomponent.h
// icalcomponent_get_current_component at icalcomponent.c:643:16 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
// icalcomponent_set_recurrenceid at icalcomponent.c:1903:6 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"
}

#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new VTODO component
    icalcomponent *vtodo = icalcomponent_new_vtodo();
    if (!vtodo) return 0;

    // Extract a description string from the input data
    std::string description(reinterpret_cast<const char*>(Data), Size);

    // Call icalcomponent_set_description
    icalcomponent_set_description(vtodo, description.c_str());

    // Create a new VCALENDAR component
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (!vcalendar1 || !vcalendar2) {
        if (vcalendar1) icalcomponent_free(vcalendar1);
        if (vcalendar2) icalcomponent_free(vcalendar2);
        icalcomponent_free(vtodo);
        return 0;
    }

    // Merge vcalendar2 into vcalendar1
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // vcalendar2 should not be used after merging

    // Set a recurrence ID using part of the data as the year
    if (Size >= sizeof(int)) {
        int year;
        std::memcpy(&year, Data, sizeof(int));
        icaltimetype recurrence_id = {year, 0, 0, 0, 0, 0, 0, 0, 0};
        icalcomponent_set_recurrenceid(vtodo, recurrence_id);
    }

    // Search for the first VTODO component within vcalendar1
    icalcomponent *first_vtodo = icalcomponent_get_first_component(vcalendar1, ICAL_VTODO_COMPONENT);

    // Get the current component from vcalendar1
    icalcomponent *current_component = icalcomponent_get_current_component(vcalendar1);

    // Cleanup
    if (first_vtodo) icalcomponent_free(first_vtodo);
    if (current_component) icalcomponent_free(current_component);
    icalcomponent_free(vcalendar1);
    icalcomponent_free(vtodo);

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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    