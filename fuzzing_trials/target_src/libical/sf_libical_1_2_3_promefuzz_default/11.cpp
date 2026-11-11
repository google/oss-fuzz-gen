// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_get_next_component at icalcomponent.c:670:16 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
// icalcomponent_get_x_name at icalcomponent.c:357:13 in icalcomponent.h
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
#include <string>
#include <cstdlib>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a new VCALENDAR component for valid merge operation
    icalcomponent *vcalendar = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (!vcalendar) return 0;

    // Create a VLOCATION component and add it to the VCALENDAR
    icalcomponent *vlocation = icalcomponent_new_vlocation();
    if (!vlocation) {
        icalcomponent_free(vcalendar);
        return 0;
    }
    icalcomponent_add_component(vcalendar, vlocation);

    // Use part of the input data as a description
    std::string description(reinterpret_cast<const char*>(Data), Size);
    
    // Set the description for the VLOCATION component
    icalcomponent_set_description(vlocation, description.c_str());

    // Check if the component is valid
    bool is_valid = icalcomponent_is_valid(vlocation);

    // Retrieve the X-NAME property if the component is valid
    if (is_valid) {
        const char *x_name = icalcomponent_get_x_name(vlocation);
        if (x_name) {
            std::cout << "X-NAME: " << x_name << std::endl;
        }
    }

    // Create another VCALENDAR component for merging
    icalcomponent *vcalendar_to_merge = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (vcalendar_to_merge) {
        // Add a VLOCATION component to the second VCALENDAR
        icalcomponent *vlocation_to_merge = icalcomponent_new_vlocation();
        if (vlocation_to_merge) {
            icalcomponent_add_component(vcalendar_to_merge, vlocation_to_merge);

            // Merge the second VCALENDAR into the first
            icalcomponent_merge_component(vcalendar, vcalendar_to_merge);
        }
    }

    // Get the next component of a specific kind
    icalcomponent *next_component = icalcomponent_get_next_component(vcalendar, ICAL_VLOCATION_COMPONENT);
    if (next_component) {
        std::cout << "Next component found." << std::endl;
    }

    // Clean up
    icalcomponent_free(vcalendar);

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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    