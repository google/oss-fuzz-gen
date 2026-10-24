// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
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
#include <cstdlib>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    // Create two VCALENDAR components for testing
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    
    // Create a VTIMEZONE component
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();

    // Attach the VTIMEZONE component to the first VCALENDAR
    icalcomponent_add_component(vcalendar1, vtimezone);

    // Set parent-child relationships
    icalcomponent_set_parent(vtimezone, vcalendar1);

    // Retrieve the parent of the VTIMEZONE component
    icalcomponent *parent = icalcomponent_get_parent(vtimezone);
    if (parent != vcalendar1) {
        std::cerr << "Parent mismatch error!" << std::endl;
    }

    // Merge the second VCALENDAR into the first
    icalcomponent_merge_component(vcalendar1, vcalendar2);

    // Clean up
    icalcomponent_free(vcalendar1); // This will also free vtimezone
    // vcalendar2 is already merged and should not be freed again

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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    