// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_get_current_component at icalcomponent.c:643:16 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
// icalproperty_get_parent at icalproperty.c:939:16 in icalcomponent.h
// icalcomponent_set_uid at icalcomponent.c:1868:6 in icalcomponent.h
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
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Prepare a UID string from input data
    char uid[256];
    size_t uid_length = (Size < 255) ? Size : 255;
    std::memcpy(uid, Data, uid_length);
    uid[uid_length] = '\0';

    // Create a new VTIMEZONE component
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();

    // Set UID for the VTIMEZONE component
    icalcomponent_set_uid(vtimezone, uid);

    // Create a parent component (VCALENDAR)
    icalcomponent *vcalendar = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Add the VTIMEZONE component to the VCALENDAR
    icalcomponent_add_component(vcalendar, vtimezone);

    // Retrieve the parent of the VTIMEZONE component
    icalcomponent *parent = icalproperty_get_parent((icalproperty *)vtimezone);

    // Set the parent explicitly
    icalcomponent_set_parent(vtimezone, vcalendar);

    // Get the current component from the parent
    icalcomponent *current = icalcomponent_get_current_component(vcalendar);

    // Cleanup
    icalcomponent_free(vcalendar);
    // vtimezone is freed as part of vcalendar

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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    