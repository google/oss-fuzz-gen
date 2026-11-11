// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_xdaylight at icalcomponent.c:2129:16 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_new_vcalendar at icalcomponent.c:2089:16 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
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

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create two VCALENDAR components
    icalcomponent *vcalendar1 = icalcomponent_new_vcalendar();
    icalcomponent *vcalendar2 = icalcomponent_new_vcalendar();

    // Create additional components to add to the VCALENDAR components
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();
    icalcomponent *xdaylight = icalcomponent_new_xdaylight();
    icalcomponent *vlocation = icalcomponent_new_vlocation();

    // Randomly add components to vcalendar1 or vcalendar2 based on input data
    if (Data[0] % 2 == 0) {
        icalcomponent_add_component(vcalendar1, vtimezone);
        icalcomponent_add_component(vcalendar2, xdaylight);
    } else {
        icalcomponent_add_component(vcalendar1, xdaylight);
        icalcomponent_add_component(vcalendar2, vlocation);
    }

    // Merge vcalendar2 into vcalendar1
    icalcomponent_merge_component(vcalendar1, vcalendar2);

    // Set vcalendar2 to nullptr after merging
    vcalendar2 = nullptr;

    // Cleanup: free all components
    icalcomponent_free(vcalendar1);
    // vcalendar2 is already merged and set to nullptr
    // No need to free vtimezone, xdaylight, or vlocation separately as they are added to the vcalendar components
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

        LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    