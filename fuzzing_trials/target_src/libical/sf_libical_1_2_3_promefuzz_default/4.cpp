// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_vcalendar at icalcomponent.c:2089:16 in icalcomponent.h
// icalcomponent_get_current_component at icalcomponent.c:643:16 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new VCALENDAR component
    icalcomponent *vcalendar1 = icalcomponent_new_vcalendar();
    icalcomponent *vcalendar2 = icalcomponent_new_vcalendar();
    if (!vcalendar1 || !vcalendar2) {
        if (vcalendar1) icalcomponent_free(vcalendar1);
        if (vcalendar2) icalcomponent_free(vcalendar2);
        return 0;
    }

    // Add components based on input data
    size_t halfSize = Size / 2;
    for (size_t i = 0; i < halfSize; ++i) {
        icalcomponent *child = icalcomponent_new_vcalendar(); // Using VCALENDAR for simplicity
        if (child) {
            if (i % 2 == 0) {
                icalcomponent_add_component(vcalendar1, child);
            } else {
                icalcomponent_add_component(vcalendar2, child);
            }
        }
    }

    // Merge the second calendar into the first
    icalcomponent_merge_component(vcalendar1, vcalendar2);

    // Test getting the parent of a component
    icalcomponent *childComponent = icalcomponent_get_current_component(vcalendar1);
    if (childComponent) {
        icalcomponent *parent = icalcomponent_get_parent(childComponent);
        if (parent) {
            // Do something with the parent if needed
        }
    }

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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    