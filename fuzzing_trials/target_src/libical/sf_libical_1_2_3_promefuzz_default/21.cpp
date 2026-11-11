// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
// icalcomponent_get_current_component at icalcomponent.c:643:16 in icalcomponent.h
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
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Step 1: Initialize components
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vtodo = icalcomponent_new_vtodo();

    // Step 2: Add components
    icalcomponent_add_component(vcalendar1, vtodo);

    // Step 3: Merge components
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Prevent accidental use

    // Step 4: Get parent component
    icalcomponent *parent = icalcomponent_get_parent(vtodo);
    if (parent != nullptr) {
        // Do something with the parent, e.g., print its kind
        std::cout << "Parent component kind: " << icalcomponent_isa(parent) << std::endl;
    }

    // Step 5: Get current component
    icalcomponent *current = icalcomponent_get_current_component(vcalendar1);
    if (current != nullptr) {
        // Do something with the current component, e.g., print its kind
        std::cout << "Current component kind: " << icalcomponent_isa(current) << std::endl;
    }

    // Step 6: Free components
    // Free vcalendar1 which will also free vtodo since it's a child component
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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    