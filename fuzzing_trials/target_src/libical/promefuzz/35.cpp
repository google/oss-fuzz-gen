// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcompiter_is_valid at icalcomponent.c:1392:6 in icalcomponent.h
// icalcomponent_isa_component at icalcomponent.c:331:6 in icalcomponent.h
// icalcomponent_kind_is_valid at icalcomponent.c:1341:6 in icalcomponent.h
// icalcomponent_is_valid at icalcomponent.c:314:6 in icalcomponent.h
// icalcomponent_get_next_component at icalcomponent.c:670:16 in icalcomponent.h
// icalcomponent_begin_component at icalcomponent.c:1401:14 in icalcomponent.h
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <fstream>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_dummy_component() {
    icalcomponent* component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    return component;
}

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icalcomponent_kind)) {
        return 0;
    }

    // Extract a kind from the input data
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);

    // Create a dummy component
    icalcomponent* component = create_dummy_component();

    if (component == nullptr) {
        return 0;
    }

    // Test icalcomponent_get_next_component
    icalcomponent* next_component = icalcomponent_get_next_component(component, kind);
    if (next_component != nullptr) {
        // Do something with next_component if needed
    }

    // Test icalcomponent_begin_component
    icalcompiter compiter = icalcomponent_begin_component(component, kind);
    if (icalcompiter_is_valid(&compiter)) {
        // Do something with compiter if needed
    }

    // Test icalcomponent_is_valid
    bool is_valid = icalcomponent_is_valid(component);
    if (is_valid) {
        // Do something if valid
    }

    // Test icalcomponent_isa_component
    bool isa_component = icalcomponent_isa_component(component);
    if (isa_component) {
        // Do something if it is a component
    }

    // Test icalcomponent_kind_is_valid
    bool kind_is_valid = icalcomponent_kind_is_valid(kind);
    if (kind_is_valid) {
        // Do something if kind is valid
    }

    // Cleanup
    icalcomponent_free(component);

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

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    