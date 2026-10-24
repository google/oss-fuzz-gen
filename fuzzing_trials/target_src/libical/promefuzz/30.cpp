// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_isa_component at icalcomponent.c:331:6 in icalcomponent.h
// icalcomponent_kind_is_valid at icalcomponent.c:1341:6 in icalcomponent.h
// icalcompiter_is_valid at icalcomponent.c:1392:6 in icalcomponent.h
// icalcomponent_is_valid at icalcomponent.c:314:6 in icalcomponent.h
// icalcomponent_get_next_component at icalcomponent.c:670:16 in icalcomponent.h
// icalcomponent_begin_component at icalcomponent.c:1401:14 in icalcomponent.h
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
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_dummy_component() {
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    return component;
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy component for testing
    icalcomponent *component = create_dummy_component();
    if (!component) return 0;

    // Fuzz different icalcomponent_kind values
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);

    // Test icalcomponent_get_next_component
    icalcomponent *next_component = icalcomponent_get_next_component(component, kind);
    if (next_component) {
        // Perform operations on next_component if needed
    }

    // Test icalcomponent_begin_component
    icalcompiter comp_iter = icalcomponent_begin_component(component, kind);
    if (icalcompiter_is_valid(&comp_iter)) {
        // Perform operations on comp_iter if needed
    }

    // Test icalcomponent_isa_component
    bool is_component = icalcomponent_isa_component(component);
    (void)is_component; // Suppress unused variable warning

    // Test icalcomponent_is_valid
    bool is_valid = icalcomponent_is_valid(component);
    (void)is_valid; // Suppress unused variable warning

    // Test icalcomponent_kind_is_valid
    bool kind_is_valid = icalcomponent_kind_is_valid(kind);
    (void)kind_is_valid; // Suppress unused variable warning

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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    