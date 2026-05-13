// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_get_current_property at icalcomponent.c:506:15 in icalcomponent.h
// icalcomponent_add_property at icalcomponent.c:428:6 in icalcomponent.h
// icalproperty_set_parent at icalproperty.c:932:6 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
// icalcomponent_clone at icalcomponent.c:137:16 in icalcomponent.h
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icalcomponent_kind)) {
        return 0;
    }

    // Create a dummy icalcomponent
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0]);
    icalcomponent *component = icalcomponent_new(kind);

    if (!component) {
        return 0;
    }

    // Test icalcomponent_clone
    icalcomponent *cloned_component = icalcomponent_clone(component);
    if (cloned_component) {
        icalcomponent_free(cloned_component);
    }

    // Test icalcomponent_is_valid
    bool is_valid = icalcomponent_is_valid(component);
    assert(is_valid == (kind != ICAL_NO_COMPONENT));

    // Test icalcomponent_add_component
    icalcomponent *child_component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (child_component) {
        icalcomponent_add_component(component, child_component);
        icalcomponent_free(child_component);
    }

    // Test icalcomponent_get_current_property
    icalproperty *current_property = icalcomponent_get_current_property(component);
    if (current_property) {
        // Do something with current_property if needed
    }

    // Create a dummy icalproperty
    icalproperty *property = icalproperty_new(ICAL_SUMMARY_PROPERTY);
    if (property) {
        // Test icalproperty_set_parent
        icalproperty_set_parent(property, component);

        // Test icalcomponent_add_property
        icalcomponent_add_property(component, property);

        // Normally we would free property, but icalcomponent_add_property takes ownership
    }

    // Clean up
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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    