#include <sys/stat.h>
#include <string.h>
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
#include <cstdint>
#include <cstring>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"

static void initialize_dummy_component(icalcomponent *component) {
    // Initialize the component with some dummy properties
    for (int i = 0; i < 5; ++i) {
        icalproperty *prop = icalproperty_new(ICAL_SUMMARY_PROPERTY);
        icalcomponent_add_property(component, prop);
    }
}

static icalcomponent* create_dummy_component() {
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    initialize_dummy_component(component);
    return component;
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    icalcomponent *component = create_dummy_component();
    icalproperty_kind kind = static_cast<icalproperty_kind>(Data[0]);

    // Test icalcomponent_remove_property_by_kind
    icalcomponent_remove_property_by_kind(component, kind);

    // Test icalcomponent_get_first_property
    icalproperty *first_property = icalcomponent_get_first_property(component, kind);
    if (first_property) {
        // Do something with first_property if needed
    }

    // Test icalcomponent_get_next_property
    icalproperty *next_property = icalcomponent_get_next_property(component, kind);
    if (next_property) {
        // Do something with next_property if needed
    }

    // Test icalcomponent_count_properties
    int count = icalcomponent_count_properties(component, kind);

    // Test icalcomponent_get_first_component
    icalcomponent_kind comp_kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);
    icalcomponent *first_component = icalcomponent_get_first_component(component, comp_kind);
    if (first_component) {
        // Do something with first_component if needed
    }

    // Test icalcomponent_begin_property
    icalpropiter prop_iter = icalcomponent_begin_property(component, kind);
    if (icalpropiter_is_valid(&prop_iter)) {
        // Iterate through properties if needed
    }

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
