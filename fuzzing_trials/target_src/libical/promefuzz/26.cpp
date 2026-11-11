// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_set_method at icalcomponent.c:1561:6 in icalcomponent.h
// icalcomponent_get_method at icalcomponent.c:1573:21 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_new_xdaylight at icalcomponent.c:2129:16 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
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
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
#include <cstdint>

static icalcomponent* create_dummy_component() {
    return icalcomponent_new(ICAL_VEVENT_COMPONENT);
}

static void test_icalcomponent_get_method(icalcomponent* comp) {
    icalproperty_method method = icalcomponent_get_method(comp);
    (void)method; // Suppress unused variable warning
}

static void test_icalcomponent_set_method(icalcomponent* comp, icalproperty_method method) {
    icalcomponent_set_method(comp, method);
}

static void test_icalcomponent_add_component(icalcomponent* parent, icalcomponent* child) {
    icalcomponent_add_component(parent, child);
}

static void test_icalcomponent_remove_component(icalcomponent* parent, icalcomponent* child) {
    icalcomponent_remove_component(parent, child);
}

static void test_icalcomponent_set_parent(icalcomponent* component, icalcomponent* parent) {
    icalcomponent_set_parent(component, parent);
}

static icalcomponent* test_icalcomponent_new_xdaylight() {
    return icalcomponent_new_xdaylight();
}

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    icalcomponent* parent = create_dummy_component();
    icalcomponent* child = create_dummy_component();

    if (!parent || !child) {
        if (parent) icalcomponent_free(parent);
        if (child) icalcomponent_free(child);
        return 0;
    }

    // Test icalcomponent_get_method and icalcomponent_set_method
    test_icalcomponent_get_method(parent);
    test_icalcomponent_set_method(parent, static_cast<icalproperty_method>(Data[0] % (ICAL_METHOD_NONE + 1)));

    // Test icalcomponent_add_component and icalcomponent_remove_component
    test_icalcomponent_add_component(parent, child);
    test_icalcomponent_remove_component(parent, child);

    // Test icalcomponent_set_parent
    test_icalcomponent_set_parent(child, parent);

    // Test icalcomponent_new_xdaylight
    icalcomponent* xdaylight = test_icalcomponent_new_xdaylight();
    if (xdaylight) {
        icalcomponent_free(xdaylight);
    }

    // Clean up
    icalcomponent_free(parent);
    icalcomponent_free(child);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    