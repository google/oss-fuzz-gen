// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_xdaylight at icalcomponent.c:2129:16 in icalcomponent.h
// icalcomponent_strip_errors at icalcomponent.c:1188:6 in icalcomponent.h
// icalcomponent_get_parent at icalcomponent.c:1270:16 in icalcomponent.h
// icalcomponent_set_sequence at icalcomponent.c:2019:6 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
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
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

static void test_icalcomponent_get_parent(icalcomponent *component) {
    icalcomponent *parent = icalcomponent_get_parent(component);
    // We can't do much with the parent in a fuzzing context,
    // but we can check if it is not null and ensure it doesn't crash.
    if (parent) {
        // Do something trivial to use the parent
        (void)icalcomponent_get_parent(parent);
    }
}

static void test_icalcomponent_merge_component(icalcomponent *comp1, icalcomponent *comp2) {
    if (icalcomponent_isa(comp1) == ICAL_VCALENDAR_COMPONENT &&
        icalcomponent_isa(comp2) == ICAL_VCALENDAR_COMPONENT) {
        icalcomponent_merge_component(comp1, comp2);
        // After merging, comp2 should not be used, so we set it to nullptr.
        comp2 = nullptr;
    }
}

static void test_icalcomponent_set_sequence(icalcomponent *component, int sequence) {
    icalcomponent_set_sequence(component, sequence);
}

static icalcomponent *test_icalcomponent_new_xdaylight() {
    return icalcomponent_new_xdaylight();
}

static void test_icalcomponent_strip_errors(icalcomponent *component) {
    icalcomponent_strip_errors(component);
}

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new VCALENDAR component
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Create a new XDAYLIGHT component
    icalcomponent *xdaylight = test_icalcomponent_new_xdaylight();

    // Set sequence based on input data
    int sequence = static_cast<int>(Data[0]);
    test_icalcomponent_set_sequence(vcalendar1, sequence);

    // Merge the two VCALENDAR components
    test_icalcomponent_merge_component(vcalendar1, vcalendar2);

    // Test getting the parent of the XDAYLIGHT component
    test_icalcomponent_get_parent(xdaylight);

    // Strip errors from the VCALENDAR component
    test_icalcomponent_strip_errors(vcalendar1);

    // Free all components
    icalcomponent_free(xdaylight);
    icalcomponent_free(vcalendar1);
    // vcalendar2 is already merged and should not be freed

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

        LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    