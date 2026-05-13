// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalpropiter_deref at icalcomponent.c:1541:15 in icalcomponent.h
// icalpropiter_next at icalcomponent.c:1522:15 in icalcomponent.h
// icalcomponent_get_current_property at icalcomponent.c:506:15 in icalcomponent.h
// icalcomponent_begin_property at icalcomponent.c:1495:14 in icalcomponent.h
// icalcomponent_remove_property at icalcomponent.c:443:6 in icalcomponent.h
// icalcomponent_add_property at icalcomponent.c:428:6 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

static icalcomponent* create_dummy_component() {
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    icalproperty *property = icalproperty_new(ICAL_SUMMARY_PROPERTY);
    icalcomponent_add_property(component, property);
    return component;
}

static void fuzz_icalpropiter_deref(icalpropiter *iter) {
    icalproperty *prop = icalpropiter_deref(iter);
    // Utilize the property if needed, currently just dereferencing
}

static void fuzz_icalcomponent_add_property(icalcomponent *component, icalproperty *property) {
    icalcomponent_add_property(component, property);
}

static void fuzz_icalpropiter_next(icalpropiter *iter) {
    icalproperty *prop = icalpropiter_next(iter);
    // Utilize the property if needed, currently just iterating
}

static void fuzz_icalcomponent_begin_property(icalcomponent *component, icalproperty_kind kind) {
    icalpropiter iter = icalcomponent_begin_property(component, kind);
    if (icalpropiter_deref(&iter)) {
        fuzz_icalpropiter_deref(&iter);
        fuzz_icalpropiter_next(&iter);
    }
}

static void fuzz_icalcomponent_remove_property(icalcomponent *component, icalproperty *property) {
    icalcomponent_remove_property(component, property);
}

static void fuzz_icalcomponent_get_current_property(icalcomponent *component) {
    icalproperty *prop = icalcomponent_get_current_property(component);
    // Utilize the property if needed, currently just getting current property
}

extern "C" int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icalproperty_kind)) return 0;

    icalcomponent *component = create_dummy_component();
    icalproperty_kind kind = static_cast<icalproperty_kind>(Data[0] % ICAL_NO_PROPERTY);

    fuzz_icalcomponent_begin_property(component, kind);

    icalproperty *new_property = icalproperty_new(kind);
    fuzz_icalcomponent_add_property(component, new_property);

    fuzz_icalcomponent_get_current_property(component);

    fuzz_icalcomponent_remove_property(component, new_property);
    icalproperty_free(new_property);

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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    