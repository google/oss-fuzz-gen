// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_new_valarm at icalcomponent.c:2109:16 in icalcomponent.h
// icalcomponent_strip_errors at icalcomponent.c:1188:6 in icalcomponent.h
// icalcomponent_remove_property at icalcomponent.c:443:6 in icalcomponent.h
// icalcomponent_isa at icalcomponent.c:324:20 in icalcomponent.h
// icalcomponent_convert_errors at icalcomponent.c:1211:6 in icalcomponent.h
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
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a new VALARM component
    icalcomponent *valarm = icalcomponent_new_valarm();
    if (!valarm) {
        return 0;
    }

    // Create a parent component of type VCALENDAR
    icalcomponent *parent = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (!parent) {
        icalcomponent_free(valarm);
        return 0;
    }

    // Optionally add the VALARM to the parent
    if (Data[0] % 2 == 0) {
        icalcomponent_add_component(parent, valarm);
    }

    // Fuzz icalcomponent_isa
    icalcomponent_kind kind = icalcomponent_isa(valarm);

    // Fuzz icalcomponent_strip_errors
    icalcomponent_strip_errors(parent);

    // Fuzz icalcomponent_convert_errors
    icalcomponent_convert_errors(parent);

    // Create a dummy property
    icalproperty *property = icalproperty_new(ICAL_SUMMARY_PROPERTY);
    if (property) {
        icalcomponent_add_property(parent, property);

        // Fuzz icalcomponent_remove_property
        icalcomponent_remove_property(parent, property);

        // Clean up the property
        icalproperty_free(property);
    }

    // Fuzz icalcomponent_remove_component
    icalcomponent_remove_component(parent, valarm);

    // Clean up components
    icalcomponent_free(parent);
    icalcomponent_free(valarm);

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

        LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    