// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalproperty_get_datetime_with_component at icalproperty.c:1072:21 in icalcomponent.h
// icalcomponent_get_due at icalcomponent.c:2661:21 in icalcomponent.h
// icalcomponent_get_dtend at icalcomponent.c:1630:21 in icalcomponent.h
// icalcomponent_set_dtend at icalcomponent.c:1686:6 in icalcomponent.h
// icalcomponent_set_due at icalcomponent.c:2682:6 in icalcomponent.h
// icalcomponent_get_inner at icalcomponent.c:1552:16 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>

static icalcomponent* create_component_from_data(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    // Attempt to parse the data as an iCalendar component
    char* dataCopy = static_cast<char*>(malloc(size + 1));
    if (!dataCopy) return nullptr;
    memcpy(dataCopy, data, size);
    dataCopy[size] = '\0';
    icalcomponent* component = icalparser_parse_string(dataCopy);
    free(dataCopy);
    return component;
}

static icalproperty* create_property_from_data(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    // Attempt to parse the data as an iCalendar property
    char* dataCopy = static_cast<char*>(malloc(size + 1));
    if (!dataCopy) return nullptr;
    memcpy(dataCopy, data, size);
    dataCopy[size] = '\0';
    icalproperty* prop = icalproperty_new_from_string(dataCopy);
    free(dataCopy);
    return prop;
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    // Split the data into two parts for property and component
    size_t mid = Size / 2;
    const uint8_t* propData = Data;
    size_t propSize = mid;
    const uint8_t* compData = Data + mid;
    size_t compSize = Size - mid;

    icalproperty* prop = create_property_from_data(propData, propSize);
    icalcomponent* comp = create_component_from_data(compData, compSize);

    if (prop && comp) {
        // Fuzz icalproperty_get_datetime_with_component
        struct icaltimetype dt = icalproperty_get_datetime_with_component(prop, comp);
        if (!icaltime_is_null_time(dt)) {
            // Do something with the result if needed
        }

        // Fuzz icalcomponent_get_due
        struct icaltimetype due = icalcomponent_get_due(comp);
        if (!icaltime_is_null_time(due)) {
            // Do something with the result if needed
        }

        // Fuzz icalcomponent_get_dtend
        struct icaltimetype dtend = icalcomponent_get_dtend(comp);
        if (!icaltime_is_null_time(dtend)) {
            // Do something with the result if needed
        }

        // Fuzz icalcomponent_get_inner
        icalcomponent* innerComp = icalcomponent_get_inner(comp);
        if (innerComp) {
            // Do something with the result if needed
        }

        // Fuzz icalcomponent_set_dtend
        icalcomponent_set_dtend(comp, dt);

        // Fuzz icalcomponent_set_due
        icalcomponent_set_due(comp, due);
    }

    if (prop) {
        icalproperty_free(prop);
    }
    if (comp) {
        icalcomponent_free(comp);
    }

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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    