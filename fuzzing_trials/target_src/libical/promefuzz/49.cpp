// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalproperty_get_datetime_with_component at icalproperty.c:1072:21 in icalcomponent.h
// icalcomponent_get_dtstamp at icalcomponent.c:1786:21 in icalcomponent.h
// icalcomponent_get_dtstart at icalcomponent.c:1617:21 in icalcomponent.h
// icalcomponent_set_dtend at icalcomponent.c:1686:6 in icalcomponent.h
// icalcomponent_get_dtend at icalcomponent.c:1630:21 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
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
#include <libical/icalcomponent.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icalproperty.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icaltime.h>

static icalcomponent* create_component_from_data(const uint8_t* Data, size_t Size) {
    // Create a dummy VEVENT component for testing
    icalcomponent* comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (Size > 0) {
        std::string dataStr(reinterpret_cast<const char*>(Data), Size);
        struct icaltimetype tt = icaltime_from_string(dataStr.c_str());
        if (!icaltime_is_null_time(tt)) {
            icalproperty* prop = icalproperty_new_dtstart(tt);
            if (prop) {
                icalcomponent_add_property(comp, prop);
            }
        }
    }
    return comp;
}

static icalproperty* create_property_from_data(const uint8_t* Data, size_t Size) {
    // Create a dummy DTSTART property for testing
    if (Size > 0) {
        std::string dataStr(reinterpret_cast<const char*>(Data), Size);
        struct icaltimetype tt = icaltime_from_string(dataStr.c_str());
        if (!icaltime_is_null_time(tt)) {
            return icalproperty_new_dtstart(tt);
        }
    }
    return nullptr;
}

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    icalcomponent* comp = create_component_from_data(Data, Size);
    icalproperty* prop = create_property_from_data(Data, Size);

    if (comp && prop) {
        // Test icalproperty_get_datetime_with_component
        struct icaltimetype dt = icalproperty_get_datetime_with_component(prop, comp);
        if (!icaltime_is_null_time(dt)) {
            icalcomponent_set_dtstamp(comp, dt);
            icalcomponent_set_dtend(comp, dt);
        }

        // Test icalcomponent_get_dtstart
        struct icaltimetype dtstart = icalcomponent_get_dtstart(comp);
        if (!icaltime_is_null_time(dtstart)) {
            icalcomponent_set_dtstamp(comp, dtstart);
        }

        // Test icalcomponent_get_dtend
        struct icaltimetype dtend = icalcomponent_get_dtend(comp);
        if (!icaltime_is_null_time(dtend)) {
            icalcomponent_set_dtstamp(comp, dtend);
        }

        // Test icalcomponent_get_dtstamp
        struct icaltimetype dtstamp = icalcomponent_get_dtstamp(comp);
        if (!icaltime_is_null_time(dtstamp)) {
            icalcomponent_set_dtend(comp, dtstamp);
        }
    }

    if (comp) {
        icalcomponent_free(comp);
    }
    if (prop) {
        icalproperty_free(prop);
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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    