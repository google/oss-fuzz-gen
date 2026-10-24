// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_set_dtend at icalcomponent.c:1686:6 in icalcomponent.h
// icalcomponent_get_dtstart at icalcomponent.c:1617:21 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
// icalcomponent_get_dtend at icalcomponent.c:1630:21 in icalcomponent.h
// icalcomponent_set_dtstart at icalcomponent.c:1597:6 in icalcomponent.h
// icalcomponent_get_dtstamp at icalcomponent.c:1786:21 in icalcomponent.h
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
#include <libical/icalcomponent.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icaltime.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icalerror.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icaltimezone.h>

static icalcomponent *create_dummy_component() {
    icalcomponent *comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (!comp) {
        std::cerr << "Failed to create icalcomponent.\n";
        return nullptr;
    }
    return comp;
}

static icaltimetype create_dummy_icaltimetype() {
    icaltimetype time = icaltime_null_time();
    time.year = 2023;
    return time;
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    icalcomponent *comp = create_dummy_component();
    if (!comp) return 0;

    icaltimetype dummy_time = create_dummy_icaltimetype();

    // Fuzzing icalcomponent_set_dtstart
    icalcomponent_set_dtstart(comp, dummy_time);

    // Fuzzing icalcomponent_get_dtstart
    icaltimetype dtstart = icalcomponent_get_dtstart(comp);

    // Fuzzing icalcomponent_set_dtstamp
    icalcomponent_set_dtstamp(comp, dummy_time);

    // Fuzzing icalcomponent_get_dtstamp
    icaltimetype dtstamp = icalcomponent_get_dtstamp(comp);

    // Fuzzing icalcomponent_set_dtend
    icalcomponent_set_dtend(comp, dummy_time);

    // Fuzzing icalcomponent_get_dtend
    icaltimetype dtend = icalcomponent_get_dtend(comp);

    // Cleanup
    icalcomponent_free(comp);

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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    