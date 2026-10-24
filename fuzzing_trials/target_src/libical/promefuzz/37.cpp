// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_foreach_recurrence at icalcomponent.c:970:6 in icalcomponent.h
// icalcomponent_set_recurrenceid at icalcomponent.c:1903:6 in icalcomponent.h
// icalcomponent_get_recurrenceid at icalcomponent.c:1923:21 in icalcomponent.h
// icalproperty_recurrence_is_excluded at icalcomponent.c:781:6 in icalcomponent.h
// icalcomponent_new_valarm at icalcomponent.c:2109:16 in icalcomponent.h
// icalcomponent_get_dtstart at icalcomponent.c:1617:21 in icalcomponent.h
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
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icaltimezone.h>

// Callback function for icalcomponent_foreach_recurrence
static void recurrence_callback(const icalcomponent *comp, const struct icaltime_span *span, void *data) {
    // Do nothing for now
    (void)comp;
    (void)span;
    (void)data;
}

// Helper function to create a random icaltimetype
static struct icaltimetype create_random_icaltimetype(const uint8_t *Data, size_t Size, size_t &offset) {
    struct icaltimetype tt = icaltime_null_time();
    if (offset + sizeof(int) <= Size) {
        tt.year = *(reinterpret_cast<const int*>(Data + offset));
        offset += sizeof(int);
    }
    tt.zone = icaltimezone_get_utc_timezone();
    return tt;
}

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    icalcomponent *comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (!comp) return 0;

    size_t offset = 0;

    // Fuzz icalcomponent_set_recurrenceid
    struct icaltimetype recurrenceid = create_random_icaltimetype(Data, Size, offset);
    icalcomponent_set_recurrenceid(comp, recurrenceid);

    // Fuzz icalcomponent_get_dtstart
    struct icaltimetype dtstart = icalcomponent_get_dtstart(comp);

    // Fuzz icalcomponent_get_recurrenceid
    struct icaltimetype got_recurrenceid = icalcomponent_get_recurrenceid(comp);

    // Fuzz icalcomponent_foreach_recurrence
    struct icaltimetype start = create_random_icaltimetype(Data, Size, offset);
    struct icaltimetype end = create_random_icaltimetype(Data, Size, offset);
    icalcomponent_foreach_recurrence(comp, start, end, recurrence_callback, nullptr);

    // Fuzz icalproperty_recurrence_is_excluded
    bool is_excluded = icalproperty_recurrence_is_excluded(comp, &dtstart, &recurrenceid);

    // Fuzz icalcomponent_new_valarm
    icalcomponent *valarm = icalcomponent_new_valarm();
    if (valarm) {
        icalcomponent_free(valarm);
    }

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

        LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    