// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_get_next_component at icalcomponent.c:670:16 in icalcomponent.h
// icalcomponent_set_due at icalcomponent.c:2682:6 in icalcomponent.h
// icalcomponent_get_dtstart at icalcomponent.c:1617:21 in icalcomponent.h
// icalcomponent_get_iana_name at icalcomponent.c:378:13 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"
}

#include <cstdint>
#include <cstring>
#include <fstream>

static icaltimetype CreateIcalTimeType(const uint8_t *Data, size_t Size) {
    icaltimetype time = icaltime_null_time();
    if (Size >= sizeof(int)) {
        std::memcpy(&time.year, Data, sizeof(int));
    }
    return time;
}

static icalcomponent* CreateVComponent(icalcomponent_kind kind) {
    return icalcomponent_new(kind);
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Fuzz icalcomponent_set_due
    icalcomponent *vtodo = CreateVComponent(ICAL_VTODO_COMPONENT);
    icaltimetype due_time = CreateIcalTimeType(Data, Size);
    icalcomponent_set_due(vtodo, due_time);

    // Fuzz icalcomponent_merge_component
    icalcomponent *vcalendar1 = CreateVComponent(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = CreateVComponent(ICAL_VCALENDAR_COMPONENT);
    icalcomponent_merge_component(vcalendar1, vcalendar2);

    // Fuzz icalcomponent_get_dtstart
    icaltimetype dtstart = icalcomponent_get_dtstart(vcalendar1);

    // Fuzz icalcomponent_get_iana_name
    const char *iana_name = icalcomponent_get_x_name(vcalendar1);

    // Fuzz icalcomponent_new_vlocation
    icalcomponent *vlocation = icalcomponent_new_vlocation();

    // Fuzz icalcomponent_get_next_component
    icalcomponent *next_component = icalcomponent_get_next_component(vcalendar1, ICAL_VEVENT_COMPONENT);

    // Cleanup
    icalcomponent_free(vtodo);
    icalcomponent_free(vcalendar1);
    icalcomponent_free(vlocation);

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

        LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    