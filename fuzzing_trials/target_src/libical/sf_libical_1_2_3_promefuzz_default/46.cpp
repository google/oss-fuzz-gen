// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_get_iana_name at icalcomponent.c:378:13 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_set_dtstamp at icalcomponent.c:1774:6 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
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
#include <libical/icaltime.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icaltimezone.h>

static icalcomponent* create_vcalendar_component() {
    return icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
}

static icalcomponent* create_vtimezone_component() {
    return icalcomponent_new_vtimezone();
}

static void set_dtstamp(icalcomponent* comp) {
    struct icaltimetype now = icaltime_current_time_with_zone(icaltimezone_get_utc_timezone());
    icalcomponent_set_dtstamp(comp, now);
}

static void merge_components(icalcomponent* comp1, icalcomponent* comp2) {
    icalcomponent_merge_component(comp1, comp2);
    comp2 = nullptr;  // Prevent reuse or freeing
}

static void set_parent(icalcomponent* child, icalcomponent* parent) {
    icalcomponent_set_parent(child, parent);
}

static const char* get_iana_name(const icalcomponent* comp) {
    return icalcomponent_get_x_name(comp);
}

static void remove_component(icalcomponent* parent, icalcomponent* child) {
    icalcomponent_remove_component(parent, child);
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    icalcomponent* vcalendar1 = create_vcalendar_component();
    icalcomponent* vcalendar2 = create_vcalendar_component();

    if (vcalendar1 && vcalendar2) {
        set_dtstamp(vcalendar1);
        set_dtstamp(vcalendar2);

        merge_components(vcalendar1, vcalendar2);

        icalcomponent* vtimezone = create_vtimezone_component();
        if (vtimezone) {
            set_parent(vtimezone, vcalendar1);

            const char* name = get_iana_name(vtimezone);
            if (name) {
                std::cout << "IANA Name: " << name << std::endl;
            }

            remove_component(vcalendar1, vtimezone);
            icalcomponent_free(vtimezone);
        }
    }

    if (vcalendar1) {
        icalcomponent_free(vcalendar1);
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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    