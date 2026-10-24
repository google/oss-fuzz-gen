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
#include <libical/icaltimezone.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icalerror.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icaltime.h>

static icalcomponent* create_vcalendar_component() {
    icalcomponent* comp = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (!comp) {
        std::cerr << "Failed to create VCALENDAR component." << std::endl;
        return nullptr;
    }
    return comp;
}

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    std::ofstream ofs("./dummy_file", std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(Data), Size);
    ofs.close();
}

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare components
    icalcomponent* vcalendar1 = create_vcalendar_component();
    icalcomponent* vcalendar2 = create_vcalendar_component();
    if (!vcalendar1 || !vcalendar2) {
        if (vcalendar1) icalcomponent_free(vcalendar1);
        if (vcalendar2) icalcomponent_free(vcalendar2);
        return 0;
    }

    // Perform merge operation
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr;  // Prevent accidental use

    // Set parent relationship
    icalcomponent* child = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    icalcomponent_set_parent(child, vcalendar1);

    // Get IANA name
    const char* iana_name = icalcomponent_get_x_name(vcalendar1);
    if (iana_name) {
        std::cout << "IANA Name: " << iana_name << std::endl;
    }

    // Remove component
    icalcomponent_remove_component(vcalendar1, child);
    icalcomponent_free(child);

    // Create and set DTSTAMP
    icalcomponent* vtimezone = icalcomponent_new_vtimezone();
    if (vtimezone) {
        struct icaltimetype dtstamp = icaltime_current_time_with_zone(nullptr);
        icalcomponent_set_dtstamp(vtimezone, dtstamp);
        icalcomponent_free(vtimezone);
    }

    // Write to dummy file
    write_dummy_file(Data, Size);

    // Cleanup
    icalcomponent_free(vcalendar1);

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

        LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    