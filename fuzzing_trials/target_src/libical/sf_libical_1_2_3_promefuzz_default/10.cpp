// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
// icalcomponent_set_due at icalcomponent.c:2682:6 in icalcomponent.h
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
#include <cstring>
#include <fstream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icalcomponent.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icaltime.h>

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    // Prepare a dummy file if needed
    std::ofstream dummyFile("./dummy_file", std::ios::binary);
    dummyFile.write(reinterpret_cast<const char*>(Data), Size);
    dummyFile.close();

    // Initialize components
    icalcomponent *vtodo = icalcomponent_new(ICAL_VTODO_COMPONENT);
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vlocation = icalcomponent_new_vlocation();
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();

    // Create a dummy icaltimetype
    struct icaltimetype due_time;
    due_time.year = static_cast<int>(Data[0]); // simplistic conversion for fuzzing
    due_time.zone = nullptr;

    // Fuzz icalcomponent_set_due
    icalcomponent_set_due(vtodo, due_time);

    // Fuzz icalcomponent_merge_component
    icalcomponent_merge_component(vcalendar1, vcalendar2);

    // Fuzz icalcomponent_get_dtstart
    struct icaltimetype dtstart_time = icalcomponent_get_dtstart(vcalendar1);

    // Fuzz icalcomponent_set_parent
    icalcomponent_set_parent(vlocation, vcalendar1);

    // Clean up
    icalcomponent_free(vtodo);
    icalcomponent_free(vcalendar1);
    // vcalendar2 is already merged into vcalendar1 and should not be freed
    icalcomponent_free(vlocation);
    icalcomponent_free(vtimezone);

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

        LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    