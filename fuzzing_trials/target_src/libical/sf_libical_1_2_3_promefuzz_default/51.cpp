// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_get_span at icalcomponent.c:713:15 in icalcomponent.h
// icalcomponent_new_vlocation at icalcomponent.c:2189:16 in icalcomponent.h
// icalcomponent_foreach_recurrence at icalcomponent.c:970:6 in icalcomponent.h
// icalcomponent_get_first_real_component at icalcomponent.c:690:16 in icalcomponent.h
// icalcomponent_new_participant at icalcomponent.c:2184:16 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
#include <iostream>
#include <fstream>

static void dummy_callback(const icalcomponent *comp, const struct icaltime_span *span, void *data) {
    // Dummy callback function for icalcomponent_foreach_recurrence
}

extern "C" int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0; // Not enough data to proceed
    }

    // Initialize components
    icalcomponent *vevent = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    // Use some parts of the input data to set up time types
    struct icaltimetype start = {0};
    struct icaltimetype end = {0};
    start.year = Data[0];
    end.year = Data[1];

    // Test icalcomponent_foreach_recurrence
    icalcomponent_foreach_recurrence(vevent, start, end, dummy_callback, nullptr);

    // Test icalcomponent_new_participant
    icalcomponent *participant = icalcomponent_new_participant();
    if (participant) {
        icalcomponent_free(participant);
    }

    // Test icalcomponent_get_span
    struct icaltime_span span = icalcomponent_get_span(vevent);

    // Test icalcomponent_merge_component
    icalcomponent_merge_component(vcalendar1, vcalendar2);
    vcalendar2 = nullptr; // Avoid accidental reuse

    // Test icalcomponent_get_first_real_component
    icalcomponent *first_real = icalcomponent_get_first_real_component(vcalendar1);

    // Test icalcomponent_new_vlocation
    icalcomponent *vlocation = icalcomponent_new_vlocation();
    if (vlocation) {
        icalcomponent_free(vlocation);
    }

    // Cleanup
    if (vevent) {
        icalcomponent_free(vevent);
    }
    if (vcalendar1) {
        icalcomponent_free(vcalendar1);
    }
    if (first_real) {
        // Assuming first_real is not separately allocated and managed by vcalendar1
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

        LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    