// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
// icalcomponent_new_vcalendar at icalcomponent.c:2089:16 in icalcomponent.h
#include <cstdint>
extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data

    // Prepare components
    icalcomponent *vcalendar1 = icalcomponent_new_vcalendar();
    icalcomponent *vcalendar2 = icalcomponent_new_vcalendar();
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();

    // Add a timezone component to the second vcalendar
    icalcomponent_add_component(vcalendar2, vtimezone);

    // Depending on the input data, decide whether to merge or remove components
    if (Data[0] % 2 == 0) {
        // Merge the second vcalendar into the first
        icalcomponent_merge_component(vcalendar1, vcalendar2);
        // vcalendar2 and its components, including vtimezone, are already freed by icalcomponent_merge_component
        vcalendar2 = nullptr;
        vtimezone = nullptr;
    } else {
        // Remove the timezone component from the second vcalendar
        icalcomponent_remove_component(vcalendar2, vtimezone);
    }

    // Cleanup
    icalcomponent_free(vcalendar1);
    if (vcalendar2) {
        icalcomponent_free(vcalendar2);
    }
    if (vtimezone) {
        icalcomponent_free(vtimezone);
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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    