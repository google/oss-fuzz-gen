// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_free at icalcomponent.c:191:6 in icalcomponent.h
// icalcomponent_new_vcalendar at icalcomponent.c:2089:16 in icalcomponent.h
// icalcomponent_set_parent at icalcomponent.c:1275:6 in icalcomponent.h
// icalcomponent_remove_component at icalcomponent.c:586:6 in icalcomponent.h
// icalcomponent_new_vtimezone at icalcomponent.c:2119:16 in icalcomponent.h
#include <cstdint>
extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create two new VCALENDAR components
    icalcomponent *comp1 = icalcomponent_new_vcalendar();
    icalcomponent *comp2 = icalcomponent_new_vcalendar();

    // Create a new VTIMEZONE component
    icalcomponent *vtimezone = icalcomponent_new_vtimezone();

    // Set comp2 as a parent of vtimezone
    icalcomponent_set_parent(vtimezone, comp2);

    // Merge comp2 into comp1
    icalcomponent_merge_component(comp1, comp2);

    // Remove vtimezone from comp1
    icalcomponent_remove_component(comp1, vtimezone);

    // Free the components
    icalcomponent_free(vtimezone);
    icalcomponent_free(comp1);

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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    