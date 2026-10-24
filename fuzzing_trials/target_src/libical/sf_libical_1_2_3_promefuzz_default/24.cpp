// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_set_method at icalcomponent.c:1561:6 in icalcomponent.h
// icalcomponent_as_ical_string_r at icalcomponent.c:245:7 in icalcomponent.h
// icalcomponent_get_x_name at icalcomponent.c:357:13 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
// icalcomponent_get_status at icalcomponent.c:2066:26 in icalcomponent.h
extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"
}

#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare the environment
    icalcomponent *comp1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *comp2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (!comp1 || !comp2) {
        if (comp1) icalcomponent_free(comp1);
        if (comp2) icalcomponent_free(comp2);
        return 0;
    }

    // Ensure the input string is null-terminated
    char *description = new char[Size + 1];
    memcpy(description, Data, Size);
    description[Size] = '\0';

    // Fuzz icalcomponent_set_description
    icalcomponent_set_description(comp1, description);

    // Fuzz icalcomponent_get_x_name
    const char *x_name = icalcomponent_get_x_name(comp1);

    // Fuzz icalcomponent_merge_component
    icalcomponent_merge_component(comp1, comp2);
    comp2 = nullptr; // comp2 is no longer valid after merge

    // Fuzz icalcomponent_get_status
    icalproperty_status status = icalcomponent_get_status(comp1);

    // Fuzz icalcomponent_as_ical_string_r
    char *ical_string = icalcomponent_as_ical_string_r(comp1);
    if (ical_string) {
        free(ical_string);
    }

    // Fuzz icalcomponent_set_method
    icalcomponent_set_method(comp1, static_cast<icalproperty_method>(Data[0] % (ICAL_METHOD_NONE + 1)));

    // Cleanup
    icalcomponent_free(comp1);
    delete[] description;

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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    