// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_get_first_component at icalcomponent.c:654:16 in icalcomponent.h
// icalcomponent_new_vtodo at icalcomponent.c:2099:16 in icalcomponent.h
// icalcomponent_get_current_component at icalcomponent.c:643:16 in icalcomponent.h
// icalcomponent_set_recurrenceid at icalcomponent.c:1903:6 in icalcomponent.h
// icalcomponent_set_description at icalcomponent.c:1949:6 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <stdint.h>
#include <stddef.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icaltimezone.h>
#include <string.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new VTODO component
    icalcomponent *vtodo = icalcomponent_new_vtodo();
    if (!vtodo) return 0;

    // Fuzz icalcomponent_set_description
    if (Size > 1) {
        char *description = (char *)malloc(Size + 1);
        if (description) {
            memcpy(description, Data, Size);
            description[Size] = '\0';
            icalcomponent_set_description(vtodo, description);
            free(description);
        }
    }

    // Fuzz icalcomponent_set_recurrenceid
    if (Size >= sizeof(int)) {
        struct icaltimetype recurrence_id = {0};
        recurrence_id.year = *(int *)Data;
        icalcomponent_set_recurrenceid(vtodo, recurrence_id);
    }

    // Fuzz icalcomponent_get_first_component
    icalcomponent *first_component = icalcomponent_get_first_component(
        vtodo, ICAL_VTODO_COMPONENT);
    (void)first_component; // Suppress unused variable warning

    // Fuzz icalcomponent_merge_component
    icalcomponent *vcalendar1 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *vcalendar2 = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    if (vcalendar1 && vcalendar2) {
        icalcomponent_merge_component(vcalendar1, vcalendar2);
        vcalendar2 = nullptr; // Prevent accidental reuse
    }

    // Fuzz icalcomponent_get_current_component
    icalcomponent *current_component = icalcomponent_get_current_component(vtodo);
    (void)current_component; // Suppress unused variable warning

    // Cleanup
    if (vcalendar1) icalcomponent_free(vcalendar1);
    if (vtodo) icalcomponent_free(vtodo);

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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    