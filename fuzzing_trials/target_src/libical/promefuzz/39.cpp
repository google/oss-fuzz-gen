// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_end_component at icalcomponent.c:1424:14 in icalcomponent.h
// icalcompiter_prior at icalcomponent.c:1465:16 in icalcomponent.h
// icalcompiter_deref at icalcomponent.c:1484:16 in icalcomponent.h
// icalcomponent_begin_component at icalcomponent.c:1401:14 in icalcomponent.h
// icalcomponent_get_current_component at icalcomponent.c:643:16 in icalcomponent.h
// icalcomponent_check_restrictions at icalcomponent.c:1160:6 in icalcomponent.h
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
#include <vector>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <libical/icalcomponent.h>

static icalcomponent* create_dummy_component() {
    icalcomponent *component = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *subcomponent = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    icalcomponent_add_component(component, subcomponent);
    return component;
}

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    icalcomponent *component = create_dummy_component();
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);

    // Fuzz icalcomponent_end_component
    icalcompiter end_iter = icalcomponent_end_component(component, kind);
    icalcomponent *end_component = icalcompiter_deref(&end_iter);

    // Fuzz icalcomponent_begin_component
    icalcompiter begin_iter = icalcomponent_begin_component(component, kind);
    icalcomponent *begin_component = icalcompiter_deref(&begin_iter);

    // Fuzz icalcomponent_get_current_component
    icalcomponent *current_component = icalcomponent_get_current_component(component);

    // Fuzz icalcomponent_check_restrictions
    bool has_restrictions = icalcomponent_check_restrictions(component);

    // Fuzz icalcompiter_prior
    icalcomponent *prior_component = icalcompiter_prior(&begin_iter);

    // Cleanup
    icalcomponent_free(component);

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

        LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    