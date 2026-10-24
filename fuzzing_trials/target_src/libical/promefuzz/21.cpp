// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_count_components at icalcomponent.c:626:5 in icalcomponent.h
// icalcomponent_get_first_component at icalcomponent.c:654:16 in icalcomponent.h
// icalcomponent_get_next_component at icalcomponent.c:670:16 in icalcomponent.h
// icalcomponent_get_first_real_component at icalcomponent.c:690:16 in icalcomponent.h
// icalcomponent_begin_component at icalcomponent.c:1401:14 in icalcomponent.h
// icalcomponent_add_component at icalcomponent.c:552:6 in icalcomponent.h
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
#include <cassert>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static void init_dummy_file(const uint8_t *Data, size_t Size) {
    std::ofstream dummy_file("./dummy_file", std::ios::binary);
    if (dummy_file.is_open()) {
        dummy_file.write(reinterpret_cast<const char*>(Data), Size);
        dummy_file.close();
    }
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(icalcomponent_kind)) {
        return 0;
    }

    icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);
    icalcomponent *parent = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent *child = icalcomponent_new(kind);
    
    if (parent && child) {
        icalcomponent_add_component(parent, child);

        icalcomponent *first_component = icalcomponent_get_first_component(parent, kind);
        icalcomponent *next_component = icalcomponent_get_next_component(parent, kind);
        icalcomponent *first_real_component = icalcomponent_get_first_real_component(parent);
        int component_count = icalcomponent_count_components(parent, kind);

        icalcompiter iter = icalcomponent_begin_component(parent, kind);
        bool is_valid_iter = icalcompiter_is_valid(&iter);

        // Use the results to avoid unused variable warnings
        (void)first_component;
        (void)next_component;
        (void)first_real_component;
        (void)component_count;
        (void)is_valid_iter;
    }

    // Cleanup
    icalcomponent_free(parent);

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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    