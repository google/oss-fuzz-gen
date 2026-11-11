// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_merge_component at icalcomponent.c:2203:6 in icalcomponent.h
// icalcomponent_get_first_component at icalcomponent.c:654:16 in icalcomponent.h
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
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

static void fuzz_icalcomponent_set_description(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        char *description = new char[Size + 1];
        memcpy(description, Data, Size);
        description[Size] = '\0';
        icalcomponent_set_description(comp, description);
        delete[] description;
    }
}

static void fuzz_icalcomponent_set_recurrenceid(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    if (Size >= sizeof(int)) {
        icaltimetype recurrenceid;
        memcpy(&recurrenceid.year, Data, sizeof(int));
        recurrenceid.zone = nullptr; // Simplified for fuzzing
        icalcomponent_set_recurrenceid(comp, recurrenceid);
    }
}

static void fuzz_icalcomponent_get_first_component(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        icalcomponent_kind kind = static_cast<icalcomponent_kind>(Data[0] % ICAL_NUM_COMPONENT_TYPES);
        icalcomponent_get_first_component(comp, kind);
    }
}

static void fuzz_icalcomponent_merge_component(icalcomponent *comp, const uint8_t *Data, size_t Size) {
    icalcomponent *comp_to_merge = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);
    icalcomponent_merge_component(comp, comp_to_merge);
    // comp_to_merge no longer exists after merge, no need to free
}

static void fuzz_icalcomponent_get_current_component(icalcomponent *comp) {
    icalcomponent_get_current_component(comp);
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    icalcomponent *comp = icalcomponent_new(ICAL_VCALENDAR_COMPONENT);

    fuzz_icalcomponent_set_description(comp, Data, Size);
    fuzz_icalcomponent_set_recurrenceid(comp, Data, Size);
    fuzz_icalcomponent_get_first_component(comp, Data, Size);
    fuzz_icalcomponent_merge_component(comp, Data, Size);
    fuzz_icalcomponent_get_current_component(comp);

    icalcomponent_free(comp);
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

        LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    