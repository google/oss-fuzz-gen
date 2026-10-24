// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_set_x_name at icalcomponent.c:344:6 in icalcomponent.h
// icalcomponent_get_x_name at icalcomponent.c:357:13 in icalcomponent.h
// icalcomponent_as_ical_string_r at icalcomponent.c:245:7 in icalcomponent.h
// icalcomponent_get_relcalid at icalcomponent.c:2639:13 in icalcomponent.h
// icalcomponent_get_uid at icalcomponent.c:1880:13 in icalcomponent.h
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <cstring>
extern "C" {
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"
}

static icalcomponent* createComponentFromData(const uint8_t* Data, size_t Size) {
    icalcomponent* comp = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (!comp) {
        return nullptr;
    }
    icalcomponent_set_x_name(comp, "X-NAME-FUZZ");
    return comp;
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    icalcomponent* comp = createComponentFromData(Data, Size);
    if (!comp) {
        return 0;
    }

    // Test icalcomponent_get_x_name
    const char* x_name = icalcomponent_get_x_name(comp);
    if (x_name) {
        // Do something with x_name if needed
    }

    // Test icalcomponent_get_uid
    const char* uid = icalcomponent_get_uid(comp);
    if (uid) {
        // Do something with uid if needed
    }

    // Test icalcomponent_get_relcalid
    const char* relcalid = icalcomponent_get_relcalid(comp);
    if (relcalid) {
        // Do something with relcalid if needed
    }

    // Test icalcomponent_as_ical_string_r
    char* ical_string = icalcomponent_as_ical_string_r(comp);
    if (ical_string) {
        // Do something with ical_string if needed
        icalmemory_free_buffer(ical_string);
    }

    // Test icalcomponent_set_x_name with different data
    // Ensure the data is null-terminated before setting it as X-NAME
    char* safe_data = (char*)malloc(Size + 1);
    if (safe_data) {
        memcpy(safe_data, Data, Size);
        safe_data[Size] = '\0';
        icalcomponent_set_x_name(comp, safe_data);
        free(safe_data);
    }

    // Clean up
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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    