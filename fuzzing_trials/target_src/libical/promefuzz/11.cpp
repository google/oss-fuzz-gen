// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_count_errors at icalcomponent.c:1166:5 in icalcomponent.h
// icalcomponent_count_properties at icalcomponent.c:490:5 in icalcomponent.h
// icalcomponent_convert_errors at icalcomponent.c:1211:6 in icalcomponent.h
// icalcomponent_new_vpoll at icalcomponent.c:2159:16 in icalcomponent.h
// icalcomponent_new_vfreebusy at icalcomponent.c:2114:16 in icalcomponent.h
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
#include <stdlib.h>
#include <string.h>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Test icalcomponent_new_vpoll
    icalcomponent *vpoll = icalcomponent_new_vpoll();
    if (vpoll) {
        // Test icalcomponent_convert_errors
        icalcomponent_convert_errors(vpoll);

        // Test icalcomponent_count_properties
        int property_count = icalcomponent_count_properties(vpoll, ICAL_ANY_PROPERTY);

        // Test icalcomponent_count_errors
        int error_count = icalcomponent_count_errors(vpoll);

        // Free the component
        icalcomponent_free(vpoll);
    }

    // Test icalcomponent_new_vfreebusy
    icalcomponent *vfreebusy = icalcomponent_new_vfreebusy();
    if (vfreebusy) {
        // Test icalcomponent_convert_errors
        icalcomponent_convert_errors(vfreebusy);

        // Test icalcomponent_count_properties
        int property_count = icalcomponent_count_properties(vfreebusy, ICAL_ANY_PROPERTY);

        // Test icalcomponent_count_errors
        int error_count = icalcomponent_count_errors(vfreebusy);

        // Free the component
        icalcomponent_free(vfreebusy);
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

        LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    