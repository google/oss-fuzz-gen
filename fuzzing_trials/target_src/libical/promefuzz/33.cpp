// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_get_component_name_r at icalcomponent.c:395:7 in icalcomponent.h
// icalcomponent_new_x at icalcomponent.c:169:16 in icalcomponent.h
// icalcomponent_set_summary at icalcomponent.c:1798:6 in icalcomponent.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Ensure null-termination for string inputs
    char *x_name = static_cast<char *>(malloc(Size + 1));
    if (!x_name) {
        return 0;
    }
    memcpy(x_name, Data, Size);
    x_name[Size] = '\0';

    // Create a new X-NAME component
    icalcomponent *comp_x = icalcomponent_new_x(x_name);
    if (comp_x) {
        // Test setting and getting IANA name
        icalcomponent_set_x_name(comp_x, x_name);
        const char *iana_name = icalcomponent_get_x_name(comp_x);

        // Test setting summary
        icalcomponent_set_summary(comp_x, x_name);

        // Test getting component name
        char *component_name = icalcomponent_get_component_name_r(comp_x);
        if (component_name) {
            free(component_name);
        }

        // Clean up
        icalcomponent_free(comp_x);
    }

    // Create a new IANA component
    icalcomponent *comp_iana = icalcomponent_new_x(x_name); // Replace with icalcomponent_new_x
    if (comp_iana) {
        // Test setting and getting IANA name
        icalcomponent_set_x_name(comp_iana, x_name);
        const char *iana_name = icalcomponent_get_x_name(comp_iana);

        // Test setting summary
        icalcomponent_set_summary(comp_iana, x_name);

        // Test getting component name
        char *component_name = icalcomponent_get_component_name_r(comp_iana);
        if (component_name) {
            free(component_name);
        }

        // Clean up
        icalcomponent_free(comp_iana);
    }

    free(x_name);
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

        LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    