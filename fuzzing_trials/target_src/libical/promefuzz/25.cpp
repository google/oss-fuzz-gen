// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_get_component_name_r at icalcomponent.c:395:7 in icalcomponent.h
// icalcomponent_set_summary at icalcomponent.c:1798:6 in icalcomponent.h
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
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include <icalcomponent.h>

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new icalcomponent using icalcomponent_new_x
    icalcomponent *comp = icalcomponent_new_x("X-TEST");
    if (!comp) return 0;

    // Ensure the data is null-terminated
    std::vector<uint8_t> safeData(Data, Data + Size);
    safeData.push_back('\0');

    // Set X name using icalcomponent_set_x_name
    icalcomponent_set_x_name(comp, reinterpret_cast<const char*>(safeData.data()));

    // Get X name using icalcomponent_get_x_name
    const char *x_name = icalcomponent_get_x_name(comp);

    // Set DESCRIPTION using icalcomponent_set_description
    icalcomponent_set_description(comp, reinterpret_cast<const char*>(safeData.data()));

    // Set SUMMARY using icalcomponent_set_summary
    icalcomponent_set_summary(comp, reinterpret_cast<const char*>(safeData.data()));

    // Get component name using icalcomponent_get_component_name_r
    char *component_name = icalcomponent_get_component_name_r(comp);
    if (component_name) {
        free(component_name);
    }

    // Clean up the component
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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    