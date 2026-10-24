// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_x at icalcomponent.c:169:16 in icalcomponent.h
// icalcomponent_get_component_name_r at icalcomponent.c:395:7 in icalcomponent.h
// icalcomponent_get_x_name at icalcomponent.c:357:13 in icalcomponent.h
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
#include <cstring>
#include <cstdlib>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_component(const uint8_t *Data, size_t Size) {
    if (Size == 0) return nullptr;

    // Ensure null-terminated string for component creation
    char *component_name = static_cast<char*>(malloc(Size + 1));
    if (!component_name) return nullptr;
    memcpy(component_name, Data, Size);
    component_name[Size] = '\0';

    icalcomponent *comp = icalcomponent_new_x(component_name);
    free(component_name);
    return comp;
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create an icalcomponent
    icalcomponent *comp = create_component(Data, Size);
    if (!comp) return 0;

    // Set IANA name
    char *iana_name = static_cast<char*>(malloc(Size + 1));
    if (iana_name) {
        memcpy(iana_name, Data, Size);
        iana_name[Size] = '\0';
        icalcomponent_set_x_name(comp, iana_name);
        free(iana_name);
    }

    // Get X-NAME
    const char *x_name = icalcomponent_get_x_name(comp);
    if (x_name) {
        std::cout << "X-NAME: " << x_name << std::endl;
    }

    // Get IANA name
    const char *retrieved_iana_name = icalcomponent_get_x_name(comp);
    if (retrieved_iana_name) {
        std::cout << "IANA Name: " << retrieved_iana_name << std::endl;
    }

    // Get component name
    char *component_name = icalcomponent_get_component_name_r(comp);
    if (component_name) {
        std::cout << "Component Name: " << component_name << std::endl;
        free(component_name);
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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    