// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_x at icalcomponent.c:169:16 in icalcomponent.h
// icalcomponent_get_component_name_r at icalcomponent.c:395:7 in icalcomponent.h
// icalcomponent_set_x_name at icalcomponent.c:344:6 in icalcomponent.h
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
#include <cstring>
#include <fstream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_component_with_name(const uint8_t* Data, size_t Size) {
    if (Size == 0) return nullptr;

    // Ensure null-termination
    char* name = new char[Size + 1];
    memcpy(name, Data, Size);
    name[Size] = '\0';

    icalcomponent* comp = icalcomponent_new_x(name);
    delete[] name;
    return comp;
}

static void set_iana_name(icalcomponent* comp, const uint8_t* Data, size_t Size) {
    if (Size == 0 || comp == nullptr) return;

    char* name = new char[Size + 1];
    memcpy(name, Data, Size);
    name[Size] = '\0';

    // Assuming icalcomponent_set_iana_name is available in the actual library
    icalcomponent_set_x_name(comp, name); // Using set_x_name as a placeholder
    delete[] name;
}

static void set_x_name(icalcomponent* comp, const uint8_t* Data, size_t Size) {
    if (Size == 0 || comp == nullptr) return;

    char* name = new char[Size + 1];
    memcpy(name, Data, Size);
    name[Size] = '\0';

    icalcomponent_set_x_name(comp, name);
    delete[] name;
}

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a component with an X-NAME
    icalcomponent* comp = create_component_with_name(Data, Size);
    if (!comp) return 0;

    // Set IANA name
    set_iana_name(comp, Data, Size);

    // Get IANA name
    const char* iana_name = icalcomponent_get_x_name(comp); // Using get_x_name as a placeholder
    if (iana_name) {
        // Do something with iana_name, e.g., logging or further processing
    }

    // Set X-NAME
    set_x_name(comp, Data, Size);

    // Get component name
    char* comp_name = icalcomponent_get_component_name_r(comp);
    if (comp_name) {
        // Do something with comp_name, e.g., logging or further processing
        free(comp_name); // Remember to free the allocated name
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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    