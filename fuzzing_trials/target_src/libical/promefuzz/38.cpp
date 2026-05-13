// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_new_x at icalcomponent.c:169:16 in icalcomponent.h
// icalcomponent_get_component_name_r at icalcomponent.c:395:7 in icalcomponent.h
// icalcomponent_set_relcalid at icalcomponent.c:2627:6 in icalcomponent.h
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
#include <cstdlib>
#include <iostream>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static icalcomponent* create_component_from_data(const uint8_t* Data, size_t Size) {
    // Ensure null-termination for strings
    char* x_name = static_cast<char*>(malloc(Size + 1));
    if (!x_name) return nullptr;
    memcpy(x_name, Data, Size);
    x_name[Size] = '\0';

    icalcomponent* comp = icalcomponent_new_x(x_name);
    free(x_name);
    return comp;
}

extern "C" int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a component using the input data
    icalcomponent* comp = create_component_from_data(Data, Size);
    if (!comp) return 0;

    // Test icalcomponent_set_x_name
    char* iana_name = static_cast<char*>(malloc(Size + 1));
    if (iana_name) {
        memcpy(iana_name, Data, Size);
        iana_name[Size] = '\0';
        icalcomponent_set_x_name(comp, iana_name);
        free(iana_name);
    }

    // Test icalcomponent_get_x_name
    const char* retrieved_iana_name = icalcomponent_get_x_name(comp);
    if (retrieved_iana_name) {
        std::cout << "Retrieved IANA Name: " << retrieved_iana_name << std::endl;
    }

    // Test icalcomponent_new_x
    icalcomponent* iana_comp = icalcomponent_new_x(retrieved_iana_name ? retrieved_iana_name : "DEFAULT");
    if (iana_comp) {
        icalcomponent_free(iana_comp);
    }

    // Test icalcomponent_set_relcalid
    char* relcalid = static_cast<char*>(malloc(Size + 1));
    if (relcalid) {
        memcpy(relcalid, Data, Size);
        relcalid[Size] = '\0';
        icalcomponent_set_relcalid(comp, relcalid);
        free(relcalid);
    }

    // Test icalcomponent_get_component_name_r
    char* component_name = icalcomponent_get_component_name_r(comp);
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

        LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    