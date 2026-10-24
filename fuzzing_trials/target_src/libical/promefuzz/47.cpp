// This fuzz driver is generated for library libical, aiming to fuzz the following functions:
// icalcomponent_kind_to_string at icalcomponent.c:1354:13 in icalcomponent.h
// icalcomponent_string_to_kind at icalcomponent.c:1367:20 in icalcomponent.h
// icalcomponent_get_component_name at icalcomponent.c:386:13 in icalcomponent.h
// icalcomponent_clone at icalcomponent.c:137:16 in icalcomponent.h
// icalcomponent_new_from_string at icalcomponent.c:132:16 in icalcomponent.h
// icalcomponent_isa at icalcomponent.c:324:20 in icalcomponent.h
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
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include "ical.h"
#include "ical.h"
#include "ical.h"
#include "icalcomponent.h"

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    std::ofstream file("./dummy_file", std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char *>(Data), Size);
        file.close();
    }
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Ensure the input string is null-terminated
    std::vector<char> inputString(Data, Data + Size);
    inputString.push_back('\0');

    // Fuzz icalcomponent_new_from_string
    icalcomponent *component = icalcomponent_new_from_string(inputString.data());
    if (component) {
        // Fuzz icalcomponent_clone
        icalcomponent *clone = icalcomponent_clone(component);
        if (clone) {
            icalcomponent_free(clone);
        }

        // Fuzz icalcomponent_isa
        icalcomponent_kind kind = icalcomponent_isa(component);

        // Fuzz icalcomponent_kind_to_string
        const char *kindStr = icalcomponent_kind_to_string(kind);
        if (kindStr) {
            // Use the kind string
        }

        // Fuzz icalcomponent_get_component_name
        const char *componentName = icalcomponent_get_component_name(component);
        if (componentName) {
            // Use the component name
        }

        icalcomponent_free(component);
    }

    // Fuzz icalcomponent_string_to_kind
    icalcomponent_kind kindFromString = icalcomponent_string_to_kind(inputString.data());
    if (kindFromString != ICAL_NO_COMPONENT) {
        // Use the kind from string
    }

    // Write input data to a dummy file if needed
    writeDummyFile(Data, Size);

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

        LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    