#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <fstream>
#include "libical/ical.h"
#include "libical/ical.h"
#include "libical/ical.h"
#include "/src/libical/src/libical/icalcomponent.h"

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Create a dummy file if needed
    std::ofstream dummyFile("./dummy_file");
    if (!dummyFile) return 0;
    dummyFile.write(reinterpret_cast<const char*>(Data), Size);
    dummyFile.close();

    // Convert input data to a string
    std::string input(reinterpret_cast<const char*>(Data), Size);

    // Test icalcomponent_new_x
    icalcomponent *compX = icalcomponent_new_x(input.c_str());
    if (compX) {
        // Test icalcomponent_get_x_name
        const char *xName = icalcomponent_get_x_name(compX);
        if (xName) {
            std::cout << "X Name: " << xName << std::endl;
        }

        // Test icalcomponent_get_component_name
        const char *componentName = icalcomponent_get_component_name(compX);
        if (componentName) {
            std::cout << "Component Name: " << componentName << std::endl;
        }

        // Test icalcomponent_set_x_name
        icalcomponent_set_x_name(compX, "test-x-name");
    }

    // Test icalcomponent_new_valarm
    icalcomponent *compValarm = icalcomponent_new_valarm();
    if (compValarm) {
        // Test icalcomponent_get_component_name
        const char *valarmName = icalcomponent_get_component_name(compValarm);
        if (valarmName) {
            std::cout << "Valarm Component Name: " << valarmName << std::endl;
        }
    }

    // Cleanup
    if (compX) {
        icalcomponent_free(compX);
    }
    if (compValarm) {
        icalcomponent_free(compValarm);
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
