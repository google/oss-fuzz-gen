#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Include for memcpy

extern "C" {
    #include "libical/ical.h"
}

extern "C" int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent from the input data
    icalcomponent *component = nullptr;
    if (size > 0) {
        // Ensure the data is null-terminated for string-based functions
        char *ical_data = static_cast<char*>(malloc(size + 1));
        if (ical_data == nullptr) {
            return 0; // Exit if memory allocation fails
        }
        memcpy(ical_data, data, size);
        ical_data[size] = '\0';

        // Parse the data into an icalcomponent
        component = icalcomponent_new_from_string(ical_data);
        free(ical_data);
    }

    if (component != nullptr) {
        // Call the function-under-test
        icalcomponent *first_real_component = icalcomponent_get_first_real_component(component);

        // Clean up the created icalcomponent
        icalcomponent_free(component);
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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
