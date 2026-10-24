#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Include this header for memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    // Initialize libical
    icalcomponent *component = nullptr;
    icalcomponent *real_component = nullptr;

    // Ensure size is non-zero to avoid creating an empty string
    if (size > 0) {
        // Create a string from the input data
        char *ical_string = static_cast<char *>(malloc(size + 1));
        if (ical_string == nullptr) {
            return 0; // Memory allocation failed
        }
        memcpy(ical_string, data, size);
        ical_string[size] = '\0'; // Null-terminate the string

        // Parse the input data into an icalcomponent
        component = icalparser_parse_string(ical_string);
        free(ical_string);

        if (component != nullptr) {
            // Call the function-under-test
            real_component = icalcomponent_get_first_real_component(component);

            // Optionally, perform additional operations on real_component
            // For example, you could print its type or properties
        }

        // Clean up
        if (component != nullptr) {
            icalcomponent_free(component);
        }
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

    LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
