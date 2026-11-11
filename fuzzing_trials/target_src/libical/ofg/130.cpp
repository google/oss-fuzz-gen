#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent from the input data
    icalcomponent *component = nullptr;

    // Ensure the data size is sufficient to create a valid component string
    if (size > 0) {
        // Create a temporary buffer to store the component string
        char *comp_str = (char *)malloc(size + 1);
        if (comp_str == nullptr) {
            return 0;
        }

        // Copy the data into the buffer and null-terminate it
        memcpy(comp_str, data, size);
        comp_str[size] = '\0';

        // Parse the component string into an icalcomponent
        component = icalparser_parse_string(comp_str);

        // Free the temporary buffer
        free(comp_str);
    }

    // If a valid component was created, call the function-under-test
    if (component != nullptr) {
        icalproperty *property = icalcomponent_get_current_property(component);

        // Perform any additional operations or checks on the property if needed

        // Free the component after use
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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
