#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    // Initialize the icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_NO_COMPONENT);

    // Ensure the data is not empty
    if (size > 0) {
        // Create a temporary buffer to hold the data for the icalproperty
        char *temp_data = (char *)malloc(size + 1);
        if (temp_data == nullptr) {
            icalcomponent_free(component);
            return 0;
        }

        // Copy the data into the temporary buffer and null-terminate it
        memcpy(temp_data, data, size);
        temp_data[size] = '\0';

        // Create a new icalproperty with the data
        icalproperty *property = icalproperty_new_from_string(temp_data);

        // If the property is successfully created, add it to the component
        if (property != nullptr) {
            icalcomponent_add_property(component, property);
        }

        // Free the temporary buffer
        free(temp_data);
    }

    // Call the function-under-test
    const char *x_name = icalcomponent_get_x_name(component);

    // Clean up
    icalcomponent_free(component);

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

    LLVMFuzzerTestOneInput_159(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
