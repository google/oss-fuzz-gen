#include <libical/ical.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Initialize the icalcomponent structure
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);

    // Ensure the data is not empty before using it
    if (size > 0) {
        // Create a temporary buffer to store the input data as a string
        char *input_data = (char *)malloc(size + 1);
        if (input_data != NULL) {
            memcpy(input_data, data, size);
            input_data[size] = '\0'; // Null-terminate the string

            // Set the description property of the component using the input data
            icalcomponent_set_description(component, input_data);

            // Free the allocated memory for the input data
            free(input_data);
        }
    }

    // Call the function-under-test
    const char *description = icalcomponent_get_description(component);

    // Perform any additional checks or operations with the description if needed
    // For example, you can print it or check its length

    // Clean up the icalcomponent
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
