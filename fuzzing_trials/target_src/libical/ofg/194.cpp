#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h> // Include for malloc and free
#include <string.h> // Include for memcpy

extern "C" {
    // Wrap C library headers and functions to ensure correct linkage
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    // Initialize a string buffer with the input data
    char *inputData = (char *)malloc(size + 1);
    if (!inputData) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(inputData, data, size);
    inputData[size] = '\0'; // Null-terminate the string

    // Create a new icalcomponent from the input data
    icalcomponent *component = icalparser_parse_string(inputData);

    // Free the input data buffer
    free(inputData);

    if (component != NULL) {
        // Initialize an icalcompiter
        icalcompiter iter = icalcomponent_begin_component(component, ICAL_ANY_COMPONENT);

        // Call the function-under-test
        icalcomponent *priorComponent = icalcompiter_prior(&iter);

        // Clean up
        if (priorComponent) {
            icalcomponent_free(priorComponent);
        }
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

    LLVMFuzzerTestOneInput_194(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
