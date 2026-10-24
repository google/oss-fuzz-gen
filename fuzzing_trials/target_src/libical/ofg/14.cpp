#include <cstdint>  // For uint8_t
#include <cstddef>  // For size_t
#include <cstdlib>  // For malloc, free
#include <cstring>  // For memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Convert the input data to a string, assuming it's null-terminated
    char *inputData = (char *)malloc(size + 1);
    if (inputData == NULL) {
        return 0;  // Exit if memory allocation fails
    }
    memcpy(inputData, data, size);
    inputData[size] = '\0';

    // Create an icalcomponent from the input data
    icalcomponent *component = icalparser_parse_string(inputData);

    // Check if the component was created successfully
    if (component != NULL) {
        // Perform additional operations on the component if needed
        // For example, you could serialize it or check its properties

        // Free the component to avoid memory leaks
        icalcomponent_free(component);
    }

    // Free the allocated memory for inputData
    free(inputData);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
