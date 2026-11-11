#include <stdint.h>
#include <stddef.h>
#include <libical/ical.h>
#include <cstring> // Include the header for memcpy

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent from the input data
    icalcomponent *component = nullptr;
    
    // Ensure size is greater than zero to avoid passing NULL data
    if (size > 0) {
        // Create a temporary buffer to hold the data as a string
        char *buffer = new char[size + 1];
        memcpy(buffer, data, size);
        buffer[size] = '\0'; // Null-terminate the string

        // Parse the buffer into an icalcomponent
        component = icalparser_parse_string(buffer);

        // Clean up the buffer
        delete[] buffer;
    }

    // If component is successfully created, call the function
    if (component != nullptr) {
        // Call the function-under-test
        int error_count = icalcomponent_count_errors(component);
        
        // Free the icalcomponent
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

    LLVMFuzzerTestOneInput_109(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
