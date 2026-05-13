#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy

extern "C" {
    #include <libical/ical.h>  // Assuming the correct path for libical headers
}

extern "C" int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Create a temporary buffer to hold the input data
    char *temp_data = (char *)malloc(size + 1);
    if (temp_data == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy the input data to the temporary buffer and null-terminate it
    memcpy(temp_data, data, size);
    temp_data[size] = '\0';

    // Parse the input data into an icalcomponent
    icalcomponent *comp = icalparser_parse_string(temp_data);

    // Ensure the component is not NULL before passing it to the function
    if (comp != NULL) {
        // Call the function-under-test
        icalcomponent_strip_errors(comp);

        // Clean up the component
        icalcomponent_free(comp);
    }

    // Free the temporary buffer
    free(temp_data);

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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
