#include <sys/stat.h>
#include "libical/ical.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a null-terminated string for icalcomponent
    if (size < 1) {
        return 0;
    }

    // Allocate memory for a null-terminated string
    char *input_data = (char *)malloc(size + 1);
    if (input_data == NULL) {
        return 0;
    }

    // Copy the input data and null-terminate it
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Create a new icalcomponent from the input data
    icalcomponent *component = icalcomponent_new_from_string(input_data);

    // Free the allocated memory for the input data
    free(input_data);

    // If the component creation failed, exit
    if (component == NULL) {
        return 0;
    }

    // Call the function-under-test
    struct icaltimetype due_time = icalcomponent_get_due(component);

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
