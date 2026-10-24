#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy

extern "C" {
    #include "libical/ical.h" // Assuming the correct path for ical.h
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent object
    icalcomponent *component = icalcomponent_new(ICAL_NO_COMPONENT);

    // Ensure the component is not NULL
    if (component == NULL) {
        return 0;
    }

    // Create a temporary buffer to store the data as a string
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        icalcomponent_free(component);
        return 0;
    }

    // Copy the data into the buffer and null-terminate it
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // Set the comment property of the component using the buffer
    icalcomponent_set_comment(component, buffer);

    // Call the function-under-test
    const char *comment = icalcomponent_get_comment(component);

    // Free the allocated memory
    free(buffer);
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
