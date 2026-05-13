#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <libical/ical.h> // Correct include path for the ical library

    // Function signature from the project
    void icalcomponent_set_x_name(icalcomponent *, const char *);
}

extern "C" int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Initialize icalcomponent
    icalcomponent *component = icalcomponent_new(ICAL_VEVENT_COMPONENT);
    if (component == NULL) {
        return 0; // Exit if initialization fails
    }

    // Ensure the data size is reasonable for a string
    if (size == 0 || size > 1000) { // Arbitrary limit to avoid excessive allocation
        icalcomponent_free(component);
        return 0;
    }

    // Convert data to a null-terminated string
    char *x_name = (char *)malloc(size + 1);
    if (x_name == NULL) {
        icalcomponent_free(component);
        return 0; // Exit if memory allocation fails
    }
    memcpy(x_name, data, size);
    x_name[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    icalcomponent_set_x_name(component, x_name);

    // Clean up
    free(x_name);
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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
