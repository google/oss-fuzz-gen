#include <cstring> // Include for strlen
#include <cstdint> // Include for uint8_t

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_168(const uint8_t *data, size_t size) {
    // Call the function-under-test
    icalcomponent *component = icalcomponent_new_vcalendar();

    // Perform some operations with the component to ensure it is used
    if (component != NULL) {
        // Convert the component to a string
        char *component_str = icalcomponent_as_ical_string(component);

        // Check if the conversion was successful
        if (component_str != NULL) {
            // Do something with the string, e.g., print its length
            size_t str_length = strlen(component_str);

            // Free the string after use
            icalmemory_free_buffer(component_str);
        }

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

    LLVMFuzzerTestOneInput_168(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
