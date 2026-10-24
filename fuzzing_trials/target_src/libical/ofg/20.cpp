#include <cstdint>
#include <cstddef>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Call the function-under-test
    icalcomponent *component = icalcomponent_new_vpoll();
    
    // Perform operations on the component if necessary
    // For fuzzing purposes, we can convert it to a string and then free it
    if (component != NULL) {
        char *component_str = icalcomponent_as_ical_string(component);
        if (component_str != NULL) {
            // Print or log the component string if needed
            // printf("%s\n", component_str);

            // Free the string
            icalmemory_free_buffer(component_str);
        }

        // Free the component
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
