#include <cstdint> // Include standard library for uint8_t
#include <cstdlib> // Include standard library for size_t

extern "C" {
    #include <libical/ical.h> // Include the libical library within extern "C"
}

extern "C" int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    // Call the function-under-test
    icalcomponent *component = icalcomponent_new_xavailable();

    // Check if the component was created successfully
    if (component != NULL) {
        // Perform operations on the component if needed
        // For the purpose of this fuzzing, we can convert it to a string and free it
        char *component_str = icalcomponent_as_ical_string(component);
        if (component_str != NULL) {
            // Normally, you might want to do something with the string
            // For fuzzing, we just ensure it doesn't crash and then free it
            icalmemory_free_buffer(component_str);
        }

        // Free the component to avoid memory leaks
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

    LLVMFuzzerTestOneInput_184(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
