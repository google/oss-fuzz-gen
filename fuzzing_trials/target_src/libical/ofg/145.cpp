#include <cstdint>
#include <cstddef>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Call the function-under-test
    icalcomponent *component = icalcomponent_new_vagenda();

    // Perform any necessary operations on the component if needed
    // For example, serialize it to a string and print (for debugging purposes)
    if (component != NULL) {
        char *str = icalcomponent_as_ical_string(component);
        if (str != NULL) {
            // For fuzzing, we generally don't print, but we could log or use the string
            // printf("%s\n", str); // Uncomment for debugging purposes
        }
        // Free the string if it was allocated
        icalmemory_free_buffer(str);

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

    LLVMFuzzerTestOneInput_145(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
