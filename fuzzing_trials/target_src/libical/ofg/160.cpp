#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <libical/icalcomponent.h> // Corrected include path for libical

    // Function to be fuzzed
    const char *icalcomponent_get_x_name(const icalcomponent *);
}

extern "C" int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    // Initialize an icalcomponent object
    icalcomponent *component = icalcomponent_new(ICAL_NO_COMPONENT);

    if (component == NULL) {
        return 0; // Exit if component creation failed
    }

    // Call the function under test
    const char *x_name = icalcomponent_get_x_name(component);

    // Optionally, you can do something with x_name here, like printing or logging
    // For fuzzing, we generally don't need to do anything with the output

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

    LLVMFuzzerTestOneInput_160(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
