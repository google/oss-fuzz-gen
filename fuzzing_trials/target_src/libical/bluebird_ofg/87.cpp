#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include the string.h library for strlen function

extern "C" {
    #include "libical/ical.h" // Correctly include the ical header from the libical project
}

extern "C" int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated to prevent buffer overflow in icalcomponent_new_from_string
    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Initialize the icalcomponent from the input data
    icalcomponent *component = icalcomponent_new_from_string(null_terminated_data);

    if (component != NULL) {
        // Call the function-under-test
        const char *relcalid = icalcomponent_get_relcalid(component);

        // Use the relcalid in some way to avoid compiler optimizations
        if (relcalid != NULL) {
            // For fuzzing purposes, we just check the length
            size_t len = strlen(relcalid);
            (void)len; // Suppress unused variable warning
        }

        // Free the icalcomponent
        icalcomponent_free(component);
    }

    // Free the allocated memory
    free(null_terminated_data);

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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
