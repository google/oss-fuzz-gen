#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

// Ensure the function is linked correctly with C++ code
extern "C" {
    icalcomponent *icalcomponent_new_from_string(const char *str);
    void icalcomponent_free(icalcomponent *component);
}

// Fuzzing harness for the function-under-test
extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Use the fuzzer input data to create a string
    char *input_data = (char *)malloc(size + 1);
    if (input_data != NULL) {
        memcpy(input_data, data, size);
        input_data[size] = '\0'; // Null-terminate the string

        // Call the function-under-test with the fuzzer input
        icalcomponent *component = icalcomponent_new_from_string(input_data);

        if (component != NULL) {
            // Perform operations on the component if needed

            // Cleanup
            icalcomponent_free(component);
        }

        free(input_data);
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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
