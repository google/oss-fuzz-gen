#include <cstdint> // Include for uint8_t
#include <cstddef> // Include for size_t
#include <cstring> // Include for strlen

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated to avoid buffer overflow in icalcomponent_new_from_string
    char *null_terminated_data = (char*)malloc(size + 1);
    if (null_terminated_data == NULL) {
        return 0; // If memory allocation fails, return immediately
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0'; // Null-terminate the string

    // Initialize an icalcomponent from the input data
    icalcomponent *component = icalcomponent_new_from_string(null_terminated_data);

    // Free the allocated memory for null-terminated data
    free(null_terminated_data);

    // If the component is successfully created, call the function-under-test
    if (component != NULL) {
        char *ical_string = icalcomponent_as_ical_string(component);
        
        // Free the string returned by icalcomponent_as_ical_string
        icalmemory_free_buffer(ical_string);
        
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
