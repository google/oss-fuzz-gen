#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Call the function-under-test
    icalcomponent *component = icalcomponent_new_vresource();

    // Check if the component is created successfully
    if (component != NULL) {
        // Perform operations on the component if needed
        // For example, convert it to a string and print (or any other operation)
        char *component_str = icalcomponent_as_ical_string(component);
        
        // If you want to print or use the string representation
        if (component_str != NULL) {
            // Do something with component_str, e.g., log or analyze
            // For fuzzing, we typically do not print, but you can use this for debugging
            // printf("%s\n", component_str);
        }

        // Free the string if allocated
        // Note: icalcomponent_as_ical_string does not require manual free, it's just an example

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
