#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    // Create a temporary string buffer to hold the input data
    char *tempData = (char *)malloc(size + 1);
    if (tempData == NULL) {
        return 0; // Memory allocation failed, return early
    }

    // Copy the input data to the temporary buffer and null-terminate it
    memcpy(tempData, data, size);
    tempData[size] = '\0';

    // Parse the input data into an icalcomponent
    icalcomponent *component = icalparser_parse_string(tempData);

    // Free the temporary buffer
    free(tempData);

    if (component != NULL) {
        // Call the function-under-test
        icalcomponent *parent = icalcomponent_get_parent(component);

        // Clean up the parsed icalcomponent
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

    LLVMFuzzerTestOneInput_175(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
