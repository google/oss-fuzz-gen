#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_190(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for creating a valid string
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *inputData = (char *)malloc(size + 1);
    if (inputData == nullptr) {
        return 0;
    }
    memcpy(inputData, data, size);
    inputData[size] = '\0';

    // Create an icalcomponent from the string
    icalcomponent *component = icalparser_parse_string(inputData);
    free(inputData);

    if (component != nullptr) {
        // Call the function-under-test
        const char *summary = icalcomponent_get_summary(component);

        // Optionally, you can perform some operations with the summary
        // For example, check its length or content
        if (summary != nullptr) {
            size_t summaryLength = strlen(summary);
            // Do something with summaryLength if needed
        }

        // Clean up
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

    LLVMFuzzerTestOneInput_190(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
