#include <libical/ical.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create a valid string
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *inputStr = (char *)malloc(size + 1);
    if (inputStr == NULL) {
        return 0;
    }
    memcpy(inputStr, data, size);
    inputStr[size] = '\0';

    // Parse the input string into an icalcomponent
    icalcomponent *component = icalparser_parse_string(inputStr);
    free(inputStr);

    if (component == NULL) {
        return 0;
    }

    // Use the first byte of data to determine the icalcomponent_kind
    icalcomponent_kind kind = static_cast<icalcomponent_kind>(data[0] % ICAL_NO_COMPONENT);

    // Call the function-under-test
    icalcomponent *result = icalcomponent_get_first_component(component, kind);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
