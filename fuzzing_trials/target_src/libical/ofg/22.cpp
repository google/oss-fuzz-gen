#include <libical/ical.h>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Include the header for memcpy

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for creating a valid string
    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *str = static_cast<char*>(malloc(size + 1));
    if (str == NULL) {
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    // Parse the string to create an icalproperty
    icalproperty *prop = icalproperty_new_from_string(str);

    // Ensure the property is not NULL before passing it to the function-under-test
    if (prop != NULL) {
        // Call the function-under-test
        icalcomponent *parent = icalproperty_get_parent(prop);

        // Clean up
        icalproperty_free(prop);
    }

    free(str);
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
