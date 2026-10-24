#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <libical/ical.h>
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated before passing it as a string
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the string and ensure it is null-terminated
    char *inputString = (char *)malloc(size + 1);
    if (inputString == NULL) {
        return 0;
    }

    // Copy the data into the inputString and null-terminate it
    memcpy(inputString, data, size);
    inputString[size] = '\0';

    // Call the function-under-test
    icalcomponent_kind kind = icalcomponent_string_to_kind(inputString);

    // Free the allocated memory
    free(inputString);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
