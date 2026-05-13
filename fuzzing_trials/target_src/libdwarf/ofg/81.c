#include <stddef.h>
#include <stdint.h>
#include <dwarf.h>
#include <libdwarf.h> // Include the necessary header for libdwarf functions

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    unsigned int tag;
    const char *tag_name;

    // Ensure that we have enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Copy the first bytes of data into the tag variable
    tag = *(const unsigned int *)data;

    // Call the function-under-test
    int result = dwarf_get_TAG_name(tag, &tag_name);

    // Use the result and tag_name in some way to avoid unused variable warnings
    if (result == DW_DLV_OK && tag_name != NULL) {
        // Do something with tag_name, e.g., print it or log it
        // This is just a placeholder, in a real fuzzing environment you might
        // want to verify the correctness of the output or check for crashes.
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_81(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
