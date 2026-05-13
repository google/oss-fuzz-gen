#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2_plugin.h>
#include <lcms2.h>  // Include the main Little CMS header for cmsDICTentry and related functions

int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    // Initialize a cmsDICTentry object
    cmsDICTentry entry;
    entry.Next = NULL;  // Initialize the Next pointer to NULL
    entry.Name = (const char *)data;  // Use the fuzzing data as the name
    entry.Value = (const char *)data; // Use the fuzzing data as the value
    entry.DisplayName = (const char *)data; // Use the fuzzing data as the display name
    entry.DisplayValue = (const char *)data; // Use the fuzzing data as the display value

    // Call the function-under-test
    const cmsDICTentry *nextEntry = cmsDictNextEntry(&entry);

    // To avoid unused variable warning
    (void)nextEntry;

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

    LLVMFuzzerTestOneInput_187(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
