#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <janet.h>

// Function-under-test
void janet_cfuns_ext_prefix(JanetTable *table, const char *prefix, const JanetRegExt *regext);

int LLVMFuzzerTestOneInput_336(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to split into meaningful parts
    if (size < 2) return 0;

    // Allocate and initialize a JanetTable
    JanetTable table;
    memset(&table, 0, sizeof(JanetTable));

    // Allocate and initialize a JanetRegExt
    JanetRegExt regext;
    memset(&regext, 0, sizeof(JanetRegExt));

    // Use part of the data as a string for prefix
    size_t prefix_len = size / 2;
    char *prefix = (char *)malloc(prefix_len + 1);
    if (!prefix) return 0; // Check for allocation failure
    memcpy(prefix, data, prefix_len);
    prefix[prefix_len] = '\0'; // Null-terminate the string

    // Call the function-under-test
    janet_cfuns_ext_prefix(&table, prefix, &regext);

    // Clean up
    free(prefix);

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

    LLVMFuzzerTestOneInput_336(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
