#include <stdint.h>
#include <string.h> // Include string.h for memcpy
#include <janet.h>

int LLVMFuzzerTestOneInput_356(const uint8_t *data, size_t size) {
    Janet janet_value;
    
    // Initialize the Janet virtual machine
    janet_init();

    // Ensure the size is sufficient to create a valid Janet value
    if (size >= sizeof(Janet)) {
        // Copy the data into a Janet value
        memcpy(&janet_value, data, sizeof(Janet));
        
        // Call the janet_hash function with the Janet value
        int32_t hash_value = janet_hash(janet_value);

        // Use the hash_value to avoid compiler optimizations
        (void)hash_value;
    }

    // Clean up the Janet virtual machine
    janet_deinit();

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

    LLVMFuzzerTestOneInput_356(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
