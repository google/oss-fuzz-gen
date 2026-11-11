#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <libdwarf.h>

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    if (size < sizeof(Dwarf_Signed) + sizeof(int) + sizeof(int)) {
        return 0;
    }

    Dwarf_Signed signed_value;
    int leb128_length;
    char *buffer;
    int buffer_size;

    // Extract Dwarf_Signed value from the input data
    signed_value = *(Dwarf_Signed *)data;

    // Extract buffer size from input data, ensure it's positive and reasonable
    buffer_size = *(int *)(data + sizeof(Dwarf_Signed));
    buffer_size = (buffer_size < 1) ? 1 : (buffer_size > 1024 ? 1024 : buffer_size);

    // Allocate buffer
    buffer = (char *)malloc(buffer_size);
    if (buffer == NULL) {
        return 0;
    }

    // Call the function-under-test
    dwarf_encode_signed_leb128(signed_value, &leb128_length, buffer, buffer_size);

    // Clean up
    free(buffer);

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

    LLVMFuzzerTestOneInput_38(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
