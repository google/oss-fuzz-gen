#include <stdint.h>
#include <stddef.h>
#include <htslib/hts.h>  // Include the header file where hts_crc32 is declared

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    uint32_t crc_init = 0;  // Initialize the CRC value to 0
    uint32_t crc_result;

    // Call the function-under-test with the provided data
    crc_result = hts_crc32(crc_init, data, size);

    // Optionally, you can do something with crc_result, like printing or logging it
    // For the purpose of fuzzing, we are primarily interested in calling the function

    return 0;  // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_148(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
