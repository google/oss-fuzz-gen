#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> // Include for memcpy
#include <htslib/hts.h>

int LLVMFuzzerTestOneInput_272(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize htsFormat
    if (size < sizeof(htsFormat)) {
        return 0;
    }

    // Initialize htsFormat from the input data
    htsFormat format;
    memcpy(&format, data, sizeof(htsFormat));

    // Call the function-under-test
    const char *extension = hts_format_file_extension(&format);

    // Print the result (for debugging purposes)
    if (extension != NULL) {
        printf("File extension: %s\n", extension);
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

    LLVMFuzzerTestOneInput_272(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
