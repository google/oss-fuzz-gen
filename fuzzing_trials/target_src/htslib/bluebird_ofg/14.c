#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "htslib/hts.h"

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize htsFormat
    if (size < sizeof(htsFormat)) {
        return 0;
    }

    // Allocate memory for htsFormat and copy data into it
    htsFormat *format = (htsFormat *)malloc(sizeof(htsFormat));
    if (!format) {
        return 0;
    }
    memcpy(format, data, sizeof(htsFormat));

    // Call the function-under-test
    char *description = hts_format_description(format);

    // Free the allocated memory for the description if it is not NULL
    if (description) {
        free(description);
    }

    // Free the allocated memory for htsFormat
    free(format);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
