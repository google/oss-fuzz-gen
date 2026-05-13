#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h> // Ensure the HTSlib library is installed and included

int LLVMFuzzerTestOneInput_237(const uint8_t *data, size_t size) {
    // Initialize the sam_hdr_t structure
    sam_hdr_t *hdr = sam_hdr_init();

    // Ensure the data size is non-zero to avoid empty string issues
    if (size == 0) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Create a null-terminated string from the input data
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        sam_hdr_destroy(hdr);
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    // Call the function under test
    int result = sam_hdr_add_lines(hdr, str, 0);

    // Clean up
    free(str);
    sam_hdr_destroy(hdr);

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

    LLVMFuzzerTestOneInput_237(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
