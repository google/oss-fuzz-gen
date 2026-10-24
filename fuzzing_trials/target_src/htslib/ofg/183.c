#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
    // Initialize the sam_hdr_t structure
    sam_hdr_t *hdr = sam_hdr_init();
    if (!hdr) {
        return 0;
    }

    // Ensure we have enough data to create non-NULL strings
    if (size < 3) {
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Create strings from the input data
    size_t str_len = size / 3;
    char *str1 = (char *)malloc(str_len + 1);
    char *str2 = (char *)malloc(str_len + 1);
    char *str3 = (char *)malloc(str_len + 1);

    if (!str1 || !str2 || !str3) {
        free(str1);
        free(str2);
        free(str3);
        sam_hdr_destroy(hdr);
        return 0;
    }

    // Copy data into strings and null-terminate them
    memcpy(str1, data, str_len);
    str1[str_len] = '\0';

    memcpy(str2, data + str_len, str_len);
    str2[str_len] = '\0';

    memcpy(str3, data + 2 * str_len, str_len);
    str3[str_len] = '\0';

    // Call the function-under-test
    sam_hdr_remove_line_id(hdr, str1, str2, str3);

    // Clean up
    free(str1);
    free(str2);
    free(str3);
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

    LLVMFuzzerTestOneInput_183(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
