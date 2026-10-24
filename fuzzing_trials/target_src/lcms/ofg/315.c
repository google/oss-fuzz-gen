#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_315(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 4) {
        return 0;
    }

    // Allocate and initialize cmsMLU object
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);

    // Prepare strings from the input data
    size_t str1_len = (size / 4);
    size_t str2_len = (size / 4);
    size_t str3_len = (size / 4);

    char *str1 = (char *)malloc(str1_len + 1);
    char *str2 = (char *)malloc(str2_len + 1);
    char *str3 = (char *)malloc(str3_len + 1);

    if (str1 == NULL || str2 == NULL || str3 == NULL) {
        free(str1);
        free(str2);
        free(str3);
        cmsMLUfree(mlu);
        return 0;
    }

    memcpy(str1, data, str1_len);
    str1[str1_len] = '\0';

    memcpy(str2, data + str1_len, str2_len);
    str2[str2_len] = '\0';

    memcpy(str3, data + str1_len + str2_len, str3_len);
    str3[str3_len] = '\0';

    // Call the function-under-test
    cmsMLUsetUTF8(mlu, str1, str2, str3);

    // Cleanup
    free(str1);
    free(str2);
    free(str3);
    cmsMLUfree(mlu);

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

    LLVMFuzzerTestOneInput_315(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
