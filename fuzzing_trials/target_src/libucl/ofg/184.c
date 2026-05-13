#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_184(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    ucl_object_t *ucl_obj = ucl_object_fromstring((const char *)data);
    if (ucl_obj == NULL) {
        return 0;
    }

    const char *result_str = NULL;
    bool result = ucl_object_tostring_safe(ucl_obj, &result_str);

    // Clean up
    ucl_object_unref(ucl_obj);

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

    LLVMFuzzerTestOneInput_184(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
