#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated to be used as a C-string
    char *null_terminated_data = (char *)malloc(size + 1);
    if (!null_terminated_data) {
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    plist_t plist = plist_new_string(null_terminated_data);

    // Clean up
    if (plist) {
        plist_free(plist);
    }
    free(null_terminated_data);

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

    LLVMFuzzerTestOneInput_175(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
