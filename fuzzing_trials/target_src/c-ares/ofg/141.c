#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    /* Ensure the data is null-terminated for string operations */
    char *sortstr = (char *)malloc(size + 1);
    if (!sortstr) {
        return 0;
    }
    memcpy(sortstr, data, size);
    sortstr[size] = '\0';

    ares_channel channel;
    if (ares_init(&channel) != ARES_SUCCESS) {
        free(sortstr);
        return 0;
    }

    /* Call the function-under-test */
    ares_set_sortlist(channel, sortstr);

    /* Clean up */
    ares_destroy(channel);
    free(sortstr);

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

    LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
