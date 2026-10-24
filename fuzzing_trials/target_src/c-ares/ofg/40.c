#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    ares_channel channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    /* Ensure that the local device name is null-terminated */
    char *local_dev_name = (char *)malloc(size + 1);
    if (local_dev_name == NULL) {
        ares_destroy(channel);
        return 0;
    }
    memcpy(local_dev_name, data, size);
    local_dev_name[size] = '\0';

    /* Call the function-under-test */
    ares_set_local_dev(channel, local_dev_name);

    /* Clean up */
    free(local_dev_name);
    ares_destroy(channel);

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
