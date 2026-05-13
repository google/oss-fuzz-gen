#include <stddef.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    struct ares_uri_reply *uri_out = NULL;

    /* Call the function-under-test */
    ares_parse_uri_reply(data, (int)size, &uri_out);

    /* Free the allocated data if any */
    if (uri_out) {
        ares_free_data(uri_out);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_67(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
