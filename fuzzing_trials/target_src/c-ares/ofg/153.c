#include <stddef.h>
#include <stdint.h>
#include <ares.h>

// Function signature for the function-under-test
int ares_parse_srv_reply(const unsigned char *abuf, int alen_int, struct ares_srv_reply **srv_out);

int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    /* Ensure that the srv_out is initialized to NULL */
    struct ares_srv_reply *srv_out = NULL;

    /* Call the function-under-test */
    ares_parse_srv_reply(data, (int)size, &srv_out);

    /* If srv_out is not NULL, free the allocated memory */
    if (srv_out) {
        ares_free_data(srv_out);
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

    LLVMFuzzerTestOneInput_153(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
