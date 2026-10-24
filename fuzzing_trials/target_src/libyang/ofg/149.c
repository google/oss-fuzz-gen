#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>  // Include string.h for memcpy
#include <libyang.h>  // Corrected the include path for libyang

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *node = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Convert the input data to a null-terminated string
    char *data_str = (char *)malloc(size + 1);
    if (data_str == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';

    // Attempt to parse the input data as a JSON data tree
    lyd_parse_data_mem(ctx, data_str, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &node);

    // Free the parsed data tree
    lyd_free_all(node);

    // Clean up
    free(data_str);
    ly_ctx_destroy(ctx);

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

    LLVMFuzzerTestOneInput_149(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
