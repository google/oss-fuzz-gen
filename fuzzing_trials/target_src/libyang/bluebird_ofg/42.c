#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libyang.h"  // Corrected the include path for libyang

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Create a dummy XML string from the input data
    char *xml_data = (char *)malloc(size + 1);
    if (xml_data == NULL) {
        ly_ctx_destroy(ctx);
        return 0;
    }
    memcpy(xml_data, data, size);
    xml_data[size] = '\0';

    // Parse the XML data into a data tree
    err = lyd_parse_data_mem(ctx, xml_data, LYD_XML, LYD_PARSE_STRICT, 0, &root);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to parse XML data\n");
    }

    // Clean up
    lyd_free_all(root);
    free(xml_data);
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
