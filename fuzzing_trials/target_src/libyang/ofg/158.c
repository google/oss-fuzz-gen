#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libyang.h>  // Corrected include statement

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    struct ly_ctx *ctx = NULL;
    struct lyd_node *root = NULL;
    struct lyd_node_term *node_term = NULL;
    const struct lyd_leafref_links_rec *links_rec = NULL;
    LY_ERR err;

    // Initialize the libyang context
    err = ly_ctx_new(NULL, 0, &ctx);
    if (err != LY_SUCCESS) {
        fprintf(stderr, "Failed to create context\n");
        return 0;
    }

    // Parse the input data as a JSON tree
    if (size > 0) {
        char *json_data = (char *)malloc(size + 1);
        if (json_data == NULL) {
            ly_ctx_destroy(ctx);
            return 0;
        }
        memcpy(json_data, data, size);
        json_data[size] = '\0';

        err = lyd_parse_data_mem(ctx, json_data, LYD_JSON, LYD_PARSE_ONLY, 0, &root);
        free(json_data);

        if (err == LY_SUCCESS && root != NULL) {
            // Assuming the first node is a term node for fuzzing purposes
            node_term = (struct lyd_node_term *)root;

            // Call the function-under-test
            lyd_leafref_get_links(node_term, &links_rec);

            // Free the parsed data tree
            lyd_free_all(root);
        }
    }

    // Destroy the context
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

    LLVMFuzzerTestOneInput_158(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
