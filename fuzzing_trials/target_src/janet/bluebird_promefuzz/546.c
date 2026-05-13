#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Helper function to initialize a JanetTable
static JanetTable *initialize_table() {
    JanetTable *table = janet_table(10);
    // Initialize table with some dummy data
    Janet key = janet_wrap_string(janet_cstring("key"));
    Janet value = janet_wrap_integer(42);
    janet_table_put(table, key, value);
    return table;
}

// Helper function to initialize JanetRegExt array
static JanetRegExt *initialize_regext_array() {
    JanetRegExt *cfuns = malloc(2 * sizeof(JanetRegExt));
    cfuns[0].name = "dummy_func";
    cfuns[0].cfun = NULL; // Assume a dummy C function
    cfuns[0].documentation = "A dummy function for testing";
    cfuns[0].source_file = NULL; // Ensure source_file is initialized
    cfuns[0].source_line = 0; // Ensure source_line is initialized
    cfuns[1].name = NULL; // Terminate the array
    return cfuns;
}

int LLVMFuzzerTestOneInput_546(const uint8_t *Data, size_t Size) {
    // Initialize the Janet environment
    janet_init();

    // Fuzz janet_table_get_ex
    JanetTable *table = initialize_table();
    Janet key = janet_wrap_string(janet_string(Data, Size));
    JanetTable *which = NULL;
    janet_table_get_ex(table, key, &which);

    // Fuzz janet_cfuns_prefix
    const char *prefix = "fuzz_prefix";
    JanetReg cfuns[] = {
        {NULL, NULL, NULL} // Dummy function
    };
    janet_cfuns_prefix(table, prefix, cfuns);

    // Fuzz janet_cfuns_ext
    JanetRegExt *ext_cfuns = initialize_regext_array();
    janet_cfuns_ext(table, prefix, ext_cfuns);
    free(ext_cfuns);

    // Fuzz janet_core_lookup_table
    JanetTable *core_table = janet_core_lookup_table(NULL);

    // Fuzz janet_env_lookup
    JanetTable *env_table = janet_env_lookup(core_table);

    // Fuzz janet_cfuns
    janet_cfuns(env_table, prefix, cfuns);

    // Cleanup
    janet_deinit();
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

    LLVMFuzzerTestOneInput_546(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
