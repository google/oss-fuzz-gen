#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static JanetTable *create_dummy_table() {
    JanetTable *table = janet_table(0);
    Janet key = janet_cstringv("dummy_key");
    Janet value = janet_cstringv("dummy_value");
    janet_table_put(table, key, value);
    return table;
}

static JanetTable *create_dummy_env() {
    return janet_table(0);
}

static Janet create_dummy_janet() {
    return janet_cstringv("dummy_key");
}

int LLVMFuzzerTestOneInput_759(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    janet_init();

    // Fuzz janet_table_get_ex
    JanetTable *table = create_dummy_table();
    JanetTable *which = NULL;
    Janet key = create_dummy_janet();
    janet_table_get_ex(table, key, &which);

    // Fuzz janet_cfuns_prefix
    JanetReg cfuns[] = {
        {NULL, NULL, NULL} // Terminator
    };
    char regprefix[256];
    snprintf(regprefix, sizeof(regprefix), "prefix_%zu", Size);
    janet_cfuns_prefix(create_dummy_env(), regprefix, cfuns);

    // Fuzz janet_cfuns_ext
    JanetRegExt cfuns_ext[] = {
        {NULL, NULL, NULL, NULL, 0} // Terminator
    };
    janet_cfuns_ext(create_dummy_env(), regprefix, cfuns_ext);

    // Fuzz janet_core_lookup_table
    JanetTable *replacements = create_dummy_table();
    JanetTable *lookup_table = janet_core_lookup_table(replacements);

    // Fuzz janet_env_lookup
    JanetTable *env = create_dummy_env();
    JanetTable *new_env = janet_env_lookup(env);

    // Fuzz janet_cfuns
    janet_cfuns(create_dummy_env(), regprefix, cfuns);

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

    LLVMFuzzerTestOneInput_759(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
