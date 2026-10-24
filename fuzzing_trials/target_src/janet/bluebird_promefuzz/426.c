#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_dynprintf(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    const char *name = (const char *)Data;
    FILE *dflt_file = fopen("./dummy_file", "w");
    if (!dflt_file) return;

    const char *format = "%s";
    // Ensure that the argument is null-terminated
    size_t arg_len = Size - 1;
    char *arg = (char *)malloc(arg_len + 1);
    if (!arg) {
        fclose(dflt_file);
        return;
    }
    memcpy(arg, Data + 1, arg_len);
    arg[arg_len] = '\0';

    janet_dynprintf(name, dflt_file, format, arg);
    fclose(dflt_file);
    free(arg);
}

static void fuzz_janet_ev_lasterr(void) {
    janet_init();
    Janet err = janet_ev_lasterr();
    (void)err;
    janet_deinit();
}

static void fuzz_janet_dynfile(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    const char *name = (const char *)Data;
    FILE *def = fopen("./dummy_file", "r");
    if (!def) return;

    FILE *result = janet_dynfile(name, def);
    if (result && result != def) fclose(result);
    fclose(def);
}

static void fuzz_janet_unwrapfile(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;

    Janet j;
    memcpy(&j, Data, sizeof(Janet));

    if (janet_checktype(j, JANET_ABSTRACT)) {
        int32_t flags;
        FILE *file = janet_unwrapfile(j, &flags);
        if (file) fclose(file);
    }
}

int LLVMFuzzerTestOneInput_426(const uint8_t *Data, size_t Size) {
    fuzz_janet_dynprintf(Data, Size);
    fuzz_janet_ev_lasterr();
    fuzz_janet_dynfile(Data, Size);
    fuzz_janet_unwrapfile(Data, Size);
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

    LLVMFuzzerTestOneInput_426(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
