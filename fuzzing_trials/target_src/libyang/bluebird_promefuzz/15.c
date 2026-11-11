#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libyang/src/context.h"

static void fuzz_ly_ctx_unset_options(struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;
    uint32_t option = *((uint32_t *)Data);
    ly_ctx_unset_options(ctx, option);
}

static void fuzz_ly_ctx_compiled_print(const struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    size_t mem_size = Size;
    void *mem = malloc(mem_size);
    if (!mem) return;
    void *mem_end = NULL;
    ly_ctx_compiled_print(ctx, mem, &mem_end);
    free(mem);
}

static void fuzz_ly_ctx_unset_searchdir_last(struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;
    uint32_t count = *((uint32_t *)Data);
    ly_ctx_unset_searchdir_last(ctx, count);
}

static void fuzz_ly_ctx_compile(struct ly_ctx *ctx) {
    ly_ctx_compile(ctx);
}

static void fuzz_ly_ctx_set_options(struct ly_ctx *ctx, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;
    uint32_t option = *((uint32_t *)Data);
    ly_ctx_set_options(ctx, option);
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    struct ly_ctx *ctx = NULL;
    const char *search_dir = "./dummy_file";
    FILE *file = fopen(search_dir, "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    if (ly_ctx_new(search_dir, 0, &ctx) != LY_SUCCESS) {
        return 0;
    }

    fuzz_ly_ctx_unset_options(ctx, Data, Size);
    fuzz_ly_ctx_compiled_print(ctx, Data, Size);
    fuzz_ly_ctx_unset_searchdir_last(ctx, Data, Size);
    fuzz_ly_ctx_compile(ctx);
    fuzz_ly_ctx_set_options(ctx, Data, Size);

    if (ctx) {
        // Assuming a function `ly_ctx_destroy` exists for cleanup
        // ly_ctx_destroy(ctx);
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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
