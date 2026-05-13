#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming JanetMarshalContext is defined in some header file included in the project
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t position;
} JanetMarshalContext;

// Mock function definition for janet_unmarshal_byte_279
uint8_t janet_unmarshal_byte_279(JanetMarshalContext *ctx) {
    if (ctx->position < ctx->size) {
        return ctx->data[ctx->position++];
    }
    return 0; // Return 0 if position is out of bounds
}

int LLVMFuzzerTestOneInput_279(const uint8_t *data, size_t size) {
    if (size == 0) return 0; // Ensure there is data to process

    // Initialize JanetMarshalContext
    JanetMarshalContext ctx;
    ctx.data = data;
    ctx.size = size;
    ctx.position = 0;

    // Call the function-under-test
    uint8_t result = janet_unmarshal_byte_279(&ctx);

    // Use the result in some way to avoid compiler optimizations removing the call
    printf("Unmarshalled byte: %u\n", result);

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

    LLVMFuzzerTestOneInput_279(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
