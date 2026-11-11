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
#include "janet.h"

static FILE *create_dummy_file() {
    FILE *f = fopen("./dummy_file", "w+");
    if (f) {
        fputs("dummy content", f);
        rewind(f);
    }
    return f;
}

int LLVMFuzzerTestOneInput_454(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;

    // Initialize the Janet VM
    janet_init();

    // Prepare the environment
    FILE *dummy_file = create_dummy_file();
    if (!dummy_file) {
        janet_deinit();
        return 0;
    }

    int32_t flags = *(const int32_t *)Data;
    JanetFile *janet_file = janet_makejfile(dummy_file, flags);
    
    if (janet_file) {
        // Test janet_unwrapfile
        int32_t retrieved_flags;
        Janet wrapped_janet_file = janet_wrap_abstract(janet_file);
        FILE *unwrapped_file = janet_unwrapfile(wrapped_janet_file, &retrieved_flags);

        // Test janet_getjfile
        Janet argv[1];
        argv[0] = wrapped_janet_file;
        JanetFile *retrieved_janet_file = janet_getjfile(argv, 0);

        // Close the JanetFile, which internally closes the FILE
        janet_file_close(janet_file);
    } else {
        // If janet_makejfile fails, we need to close the dummy_file ourselves
        fclose(dummy_file);
    }

    // Deinitialize the Janet VM
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

    LLVMFuzzerTestOneInput_454(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
