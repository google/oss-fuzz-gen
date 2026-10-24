// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_optsize at janet.c:4868:8 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_unmarshal at marsh.c:1635:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_optkeyword at janet.c:4530:1 in janet.h
// janet_optbuffer at janet.c:4538:1 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <janet.h>

static void fuzz_janet_optsize(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 3 + sizeof(size_t)) return;
    const Janet *argv = (const Janet *)Data;
    int32_t argc = *(int32_t *)(Data + sizeof(Janet));
    int32_t n = *(int32_t *)(Data + sizeof(Janet) + sizeof(int32_t));
    size_t dflt = *(size_t *)(Data + sizeof(Janet) + sizeof(int32_t) * 2);

    janet_optsize(argv, argc, n, dflt);
}

static void fuzz_janet_unmarshal(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    int flags = *(int *)Data;
    JanetTable reg;
    const uint8_t *next;

    janet_init(); // Initialize Janet VM before using any Janet functions
    janet_unmarshal(Data + sizeof(int), Size - sizeof(int), flags, &reg, &next);
    janet_deinit(); // Deinitialize Janet VM after use
}

static void fuzz_janet_optkeyword(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 2 + sizeof(JanetString)) return;
    const Janet *argv = (const Janet *)Data;
    int32_t argc = *(int32_t *)(Data + sizeof(Janet));
    int32_t n = *(int32_t *)(Data + sizeof(Janet) + sizeof(int32_t));
    JanetString dflt = (JanetString)(Data + sizeof(Janet) + sizeof(int32_t) * 2);

    janet_optkeyword(argv, argc, n, dflt);
}

static void fuzz_janet_optbuffer(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 3) return;
    const Janet *argv = (const Janet *)Data;
    int32_t argc = *(int32_t *)(Data + sizeof(Janet));
    int32_t n = *(int32_t *)(Data + sizeof(Janet) + sizeof(int32_t));
    int32_t dflt_len = *(int32_t *)(Data + sizeof(Janet) + sizeof(int32_t) * 2);

    janet_optbuffer(argv, argc, n, dflt_len);
}

int LLVMFuzzerTestOneInput_614(const uint8_t *Data, size_t Size) {
    janet_init(); // Initialize Janet VM before using any Janet functions
    fuzz_janet_optsize(Data, Size);
    fuzz_janet_unmarshal(Data, Size);
    fuzz_janet_optkeyword(Data, Size);
    fuzz_janet_optbuffer(Data, Size);
    janet_deinit(); // Deinitialize Janet VM after use
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

        LLVMFuzzerTestOneInput_614(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    