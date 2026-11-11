// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_abstract_begin at janet.c:1330:7 in janet.h
// janet_unmarshal_abstract at marsh.c:1281:7 in janet.h
// janet_panic_abstract at janet.c:4443:6 in janet.h
// janet_abstract at janet.c:1343:7 in janet.h
// janet_abstract_begin_threaded at janet.c:1353:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Ensure Janet is initialized before using any Janet functions
static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_abstract_head(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *)) return;
    const void *abstract = *(const void **)Data;
    JanetAbstractHead *head = janet_abstract_head(abstract);
    (void)head;
}

static void fuzz_janet_abstract_begin(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAbstractType) + sizeof(size_t)) return;
    const JanetAbstractType *type = (const JanetAbstractType *)Data;
    size_t size = *(const size_t *)(Data + sizeof(JanetAbstractType));
    void *abstract = janet_abstract_begin(type, size);
    if (abstract) {
        // Simulate some use of the abstract
        memset(abstract, 0, size);
    }
}

static void fuzz_janet_unmarshal_abstract(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetMarshalContext) + sizeof(size_t)) return;
    JanetMarshalContext *ctx = (JanetMarshalContext *)Data;
    size_t size = *(const size_t *)(Data + sizeof(JanetMarshalContext));
    JanetAbstract abstract = janet_unmarshal_abstract(ctx, size);
    (void)abstract;
}

static void fuzz_janet_panic_abstract(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(int32_t) + sizeof(JanetAbstractType)) return;
    Janet x = *(const Janet *)Data;
    int32_t n = *(const int32_t *)(Data + sizeof(Janet));
    const JanetAbstractType *at = (const JanetAbstractType *)(Data + sizeof(Janet) + sizeof(int32_t));
    
    if (at->name) {
        janet_panic_abstract(x, n, at);
    }
}

static void fuzz_janet_abstract(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAbstractType) + sizeof(size_t)) return;
    const JanetAbstractType *type = (const JanetAbstractType *)Data;
    size_t size = *(const size_t *)(Data + sizeof(JanetAbstractType));
    JanetAbstract abstract = janet_abstract(type, size);
    (void)abstract;
}

static void fuzz_janet_abstract_begin_threaded(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAbstractType) + sizeof(size_t)) return;
    const JanetAbstractType *atype = (const JanetAbstractType *)Data;
    size_t size = *(const size_t *)(Data + sizeof(JanetAbstractType));
    void *abstract = janet_abstract_begin_threaded(atype, size);
    if (abstract) {
        // Simulate some use of the abstract
        memset(abstract, 0, size);
    }
}

int LLVMFuzzerTestOneInput_513(const uint8_t *Data, size_t Size) {
    initialize_janet();
    fuzz_janet_abstract_head(Data, Size);
    fuzz_janet_abstract_begin(Data, Size);
    fuzz_janet_unmarshal_abstract(Data, Size);
    fuzz_janet_panic_abstract(Data, Size);
    fuzz_janet_abstract(Data, Size);
    fuzz_janet_abstract_begin_threaded(Data, Size);
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

        LLVMFuzzerTestOneInput_513(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    