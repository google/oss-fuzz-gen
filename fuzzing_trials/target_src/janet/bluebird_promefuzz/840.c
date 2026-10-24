#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_atomic_inc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAtomicInt)) return;
    JanetAtomicInt x = *(JanetAtomicInt *)Data;
    janet_atomic_inc(&x);
}

static void fuzz_janet_gclock(const uint8_t *Data, size_t Size) {
    (void)Data;
    (void)Size;
    janet_gclock();
}

static void fuzz_janet_abstract_incref(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAtomicInt)) return;
    // Allocate a dummy abstract object to ensure valid memory access
    JanetAbstractHead *head = (JanetAbstractHead *)malloc(sizeof(JanetAbstractHead) + sizeof(JanetAtomicInt));
    if (!head) return;
    head->gc.data.refcount = *(JanetAtomicInt *)Data;
    janet_abstract_incref(head + 1);
    free(head);
}

static void fuzz_janet_atomic_load(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetAtomicInt)) return;
    JanetAtomicInt x = *(JanetAtomicInt *)Data;
    janet_atomic_load(&x);
}

int LLVMFuzzerTestOneInput_840(const uint8_t *Data, size_t Size) {
    fuzz_janet_atomic_inc(Data, Size);
    fuzz_janet_gclock(Data, Size);
    fuzz_janet_abstract_incref(Data, Size);
    fuzz_janet_atomic_load(Data, Size);
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

    LLVMFuzzerTestOneInput_840(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
