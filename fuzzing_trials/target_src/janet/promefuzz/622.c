// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table at janet.c:33121:13 in janet.h
// janet_var at janet.c:34118:6 in janet.h
// janet_table at janet.c:33121:13 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_var_sm at janet.c:34110:6 in janet.h
// janet_nanbox_from_bits at janet.c:37716:7 in janet.h
// janet_resolve_core at janet.c:34455:7 in janet.h
// janet_setdyn at janet.c:4789:6 in janet.h
// janet_table at janet.c:33121:13 in janet.h
// janet_def_sm at janet.c:34099:6 in janet.h
// janet_table at janet.c:33121:13 in janet.h
// janet_def at janet.c:34105:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "janet.h"

static void initialize_janet_vm() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static Janet fuzz_janet_resolve_core(const uint8_t *Data, size_t Size) {
    char name[256];
    if (Size < 1) return janet_wrap_nil();
    size_t copy_size = Size < 255 ? Size : 255;
    memcpy(name, Data, copy_size);
    name[copy_size] = '\0';
    return janet_resolve_core(name);
}

static void fuzz_janet_setdyn(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    char name[256];
    size_t name_size = Size - sizeof(Janet);
    if (name_size > 255) name_size = 255;
    memcpy(name, Data, name_size);
    name[name_size] = '\0';
    Janet value;
    memcpy(&value, Data + name_size, sizeof(Janet));
    janet_setdyn(name, value);
}

static void fuzz_janet_def_sm(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 8) return;
    JanetTable *env = janet_table(10);
    char name[256], doc[256], source_file[256];
    int32_t source_line;

    size_t offset = 0;
    size_t name_size = Size - sizeof(Janet) - 8;
    if (name_size > 255) name_size = 255;
    memcpy(name, Data + offset, name_size);
    name[name_size] = '\0';
    offset += name_size;

    Janet value;
    memcpy(&value, Data + offset, sizeof(Janet));
    offset += sizeof(Janet);

    size_t doc_size = Size - offset - 4;
    if (doc_size > 255) doc_size = 255;
    memcpy(doc, Data + offset, doc_size);
    doc[doc_size] = '\0';
    offset += doc_size;

    size_t source_file_size = Size - offset - 4;
    if (source_file_size > 255) source_file_size = 255;
    memcpy(source_file, Data + offset, source_file_size);
    source_file[source_file_size] = '\0';
    offset += source_file_size;

    memcpy(&source_line, Data + offset, sizeof(int32_t));

    janet_def_sm(env, name, value, doc, source_file, source_line);
}

static void fuzz_janet_def(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 4) return;
    JanetTable *env = janet_table(10);
    char name[256], doc[256];

    size_t offset = 0;
    size_t name_size = Size - sizeof(Janet) - 4;
    if (name_size > 255) name_size = 255;
    memcpy(name, Data + offset, name_size);
    name[name_size] = '\0';
    offset += name_size;

    Janet value;
    memcpy(&value, Data + offset, sizeof(Janet));
    offset += sizeof(Janet);

    size_t doc_size = Size - offset;
    if (doc_size > 255) doc_size = 255;
    memcpy(doc, Data + offset, doc_size);
    doc[doc_size] = '\0';

    janet_def(env, name, value, doc);
}

static void fuzz_janet_var(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 4) return;
    JanetTable *env = janet_table(10);
    char name[256], doc[256];

    size_t offset = 0;
    size_t name_size = Size - sizeof(Janet) - 4;
    if (name_size > 255) name_size = 255;
    memcpy(name, Data + offset, name_size);
    name[name_size] = '\0';
    offset += name_size;

    Janet value;
    memcpy(&value, Data + offset, sizeof(Janet));
    offset += sizeof(Janet);

    size_t doc_size = Size - offset;
    if (doc_size > 255) doc_size = 255;
    memcpy(doc, Data + offset, doc_size);
    doc[doc_size] = '\0';

    janet_var(env, name, value, doc);
}

static void fuzz_janet_var_sm(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + 8) return;
    JanetTable *env = janet_table(10);
    char name[256], doc[256], source_file[256];
    int32_t source_line;

    size_t offset = 0;
    size_t name_size = Size - sizeof(Janet) - 8;
    if (name_size > 255) name_size = 255;
    memcpy(name, Data + offset, name_size);
    name[name_size] = '\0';
    offset += name_size;

    Janet value;
    memcpy(&value, Data + offset, sizeof(Janet));
    offset += sizeof(Janet);

    size_t doc_size = Size - offset - 4;
    if (doc_size > 255) doc_size = 255;
    memcpy(doc, Data + offset, doc_size);
    doc[doc_size] = '\0';
    offset += doc_size;

    size_t source_file_size = Size - offset - 4;
    if (source_file_size > 255) source_file_size = 255;
    memcpy(source_file, Data + offset, source_file_size);
    source_file[source_file_size] = '\0';
    offset += source_file_size;

    memcpy(&source_line, Data + offset, sizeof(int32_t));

    janet_var_sm(env, name, value, doc, source_file, source_line);
}

int LLVMFuzzerTestOneInput_622(const uint8_t *Data, size_t Size) {
    initialize_janet_vm();
    fuzz_janet_resolve_core(Data, Size);
    fuzz_janet_setdyn(Data, Size);
    fuzz_janet_def_sm(Data, Size);
    fuzz_janet_def(Data, Size);
    fuzz_janet_var(Data, Size);
    fuzz_janet_var_sm(Data, Size);
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

        LLVMFuzzerTestOneInput_622(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    