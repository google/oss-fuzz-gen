// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_smalloc at gc.c:706:7 in janet.h
// janet_abstract_begin at janet.c:1330:7 in janet.h
// janet_smalloc at gc.c:706:7 in janet.h
// janet_srealloc at gc.c:735:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "janet.h"

// Dummy JanetAbstractType for testing
static JanetAbstractType dummyType = {0};

// Initialize Janet VM
static void initialize_janet_vm() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

// Helper function to test janet_smalloc
static void test_janet_smalloc(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        size_t alloc_size = Data[0] % 256; // Limit size to 256 for testing
        void *ptr = janet_smalloc(alloc_size);
        if (ptr) {
            // Normally, you would use the allocated memory here
            // For fuzzing, we just ensure it does not crash
        }
    }
}

// Helper function to test janet_abstract_begin
static void test_janet_abstract_begin(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        size_t alloc_size = Data[0] % 256; // Limit size to 256 for testing
        void *ptr = janet_abstract_begin(&dummyType, alloc_size);
        if (ptr) {
            // Normally, you would use the allocated memory here
            // For fuzzing, we just ensure it does not crash
        }
    }
}

// Helper function to test janet_srealloc
static void test_janet_srealloc(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        size_t alloc_size = Data[0] % 256; // Limit size to 256 for testing
        void *ptr = janet_smalloc(alloc_size);
        if (ptr) {
            size_t new_size = (Size > 1) ? Data[1] % 256 : 0;
            void *new_ptr = janet_srealloc(ptr, new_size);
            if (new_ptr) {
                // Normally, you would use the reallocated memory here
                // For fuzzing, we just ensure it does not crash
            }
        }
    }
}

// Helper function to test janet_realloc
static void test_janet_realloc(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        size_t alloc_size = Data[0] % 256; // Limit size to 256 for testing
        void *ptr = janet_malloc(alloc_size);
        if (ptr) {
            size_t new_size = (Size > 1) ? Data[1] % 256 : 0;
            void *new_ptr = janet_realloc(ptr, new_size);
            if (new_ptr) {
                // Normally, you would use the reallocated memory here
                // For fuzzing, we just ensure it does not crash
            }
        }
    }
}

// Helper function to test janet_malloc
static void test_janet_malloc(const uint8_t *Data, size_t Size) {
    if (Size > 0) {
        size_t alloc_size = Data[0] % 256; // Limit size to 256 for testing
        void *ptr = janet_malloc(alloc_size);
        if (ptr) {
            // Normally, you would use the allocated memory here
            // For fuzzing, we just ensure it does not crash
        }
    }
}

int LLVMFuzzerTestOneInput_133(const uint8_t *Data, size_t Size) {
    initialize_janet_vm();
    test_janet_smalloc(Data, Size);
    test_janet_abstract_begin(Data, Size);
    test_janet_srealloc(Data, Size);
    test_janet_realloc(Data, Size);
    test_janet_malloc(Data, Size);
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

        LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    