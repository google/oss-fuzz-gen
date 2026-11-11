// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_value_dup at sqlite3.c:78678:27 in sqlite3.h
// sqlite3_value_text at sqlite3.c:78560:33 in sqlite3.h
// sqlite3_value_text16le at sqlite3.c:78570:24 in sqlite3.h
// sqlite3_value_text16 at sqlite3.c:78564:24 in sqlite3.h
// sqlite3_value_pointer at sqlite3.c:78547:18 in sqlite3.h
// sqlite3_value_dup at sqlite3.c:78678:27 in sqlite3.h
// sqlite3_value_free at sqlite3.c:78704:17 in sqlite3.h
// sqlite3_value_text16be at sqlite3.c:78567:24 in sqlite3.h
// sqlite3_value_free at sqlite3.c:78704:17 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Create an sqlite3_value object from input data
    sqlite3_value *value = sqlite3_value_dup(NULL);
    if (!value) {
        return 0;
    }

    // Set up the value as a text type for testing
    sqlite3_value_text(value);

    // Fuzz sqlite3_value_text16le
    const void *text16le = sqlite3_value_text16le(value);

    // Fuzz sqlite3_value_text16
    const void *text16 = sqlite3_value_text16(value);

    // Fuzz sqlite3_value_pointer with a dummy type name
    void *pointer = sqlite3_value_pointer(value, "dummy_type");

    // Fuzz sqlite3_value_dup
    sqlite3_value *value_dup = sqlite3_value_dup(value);
    if (value_dup) {
        // Free the duplicated value
        sqlite3_value_free(value_dup);
    }

    // Fuzz sqlite3_value_text16be
    const void *text16be = sqlite3_value_text16be(value);

    // Clean up
    sqlite3_value_free(value);

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

        LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    