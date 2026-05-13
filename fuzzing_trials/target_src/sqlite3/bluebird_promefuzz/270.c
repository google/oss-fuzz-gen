#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "sqlite3.h"
#include <stdlib.h>
#include <string.h>

static sqlite3_str* create_sqlite3_str() {
    sqlite3 *db = NULL;
    sqlite3_str *str = sqlite3_str_new(db);
    return str;
}

static void fuzz_sqlite3_str_functions(sqlite3_str *str, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    int choice = Data[0] % 5;
    Data++;
    Size--;

    switch(choice) {
        case 0: {
            // Test sqlite3_str_appendchar
            if (Size < 2) return;
            int N = Data[0];
            char C = (char)Data[1];
            sqlite3_str_appendchar(str, N, C);
            break;
        }
        case 1: {
            // Test sqlite3_str_append
            if (Size < 1) return;
            int N = Size;
            sqlite3_str_append(str, (const char*)Data, N);
            break;
        }
        case 2: {
            // Test sqlite3_str_truncate
            if (Size < 1) return;
            int N = Data[0];
            sqlite3_str_truncate(str, N);
            break;
        }
        case 3: {
            // Test sqlite3_str_length
            int length = sqlite3_str_length(str);
            (void)length; // Avoid unused variable warning
            break;
        }
        case 4: {
            // Test sqlite3_str_errcode
            int errcode = sqlite3_str_errcode(str);
            (void)errcode; // Avoid unused variable warning
            break;
        }
    }
}

int LLVMFuzzerTestOneInput_270(const uint8_t *Data, size_t Size) {
    sqlite3_str *str = create_sqlite3_str();
    if (str == NULL) {
        return 0;
    }

    fuzz_sqlite3_str_functions(str, Data, Size);

    sqlite3_str_free(str);
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

    LLVMFuzzerTestOneInput_270(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
