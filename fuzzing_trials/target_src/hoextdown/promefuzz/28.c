// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_buffer_init at buffer.c:48:1 in buffer.h
// hoedown_buffer_putc at buffer.c:138:1 in buffer.h
// hoedown_buffer_slurp at buffer.c:210:1 in buffer.h
// hoedown_buffer_printf at buffer.c:238:1 in buffer.h
// hoedown_buffer_reset at buffer.c:93:1 in buffer.h
// hoedown_buffer_uninit at buffer.c:66:1 in buffer.h
// hoedown_buffer_uninit at buffer.c:66:1 in buffer.h
// hoedown_buffer_init at buffer.c:48:1 in buffer.h
// hoedown_buffer_putc at buffer.c:138:1 in buffer.h
// hoedown_buffer_reset at buffer.c:93:1 in buffer.h
// hoedown_buffer_uninit at buffer.c:66:1 in buffer.h
// hoedown_buffer_uninit at buffer.c:66:1 in buffer.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "buffer.h"

static void *default_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

static void default_free(void *ptr) {
    free(ptr);
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    hoedown_buffer buffer;
    hoedown_buffer_init(&buffer, 64, default_realloc, default_free, default_free);

    size_t action = Data[0] % 6; // Select an action based on the first byte
    const uint8_t *inputData = Data + 1;
    size_t inputSize = Size - 1;

    switch (action) {
        case 0: {
            // Test hoedown_buffer_putc
            for (size_t i = 0; i < inputSize; i++) {
                hoedown_buffer_putc(&buffer, inputData[i]);
            }
            break;
        }
        case 1: {
            // Test hoedown_buffer_slurp
            if (inputSize > 0) {
                size_t slurpSize = inputData[0] % (buffer.size + 1);
                hoedown_buffer_slurp(&buffer, slurpSize);
            }
            break;
        }
        case 2: {
            // Test hoedown_buffer_printf
            char formatString[100];
            snprintf(formatString, sizeof(formatString), "Data: %.*s", (int)inputSize, inputData);
            hoedown_buffer_printf(&buffer, "%s", formatString);
            break;
        }
        case 3: {
            // Test hoedown_buffer_reset
            hoedown_buffer_reset(&buffer);
            break;
        }
        case 4: {
            // Test hoedown_buffer_uninit
            hoedown_buffer_uninit(&buffer);
            break;
        }
        case 5: {
            // Reinitialize buffer and test all functions
            hoedown_buffer_uninit(&buffer);
            hoedown_buffer_init(&buffer, 64, default_realloc, default_free, default_free);
            for (size_t i = 0; i < inputSize; i++) {
                hoedown_buffer_putc(&buffer, inputData[i]);
            }
            hoedown_buffer_reset(&buffer);
            hoedown_buffer_uninit(&buffer);
            break;
        }
        default:
            break;
    }

    // Cleanup
    hoedown_buffer_uninit(&buffer);
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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    