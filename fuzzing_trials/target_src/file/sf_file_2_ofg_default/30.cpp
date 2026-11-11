#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure the input data is not empty to maximize fuzzing effectiveness
    if (size == 0) {
        return 0;
    }

    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test with a non-zero size
    const char *result = magic_buffer(magic, (const void *)data, size);

    // Utilize the result to increase code coverage
    if (result != NULL) {
        // Use the result in some way to increase code coverage
        size_t result_length = strlen(result);
        if (result_length > 0) {
            // Process the result to ensure the code is exercised
            for (size_t i = 0; i < result_length; ++i) {
                volatile char dummy = result[i];
                (void)dummy; // Prevent unused variable warning
            }

            // Additional processing to further increase code coverage
            // For example, checking for specific strings or patterns
            if (strstr(result, "text") != NULL) {
                // Simulate some processing when "text" is found in the result
                volatile int found_text = 1;
                (void)found_text;
            }

            if (strstr(result, "image") != NULL) {
                // Simulate some processing when "image" is found in the result
                volatile int found_image = 1;
                (void)found_image;
            }

            // Further processing to increase coverage
            if (strstr(result, "audio") != NULL) {
                // Simulate some processing when "audio" is found in the result
                volatile int found_audio = 1;
                (void)found_audio;
            }

            if (strstr(result, "video") != NULL) {
                // Simulate some processing when "video" is found in the result
                volatile int found_video = 1;
                (void)found_video;
            }
        }
    }

    magic_close(magic);
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
