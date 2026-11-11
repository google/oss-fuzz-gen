#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "../../liblouis/liblouis.h"
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <fstream>

static void writeDummyFile(const char *data, size_t size) {
    std::ofstream file("./dummy_file", std::ios::binary);
    file.write(data, size);
    file.close();
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    // Prepare input data
    const char *tableList = "./dummy_file";
    writeDummyFile(reinterpret_cast<const char*>(Data), Size);

    // Prepare buffers and parameters
    int inlen = Size / 2;
    int outlen = Size / 2;
    widechar *inbuf = new widechar[inlen];
    widechar *outbuf = new widechar[outlen];
    formtype *typeform = nullptr;
    char *spacing = nullptr;
    int *outputPos = new int[inlen];
    int *inputPos = new int[outlen];
    int cursorPos = 0;
    int mode = 0;

    // Fill input buffer
    std::memcpy(inbuf, Data, inlen * sizeof(widechar));

    // Call lou_backTranslate
    lou_backTranslate(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, mode);

    // Reset lengths for next function
    inlen = Size / 2;
    outlen = Size / 2;

    // Call lou_translate
    lou_translate(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, mode);

    // Reset lengths for next function
    int length = Size / 2;

    // Call lou_charToDots
    lou_charToDots(tableList, inbuf, outbuf, length, mode);

    // Reset lengths for next function
    inlen = Size / 2;
    outlen = Size / 2;

    // Call lou_translatePrehyphenated
    char *inputHyphens = nullptr;
    char *outputHyphens = nullptr;
    lou_translatePrehyphenated(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, outputPos, inputPos, &cursorPos, inputHyphens, outputHyphens, mode);

    // Reset lengths for next function
    inlen = Size / 2;
    outlen = Size / 2;

    // Call lou_backTranslateString
    lou_backTranslateString(tableList, inbuf, &inlen, outbuf, &outlen, typeform, spacing, mode);

    // Call lou_dotsToChar
    lou_dotsToChar(tableList, inbuf, outbuf, length, mode);

    // Cleanup
    delete[] inbuf;
    delete[] outbuf;
    delete[] outputPos;
    delete[] inputPos;

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
