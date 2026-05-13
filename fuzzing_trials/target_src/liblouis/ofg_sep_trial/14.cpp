#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include <liblouis/liblouis.h>
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to split into meaningful parts
    if (size < 4) {
        return 0;
    }

    // Prepare input parameters for lou_charToDots
    const char *tableList = "unicode.dis"; // A non-NULL string for tableList
    const widechar *inbuf = reinterpret_cast<const widechar *>(data); // Treat data as widechar input
    int inlen = size / sizeof(widechar); // Calculate the number of widechars in data
    widechar *outbuf = new widechar[inlen + 1]; // Allocate output buffer
    int outlen = inlen; // Set output length to input length

    // Call the function under test
    lou_charToDots(tableList, inbuf, outbuf, inlen, outlen);

    // Clean up
    delete[] outbuf;

    return 0;
}