#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 3) return 0;

    // Initialize variables
    cmsMLU *mlu = cmsMLUalloc(NULL, 1);
    const char *languageCode = "en";
    const char *countryCode = "US";
    char outputBuffer[256];
    cmsUInt32Number bufferSize = sizeof(outputBuffer);

    // Use the first byte of data to determine the size of the text
    cmsUInt32Number textSize = data[0] % 255; // Ensure textSize is within bounds

    // Ensure there is enough data for the text
    if (size < 1 + textSize) {
        cmsMLUfree(mlu);
        return 0;
    }

    // Copy text from data to a null-terminated string
    char text[256];
    memcpy(text, data + 1, textSize);
    text[textSize] = '\0';

    // Set the text in the cmsMLU object
    cmsMLUsetASCII(mlu, languageCode, countryCode, text);

    // Call the function under test
    cmsUInt32Number result = cmsMLUgetUTF8(mlu, languageCode, countryCode, outputBuffer, bufferSize);

    // Clean up
    cmsMLUfree(mlu);

    return 0;
}