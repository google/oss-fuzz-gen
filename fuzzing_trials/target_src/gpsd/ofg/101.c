#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>  // Include string.h for using memset
#include "gpsd_config.h"  // Assuming this header defines MAX_DEVICES, MAX_SUBFRAMES, MAX_SENTENCES, and other necessary configurations
#include "gpsd.h"  // Assuming gpsd.h contains the declaration for gpsd_interpret_subframe_raw and struct gps_device_t

// Define MAX_SUBFRAMES and MAX_SENTENCES if they are not defined in gpsd_config.h
#ifndef MAX_SUBFRAMES
#define MAX_SUBFRAMES 5
#endif

#ifndef MAX_SENTENCES
#define MAX_SENTENCES 10
#endif

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t) * 10 + sizeof(unsigned int) * 4) {
        return 0;  // Not enough data to fill all parameters
    }

    struct gps_device_t device;
    memset(&device, 0, sizeof(device));  // Ensure zero-initialization using memset

    // Ensure that we do not read beyond the provided data
    if (size < 3 * sizeof(unsigned int) + 10 * sizeof(uint32_t) + sizeof(unsigned int)) {
        return 0;
    }

    unsigned int subframe = 0;
    unsigned int word_count = 0;
    unsigned int sentence_index = 0;
    uint32_t words[10] = {0};
    unsigned int data_length = 0;

    // Safely extract data ensuring no out-of-bounds access
    if (size >= sizeof(unsigned int)) {
        subframe = *((unsigned int *)data);
    }
    if (size >= 2 * sizeof(unsigned int)) {
        word_count = *((unsigned int *)(data + sizeof(unsigned int)));
    }
    if (size >= 3 * sizeof(unsigned int)) {
        sentence_index = *((unsigned int *)(data + 2 * sizeof(unsigned int)));
    }
    if (size >= 3 * sizeof(unsigned int) + 10 * sizeof(uint32_t)) {
        for (int i = 0; i < 10; i++) {
            words[i] = *((uint32_t *)(data + 3 * sizeof(unsigned int) + i * sizeof(uint32_t)));
        }
    }
    if (size >= 3 * sizeof(unsigned int) + 10 * sizeof(uint32_t) + sizeof(unsigned int)) {
        data_length = *((unsigned int *)(data + 3 * sizeof(unsigned int) + 10 * sizeof(uint32_t)));
    }

    // Ensure valid values are passed to the function to avoid segmentation faults
    if (subframe < MAX_SUBFRAMES && word_count <= 10 && sentence_index < MAX_SENTENCES) {
        // Call the function under test
        gps_mask_t result = gpsd_interpret_subframe_raw(&device, subframe, word_count, sentence_index, words, data_length);

        // Use the result to avoid the unused variable warning
        if (result != 0) {
            printf("Result: %lu\n", (unsigned long)result);  // Use %lu for unsigned long
        }
    }

    return 0;
}