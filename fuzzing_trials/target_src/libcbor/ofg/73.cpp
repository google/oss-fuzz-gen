extern "C" {
#include <stdint.h>
#include <stdlib.h>
#include <cbor.h>
}

// Fuzzing harness for cbor_tag_set_item
extern "C" int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create cbor_item_t objects
    if (size < 9) {
        return 0;
    }

    // Create two cbor_item_t objects
    uint64_t tag_value = 0;
    for (int i = 0; i < 8; ++i) {
        tag_value = (tag_value << 8) | data[i];
    }
    cbor_item_t *tag_item = cbor_new_tag(tag_value);
    cbor_item_t *child_item = cbor_new_int8();

    // Check if the items were successfully created
    if (tag_item == NULL || child_item == NULL) {
        if (tag_item != NULL) {
            cbor_decref(&tag_item);
        }
        if (child_item != NULL) {
            cbor_decref(&child_item);
        }
        return 0;
    }

    // Set some values in child_item to avoid it being NULL
    cbor_mark_uint(child_item);
    cbor_set_uint8(child_item, data[8]);

    // Call the function-under-test
    cbor_tag_set_item(tag_item, child_item);

    // Additional operations to ensure coverage
    // Serialize the tag item to check if serialization paths are covered
    unsigned char *buffer;
    size_t buffer_size;
    if (cbor_serialize_alloc(tag_item, &buffer, &buffer_size)) {
        free(buffer);
    }

    // Clean up
    cbor_decref(&tag_item);
    cbor_decref(&child_item);

    return 0;
}