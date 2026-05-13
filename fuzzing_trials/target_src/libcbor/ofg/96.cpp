#include <cstdint>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a cbor_item_t
    if (size < 1) {
        return 0;
    }

    // Use the first byte to decide the type of CBOR item to create
    cbor_item_t *item = nullptr;
    switch (data[0] % 4) {
        case 0:
            item = cbor_new_int8();
            cbor_set_uint8(item, data[0]);
            break;
        case 1:
            item = cbor_new_int16();
            if (size >= 2) {
                cbor_set_uint16(item, (data[0] << 8) | data[1]);
            }
            break;
        case 2:
            item = cbor_new_int32();
            if (size >= 4) {
                cbor_set_uint32(item, (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
            }
            break;
        case 3:
            item = cbor_new_int64();
            if (size >= 8) {
                cbor_set_uint64(item, ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) |
                                          ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) |
                                          ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) |
                                          ((uint64_t)data[6] << 8) | (uint64_t)data[7]);
            }
            break;
    }

    // Ensure the item was created
    if (item != nullptr) {
        // Call the function-under-test
        bool result = cbor_is_int(item);

        // Clean up
        cbor_decref(&item);
    }

    return 0;
}