#include <cbor.h>
#include <stddef.h>
#include <stdint.h>

extern "C" {
    struct cbor_decoder_result cbor_stream_decode(cbor_data, size_t, const struct cbor_callbacks *, void *);
}

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Initialize cbor_callbacks with dummy functions
    struct cbor_callbacks callbacks;
    callbacks.uint8 = [](void *, uint8_t) {};
    callbacks.uint16 = [](void *, uint16_t) {};
    callbacks.uint32 = [](void *, uint32_t) {};
    callbacks.uint64 = [](void *, uint64_t) {};
    callbacks.negint8 = [](void *, uint8_t) {};
    callbacks.negint16 = [](void *, uint16_t) {};
    callbacks.negint32 = [](void *, uint32_t) {};
    callbacks.negint64 = [](void *, uint64_t) {};
    callbacks.byte_string = [](void *, cbor_data, size_t) {};
    callbacks.byte_string_start = [](void *) {};
    callbacks.string = [](void *, cbor_data, size_t) {};
    callbacks.string_start = [](void *) {};
    callbacks.indef_array_start = [](void *) {};
    callbacks.array_start = [](void *, size_t) {};
    callbacks.indef_map_start = [](void *) {};
    callbacks.map_start = [](void *, size_t) {};
    callbacks.tag = [](void *, uint64_t) {};
    callbacks.float2 = [](void *, float) {};
    callbacks.float4 = [](void *, float) {};
    callbacks.float8 = [](void *, double) {};
    callbacks.undefined = [](void *) {};
    callbacks.null = [](void *) {};
    callbacks.boolean = [](void *, bool) {};
    callbacks.indef_break = [](void *) {};

    // Dummy context for the callbacks
    void *context = nullptr;

    // Call the function-under-test
    cbor_stream_decode(data, size, &callbacks, context);

    return 0;
}