// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_encode_negint32 at encoding.c:49:8 in encoding.h
// cbor_encode_negint at encoding.c:59:8 in encoding.h
// cbor_encode_negint64 at encoding.c:54:8 in encoding.h
// cbor_serialize_negint at serialization.c:211:8 in serialization.h
// cbor_encode_negint8 at encoding.c:39:8 in encoding.h
// cbor_encode_negint16 at encoding.c:44:8 in encoding.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
extern "C" {
#include "cbor.h"
#include "cbor.h"
}

#include <cstddef>
#include <cstdint>
#include <cstring>

static void fuzz_cbor_encode_negint32(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    uint32_t value;
    memcpy(&value, Data, sizeof(uint32_t));
    unsigned char buffer[10]; // Assume buffer size of 10 for testing
    cbor_encode_negint32(value, buffer, sizeof(buffer));
}

static void fuzz_cbor_encode_negint(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return;

    uint64_t value;
    memcpy(&value, Data, sizeof(uint64_t));
    unsigned char buffer[10]; // Assume buffer size of 10 for testing
    cbor_encode_negint(value, buffer, sizeof(buffer));
}

static void fuzz_cbor_encode_negint64(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return;

    uint64_t value;
    memcpy(&value, Data, sizeof(uint64_t));
    unsigned char buffer[10]; // Assume buffer size of 10 for testing
    cbor_encode_negint64(value, buffer, sizeof(buffer));
}

static void fuzz_cbor_serialize_negint(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    cbor_item_t item;
    item.type = CBOR_TYPE_NEGINT;
    item.data = const_cast<unsigned char*>(Data);
    unsigned char buffer[10]; // Assume buffer size of 10 for testing
    cbor_serialize_negint(&item, buffer, sizeof(buffer));
}

static void fuzz_cbor_encode_negint8(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint8_t)) return;

    uint8_t value;
    memcpy(&value, Data, sizeof(uint8_t));
    unsigned char buffer[10]; // Assume buffer size of 10 for testing
    cbor_encode_negint8(value, buffer, sizeof(buffer));
}

static void fuzz_cbor_encode_negint16(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint16_t)) return;

    uint16_t value;
    memcpy(&value, Data, sizeof(uint16_t));
    unsigned char buffer[10]; // Assume buffer size of 10 for testing
    cbor_encode_negint16(value, buffer, sizeof(buffer));
}

extern "C" int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    fuzz_cbor_encode_negint32(Data, Size);
    fuzz_cbor_encode_negint(Data, Size);
    fuzz_cbor_encode_negint64(Data, Size);
    fuzz_cbor_serialize_negint(Data, Size);
    fuzz_cbor_encode_negint8(Data, Size);
    fuzz_cbor_encode_negint16(Data, Size);

    return 0;
}