// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_definite_map at maps.c:21:14 in maps.h
// cbor_new_indefinite_map at maps.c:37:14 in maps.h
// cbor_new_definite_map at maps.c:21:14 in maps.h
// _cbor_map_add_key at maps.c:52:6 in maps.h
// cbor_new_definite_map at maps.c:21:14 in maps.h
// cbor_new_definite_map at maps.c:21:14 in maps.h
// cbor_map_add at maps.c:107:6 in maps.h
// cbor_map_is_definite at maps.c:113:6 in maps.h
// cbor_map_handle at maps.c:122:19 in maps.h
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
}

#include <cstddef>
#include <cstdint>
#include <cstdlib>

static cbor_item_t* create_random_map(const uint8_t *Data, size_t Size) {
    if (Size % 2 == 0) {
        return cbor_new_definite_map(Size / 2);
    } else {
        return cbor_new_indefinite_map();
    }
}

static bool add_random_key(cbor_item_t* map, const uint8_t *Data, size_t Size) {
    if (Size == 0) return false;
    cbor_item_t* key = cbor_new_definite_map(1);  // Dummy key
    if (!key) return false;
    bool result = _cbor_map_add_key(map, key);
    // Normally, you would decrease the reference count of key here
    return result;
}

static bool add_random_pair(cbor_item_t* map, const uint8_t *Data, size_t Size) {
    if (Size < 2) return false;
    cbor_item_t* key = cbor_new_definite_map(1);  // Dummy key
    cbor_item_t* value = cbor_new_definite_map(1);  // Dummy value
    if (!key || !value) return false;
    cbor_pair pair = { key, value };
    bool result = cbor_map_add(map, pair);
    // Normally, you would decrease the reference count of key and value here
    return result;
}

extern "C" int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    cbor_item_t* map = create_random_map(Data, Size);
    if (!map) return 0;

    bool is_definite = cbor_map_is_definite(map);
    if (is_definite) {
        add_random_key(map, Data, Size);
    } else {
        add_random_pair(map, Data, Size);
    }

    cbor_pair* pairs = cbor_map_handle(map);
    // Normally, you would do something with `pairs` here

    // Cleanup
    // Normally, you would decrease the reference count of map here

    return 0;
}