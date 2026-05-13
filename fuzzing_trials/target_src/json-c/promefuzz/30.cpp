// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// json_object_new_object at json_object.c:530:21 in json_object.h
// json_object_set_string at json_object.c:1443:5 in json_object.h
// json_object_to_file_ext at json_util.c:163:5 in json_util.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_new_object at json_object.c:530:21 in json_object.h
// json_object_set_string at json_object.c:1443:5 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_to_fd at json_util.c:187:5 in json_util.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_new_object at json_object.c:530:21 in json_object.h
// json_object_set_string at json_object.c:1443:5 in json_object.h
// json_object_object_get_ex at json_object.c:617:11 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_new_object at json_object.c:530:21 in json_object.h
// json_object_set_string at json_object.c:1443:5 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_new_object at json_object.c:530:21 in json_object.h
// json_object_set_string at json_object.c:1443:5 in json_object.h
// json_object_to_file at json_util.c:230:5 in json_util.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_new_object at json_object.c:530:21 in json_object.h
// json_object_set_string at json_object.c:1443:5 in json_object.h
// json_object_to_json_string at json_object.c:441:13 in json_object.h
// json_object_put at json_object.c:272:5 in json_object.h
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
#include <json_util.h>
#include <json_object.h>
#include <fcntl.h>
#include <unistd.h>
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static void fuzz_json_object_to_file_ext(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    struct json_object *obj = json_object_new_object();
    if (!obj) return;

    std::string str(reinterpret_cast<const char *>(Data), Size);
    json_object_set_string(obj, str.c_str());
    json_object_to_file_ext("./dummy_file", obj, JSON_C_TO_STRING_PLAIN);
    json_object_put(obj);
}

static void fuzz_json_object_to_fd(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    struct json_object *obj = json_object_new_object();
    if (!obj) return;

    std::string str(reinterpret_cast<const char *>(Data), Size);
    json_object_set_string(obj, str.c_str());
    int fd = open("./dummy_file", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        json_object_put(obj);
        return;
    }

    json_object_to_fd(fd, obj, JSON_C_TO_STRING_PLAIN);
    close(fd);
    json_object_put(obj);
}

static void fuzz_json_object_object_get_ex(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    struct json_object *obj = json_object_new_object();
    if (!obj) return;

    std::string str(reinterpret_cast<const char *>(Data), Size);
    json_object_set_string(obj, str.c_str());
    struct json_object *value;
    json_object_object_get_ex(obj, str.c_str(), &value);
    json_object_put(obj);
}

static void fuzz_json_object_set_string(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    struct json_object *obj = json_object_new_object();
    if (!obj) return;

    std::string str(reinterpret_cast<const char *>(Data), Size);
    json_object_set_string(obj, str.c_str());
    json_object_put(obj);
}

static void fuzz_json_object_to_file(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    struct json_object *obj = json_object_new_object();
    if (!obj) return;

    std::string str(reinterpret_cast<const char *>(Data), Size);
    json_object_set_string(obj, str.c_str());
    json_object_to_file("./dummy_file", obj);
    json_object_put(obj);
}

static void fuzz_json_object_to_json_string(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    struct json_object *obj = json_object_new_object();
    if (!obj) return;

    std::string str(reinterpret_cast<const char *>(Data), Size);
    json_object_set_string(obj, str.c_str());
    const char *json_str = json_object_to_json_string(obj);
    (void)json_str; // Suppress unused variable warning
    json_object_put(obj);
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    fuzz_json_object_to_file_ext(Data, Size);
    fuzz_json_object_to_fd(Data, Size);
    fuzz_json_object_object_get_ex(Data, Size);
    fuzz_json_object_set_string(Data, Size);
    fuzz_json_object_to_file(Data, Size);
    fuzz_json_object_to_json_string(Data, Size);
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
    