// This fuzz driver is generated for library json-c, aiming to fuzz the following functions:
// json_object_to_fd at json_util.c:187:5 in json_util.h
// json_object_set_boolean at json_object.c:692:5 in json_object.h
// json_object_from_fd at json_util.c:81:21 in json_util.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_to_file at json_util.c:230:5 in json_util.h
// json_object_new_boolean at json_object.c:663:21 in json_object.h
// json_object_object_add_ex at json_object.c:557:5 in json_object.h
// json_object_from_fd_ex at json_util.c:85:21 in json_util.h
// json_object_put at json_object.c:272:5 in json_object.h
// json_object_new_object at json_object.c:530:21 in json_object.h
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
}

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

static void fuzz_json_object_to_fd(struct json_object *obj) {
    int fd = open("./dummy_file", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd != -1) {
        json_object_to_fd(fd, obj, JSON_C_TO_STRING_PLAIN);
        close(fd);
    }
}

static void fuzz_json_object_set_boolean(struct json_object *obj) {
    json_bool new_value = rand() % 2;
    json_object_set_boolean(obj, new_value);
}

static void fuzz_json_object_from_fd() {
    int fd = open("./dummy_file", O_RDONLY);
    if (fd != -1) {
        struct json_object *obj = json_object_from_fd(fd);
        json_object_put(obj);
        close(fd);
    }
}

static void fuzz_json_object_to_file(struct json_object *obj) {
    json_object_to_file("./dummy_file", obj);
}

static void fuzz_json_object_object_add_ex(struct json_object *obj) {
    struct json_object *val = json_object_new_boolean(rand() % 2);
    json_object_object_add_ex(obj, "key", val, JSON_C_OBJECT_ADD_KEY_IS_NEW);
}

static void fuzz_json_object_from_fd_ex() {
    int fd = open("./dummy_file", O_RDONLY);
    if (fd != -1) {
        lseek(fd, 0, SEEK_SET);
        struct json_object *obj = json_object_from_fd_ex(fd, -1);
        json_object_put(obj);
        close(fd);
    }
}

extern "C" int LLVMFuzzerTestOneInput_131(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    struct json_object *obj = json_object_new_object();
    if (!obj) return 0;

    // Write Data to dummy file
    int fd = open("./dummy_file", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd != -1) {
        write(fd, Data, Size);
        close(fd);
    }

    fuzz_json_object_to_fd(obj);
    fuzz_json_object_set_boolean(obj);
    fuzz_json_object_from_fd();
    fuzz_json_object_to_file(obj);
    fuzz_json_object_object_add_ex(obj);
    fuzz_json_object_from_fd_ex();

    json_object_put(obj);
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

        LLVMFuzzerTestOneInput_131(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    