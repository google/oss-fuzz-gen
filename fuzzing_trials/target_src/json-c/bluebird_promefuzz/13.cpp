#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "/src/json-c/json_util.h"
#include "/src/json-c/json_object.h"
#include <fcntl.h>
#include <unistd.h>
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Ensure Data is null-terminated before passing to json_tokener_parse
    std::vector<uint8_t> data_with_null(Data, Data + Size);
    data_with_null.push_back('\0');

    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function json_tokener_parse with json_object_new_string
    struct json_object *obj = json_object_new_string((const char*)data_with_null.data());
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    if (!obj) {
        return 0;
    }

    // Test json_object_to_file_ext

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from json_tokener_parse to json_object_to_fd
    int32_t ret_json_object_get_int_wyrcn = json_object_get_int(NULL);
    if (ret_json_object_get_int_wyrcn < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    double ret_json_object_get_double_aysou = json_object_get_double(obj);
    if (ret_json_object_get_double_aysou < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!obj) {
    	return 0;
    }
    int ret_json_object_to_fd_kfxnh = json_object_to_fd((int )ret_json_object_get_int_wyrcn, obj, (int )ret_json_object_get_double_aysou);
    if (ret_json_object_to_fd_kfxnh < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    const char *filename = "./dummy_file";
    int flags = 0;
    int ret = json_object_to_file_ext(filename, obj, flags);
    if (ret == -1) {
        std::cerr << "json_object_to_file_ext failed: " << json_util_get_last_err() << std::endl;
    }

    // Test json_object_to_fd
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd != -1) {
        ret = json_object_to_fd(fd, obj, flags);
        if (ret == -1) {
            std::cerr << "json_object_to_fd failed: " << json_util_get_last_err() << std::endl;
        }
        close(fd);
    }

    // Test json_object_object_get_ex
    struct json_object *value = nullptr;
    const char *key = "key";
    int found = json_object_object_get_ex(obj, key, &value);
    if (found) {
        // Do something with value if needed
    }

    // Test json_object_to_json_string_ext
    const char *json_str_ext = json_object_to_json_string_ext(obj, flags);
    if (json_str_ext) {
        // Do something with json_str_ext if needed
    }

    // Test json_object_to_json_string_length
    size_t length = 0;
    const char *json_str_length = json_object_to_json_string_length(obj, flags, &length);
    if (json_str_length) {
        // Do something with json_str_length if needed
    }

    // Test json_object_to_json_string
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function json_object_to_json_string with json_object_get_string
    const char *json_str = json_object_get_string(obj);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    if (json_str) {
        // Do something with json_str if needed
    }

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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
