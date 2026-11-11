// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_parser_new at ucl_parser.c:2826:1 in ucl.h
// ucl_parser_add_chunk at ucl_parser.c:3131:6 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
// ucl_parser_get_comments at ucl_util.c:3937:1 in ucl.h
// ucl_parser_get_object at ucl_util.c:590:1 in ucl.h
// ucl_object_emit_file_funcs at ucl_emitter_utils.c:442:1 in ucl.h
// ucl_object_emit_fd_funcs at ucl_emitter_utils.c:461:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    // Initialize parser
    struct ucl_parser *parser = ucl_parser_new(0);
    if (!parser) {
        return 0;
    }

    // Parse the input data
    if (!ucl_parser_add_chunk(parser, Data, Size)) {
        ucl_parser_free(parser);
        return 0;
    }

    // 1. Invoke ucl_parser_get_comments
    const ucl_object_t *comments = ucl_parser_get_comments(parser);

    // 2. Invoke ucl_parser_get_object
    ucl_object_t *top_object = ucl_parser_get_object(parser);

    // 3. Invoke ucl_object_emit_file_funcs
    FILE *dummy_file = fopen("./dummy_file", "w+");
    if (dummy_file) {
        struct ucl_emitter_functions *file_funcs = ucl_object_emit_file_funcs(dummy_file);
        if (file_funcs) {
            // Use file_funcs if needed
            if (file_funcs->ucl_emitter_free_func) {
                file_funcs->ucl_emitter_free_func(file_funcs->ud);
            }
            free(file_funcs);
        }
        fclose(dummy_file);
    }

    // 4. Invoke ucl_object_emit_fd_funcs
    int fd = open("./dummy_file", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd != -1) {
        struct ucl_emitter_functions *fd_funcs = ucl_object_emit_fd_funcs(fd);
        if (fd_funcs) {
            // Use fd_funcs if needed
            if (fd_funcs->ucl_emitter_free_func) {
                fd_funcs->ucl_emitter_free_func(fd_funcs->ud);
            }
            free(fd_funcs);
        }
        close(fd);
    }

    // Cleanup
    if (top_object) {
        ucl_object_unref(top_object);
    }
    ucl_parser_free(parser);

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
