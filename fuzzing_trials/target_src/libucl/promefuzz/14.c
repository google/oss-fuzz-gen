// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_emit_full at ucl_emitter.c:700:6 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
// ucl_parser_new at ucl_parser.c:2826:1 in ucl.h
// ucl_parser_add_chunk at ucl_parser.c:3131:6 in ucl.h
// ucl_parser_get_comments at ucl_util.c:3937:1 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
// ucl_object_emit at ucl_emitter.c:667:1 in ucl.h
// ucl_object_emit at ucl_emitter.c:667:1 in ucl.h
// ucl_object_emit at ucl_emitter.c:667:1 in ucl.h
// ucl_object_emit at ucl_emitter.c:667:1 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
// ucl_object_emit_memory_funcs at ucl_emitter_utils.c:419:1 in ucl.h
// ucl_parser_free at ucl_util.c:599:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int append_character(unsigned char c, size_t nchars, void *ud) {
    unsigned char *buf = *(unsigned char **)ud;
    for (size_t i = 0; i < nchars; i++) {
        *buf++ = c;
    }
    *(unsigned char **)ud = buf;
    return 0;
}

static int append_len(unsigned const char *str, size_t len, void *ud) {
    unsigned char *buf = *(unsigned char **)ud;
    memcpy(buf, str, len);
    *(unsigned char **)ud = buf + len;
    return 0;
}

static int append_int(int64_t elt, void *ud) {
    unsigned char *buf = *(unsigned char **)ud;
    int len = snprintf((char *)buf, 20, "%lld", (long long)elt);
    *(unsigned char **)ud = buf + len;
    return 0;
}

static int append_double(double elt, void *ud) {
    unsigned char *buf = *(unsigned char **)ud;
    int len = snprintf((char *)buf, 20, "%f", elt);
    *(unsigned char **)ud = buf + len;
    return 0;
}

static void free_func(void *ud) {
    free(ud);
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct ucl_parser *parser = ucl_parser_new(0);
    if (!parser) return 0;

    ucl_parser_add_chunk(parser, Data, Size);

    const ucl_object_t *comments = ucl_parser_get_comments(parser);
    if (!comments) {
        ucl_parser_free(parser);
        return 0;
    }

    unsigned char *json_output = ucl_object_emit(comments, UCL_EMIT_JSON);
    if (json_output) {
        free(json_output);
    }

    unsigned char *config_output = ucl_object_emit(comments, UCL_EMIT_CONFIG);
    if (config_output) {
        free(config_output);
    }

    unsigned char *yaml_output = ucl_object_emit(comments, UCL_EMIT_YAML);
    if (yaml_output) {
        free(yaml_output);
    }

    unsigned char *msgpack_output = ucl_object_emit(comments, UCL_EMIT_MSGPACK);
    if (msgpack_output) {
        free(msgpack_output);
    }

    void *mem = malloc(1024);
    if (!mem) {
        ucl_parser_free(parser);
        return 0;
    }

    struct ucl_emitter_functions *emitter = ucl_object_emit_memory_funcs(&mem);
    if (!emitter) {
        free(mem);
        ucl_parser_free(parser);
        return 0;
    }

    emitter->ucl_emitter_append_character = append_character;
    emitter->ucl_emitter_append_len = append_len;
    emitter->ucl_emitter_append_int = append_int;
    emitter->ucl_emitter_append_double = append_double;
    emitter->ucl_emitter_free_func = free_func;
    emitter->ud = mem;

    bool success = ucl_object_emit_full(comments, UCL_EMIT_JSON, emitter, comments);
    if (success) {
        free(mem);
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
