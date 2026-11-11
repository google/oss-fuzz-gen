// This fuzz driver is generated for library gdbm, aiming to fuzz the following functions:
// slist_new_l at gdbmshell.c:2757:1 in gdbmtool.h
// slist_new_s at gdbmshell.c:2742:1 in gdbmtool.h
// slist_new at gdbmshell.c:2751:1 in gdbmtool.h
// kvpair_list at gdbmshell.c:2804:1 in gdbmtool.h
// slist_insert at gdbmshell.c:2778:1 in gdbmtool.h
// slist_free at gdbmshell.c:2766:1 in gdbmtool.h
// slist_free at gdbmshell.c:2766:1 in gdbmtool.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "gdbmtool.h"

static char *create_random_string(const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size + 1);
    if (str) {
        memcpy(str, Data, Size);
        str[Size] = '\0';
    }
    return str;
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a random string
    char *random_string = create_random_string(Data, Size);
    if (!random_string) return 0;

    // Test slist_new_l
    struct slist *list_l = slist_new_l(random_string, Size > 1 ? Data[0] % Size : 0);
    
    // Test slist_new_s
    struct slist *list_s = slist_new_s(random_string);

    // Test slist_new
    struct slist *list_new = slist_new(random_string);

    // Prepare a locus
    struct locus loc = {
        .beg = { .file = random_string, .line = 1, .col = 1 },
        .end = { .file = random_string, .line = 1, .col = 2 }
    };

    // Test kvpair_list
    struct kvpair *kv_list = kvpair_list(&loc, list_l);

    // Test slist_insert
    slist_insert(&list_s, list_new);

    // Cleanup
    slist_free(list_l);
    slist_free(list_s);
    // list_new is already freed as part of list_s
    if (kv_list) free(kv_list);

    free(random_string);
    return 0;
}