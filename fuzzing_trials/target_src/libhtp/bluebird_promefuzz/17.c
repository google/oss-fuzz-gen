#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "htp/htp.h"
#include "htp/htp.h"
#include "htp/htp.h"
#include "/src/libhtp/htp/htp_connection_parser.h"

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    htp_cfg_t *cfg = htp_config_create();
    if (cfg == NULL) {
        return 0;
    }

    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) {
        htp_config_destroy(cfg);
        return 0;
    }

    htp_connp_set_user_data(connp, (void *)Data);

    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);

    htp_connp_open(connp, "127.0.0.1", 80, "127.0.0.1", 8080, &timestamp);
    htp_connp_open(connp, "127.0.0.1", 80, "127.0.0.1", 8080, &timestamp);

    htp_connp_req_data(connp, &timestamp, Data, Size);
    htp_connp_req_data_consumed(connp);

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of htp_connp_res_data
    htp_connp_res_data(connp, &timestamp, NULL, Size);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    htp_connp_res_data(connp, &timestamp, Data, Size);
    htp_connp_res_data_consumed(connp);

    htp_connp_req_data(connp, &timestamp, Data, Size);
    htp_connp_res_data(connp, &timestamp, Data, Size);

    htp_connp_close(connp, &timestamp);

    htp_connp_destroy_all(connp);
    htp_config_destroy(cfg);
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
