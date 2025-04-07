#ifndef __LW_LOG_H
#define __LW_LOG_H

#include "lw.h"

typedef enum{
    LW_MACCMD_PORT0,
    LW_MACCMD_FOPTS,
}lw_maccmd_type_t;

void lw_log_all_node();
int lw_log_maccmd(uint8_t mac_header, lw_maccmd_type_t type, uint8_t *opts, int len);
void lw_log(lw_frame_t *frame, uint8_t *msg, int len);
void lw_log_rxpkt(lw_rxpkt_t *rxpkt);
void lw_log_txpkt(lw_txpkt_t *txpkt);
void lw_log_frame(lw_frame_t *frame, void *pkt);

#endif
