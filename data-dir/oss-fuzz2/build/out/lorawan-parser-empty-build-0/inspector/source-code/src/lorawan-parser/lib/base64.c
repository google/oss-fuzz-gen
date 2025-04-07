/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
    Base64 encoding & decoding library

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Sylvain Miermont
*/


/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "base64.h"

/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof((a)[0]))
#define CRIT(a)             fprintf(stderr, "\nCRITICAL file:%s line:%u msg:%s\n", __FILE__, __LINE__,a);exit(EXIT_FAILURE)

//#define DEBUG(args...)    fprintf(stderr,"debug: " args) /* diagnostic message that is destined to the user */
#define DEBUG(args...)

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE MODULE-WIDE VARIABLES ---------------------------------------- */

static char code_62 = '+';    /* RFC 1421 standard character for code 62 */
static char code_63 = '/';    /* RFC 1421 standard character for code 63 */
static char code_pad = '=';    /* RFC 1421 padding character if padding */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DECLARATION ---------------------------------------- */

/**
@brief Convert a code in the range 0-63 to an ASCII character
*/
char code_to_char(uint8_t x);

/**
@brief Convert an ASCII character to a code in the range 0-63
*/
uint8_t char_to_code(char x);

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */

char code_to_char(uint8_t x) {
    if (x <= 25) {
        return 'A' + x;
    } else if ((x >= 26) && (x <= 51)) {
        return 'a' + (x-26);
    } else if ((x >= 52) && (x <= 61)) {
        return '0' + (x-52);
    } else if (x == 62) {
        return code_62;
    } else if (x == 63) {
        return code_63;
    } else {
        DEBUG("ERROR: %i IS OUT OF RANGE 0-63 FOR BASE64 ENCODING\n", x);
        exit(EXIT_FAILURE);
    } //TODO: improve error management
}

uint8_t char_to_code(char x) {
    if ((x >= 'A') && (x <= 'Z')) {
        return (uint8_t)x - (uint8_t)'A';
    } else if ((x >= 'a') && (x <= 'z')) {
        return (uint8_t)x - (uint8_t)'a' + 26;
    } else if ((x >= '0') && (x <= '9')) {
        return (uint8_t)x - (uint8_t)'0' + 52;
    } else if (x == code_62) {
        return 62;
    } else if (x == code_63) {
        return 63;
    } else {
        DEBUG("ERROR: %c (0x%x) IS INVALID CHARACTER FOR BASE64 DECODING\n", x, x);
        exit(EXIT_FAILURE);
    } //TODO: improve error management
}

/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS DEFINITION ------------------------------------------ */

int bin_to_b64_nopad(const uint8_t * in, int size, char * out, int max_len) {
    int i;
    int result_len; /* size of the result */
    int full_blocks; /* number of 3 unsigned chars / 4 characters blocks */
    int last_bytes; /* number of unsigned chars <3 in the last block */
    int last_chars; /* number of characters <4 in the last block */
    uint32_t b;

    /* check input values */
    if ((out == NULL) || (in == NULL)) {
        DEBUG("ERROR: NULL POINTER AS OUTPUT IN BIN_TO_B64\n");
        return -1;
    }
    if (size == 0) {
        *out = 0; /* null string */
        return 0;
    }

    /* calculate the number of base64 'blocks' */
    full_blocks = size / 3;
    last_bytes = size % 3;
    switch (last_bytes) {
        case 0: /* no byte left to encode */
            last_chars = 0;
            break;
        case 1: /* 1 byte left to encode -> +2 chars */
            last_chars = 2;
            break;
        case 2: /* 2 bytes left to encode -> +3 chars */
            last_chars = 3;
            break;
        default:
            CRIT("switch default that should not be possible");
    }

    /* check if output buffer is big enough */
    result_len = (4*full_blocks) + last_chars;
    if (max_len < (result_len + 1)) { /* 1 char added for string terminator */
        DEBUG("ERROR: OUTPUT BUFFER TOO SMALL IN BIN_TO_B64\n");
        return -1;
    }

    /* process all the full blocks */
    for (i=0; i < full_blocks; ++i) {
        b  = (0xFF & in[3*i]    ) << 16;
        b |= (0xFF & in[3*i + 1]) << 8;
        b |=  0xFF & in[3*i + 2];
        out[4*i + 0] = code_to_char((b >> 18) & 0x3F);
        out[4*i + 1] = code_to_char((b >> 12) & 0x3F);
        out[4*i + 2] = code_to_char((b >> 6 ) & 0x3F);
        out[4*i + 3] = code_to_char( b        & 0x3F);
    }

    /* process the last 'partial' block and terminate string */
    i = full_blocks;
    if (last_chars == 0) {
        out[4*i] =  0; /* null character to terminate string */
    } else if (last_chars == 2) {
        b  = (0xFF & in[3*i]    ) << 16;
        out[4*i + 0] = code_to_char((b >> 18) & 0x3F);
        out[4*i + 1] = code_to_char((b >> 12) & 0x3F);
        out[4*i + 2] =  0; /* null character to terminate string */
    } else if (last_chars == 3) {
        b  = (0xFF & in[3*i]    ) << 16;
        b |= (0xFF & in[3*i + 1]) << 8;
        out[4*i + 0] = code_to_char((b >> 18) & 0x3F);
        out[4*i + 1] = code_to_char((b >> 12) & 0x3F);
        out[4*i + 2] = code_to_char((b >> 6 ) & 0x3F);
        out[4*i + 3] = 0; /* null character to terminate string */
    }

    return result_len;
}

int b64_to_bin_nopad(const char * in, int size, uint8_t * out, int max_len) {
    int i;
    int result_len; /* size of the result */
    int full_blocks; /* number of 3 unsigned chars / 4 characters blocks */
    int last_chars; /* number of characters <4 in the last block */
    int last_bytes; /* number of unsigned chars <3 in the last block */
    uint32_t b;
    ;

    /* check input values */
    if ((out == NULL) || (in == NULL)) {
        DEBUG("ERROR: NULL POINTER AS OUTPUT OR INPUT IN B64_TO_BIN\n");
        return -1;
    }
    if (size == 0) {
        return 0;
    }

    /* calculate the number of base64 'blocks' */
    full_blocks = size / 4;
    last_chars = size % 4;
    switch (last_chars) {
        case 0: /* no char left to decode */
            last_bytes = 0;
            break;
        case 1: /* only 1 char left is an error */
            DEBUG("ERROR: ONLY ONE CHAR LEFT IN B64_TO_BIN\n");
            return -1;
        case 2: /* 2 chars left to decode -> +1 byte */
            last_bytes = 1;
            break;
        case 3: /* 3 chars left to decode -> +2 bytes */
            last_bytes = 2;
            break;
        default:
            CRIT("switch default that should not be possible");
    }

    /* check if output buffer is big enough */
    result_len = (3*full_blocks) + last_bytes;
    if (max_len < result_len) {
        DEBUG("ERROR: OUTPUT BUFFER TOO SMALL IN B64_TO_BIN\n");
        return -1;
    }

    /* process all the full blocks */
    for (i=0; i < full_blocks; ++i) {
        b  = (0x3F & char_to_code(in[4*i]    )) << 18;
        b |= (0x3F & char_to_code(in[4*i + 1])) << 12;
        b |= (0x3F & char_to_code(in[4*i + 2])) << 6;
        b |=  0x3F & char_to_code(in[4*i + 3]);
        out[3*i + 0] = (b >> 16) & 0xFF;
        out[3*i + 1] = (b >> 8 ) & 0xFF;
        out[3*i + 2] =  b        & 0xFF;
    }

    /* process the last 'partial' block */
    i = full_blocks;
    if (last_bytes == 1) {
        b  = (0x3F & char_to_code(in[4*i]    )) << 18;
        b |= (0x3F & char_to_code(in[4*i + 1])) << 12;
        out[3*i + 0] = (b >> 16) & 0xFF;
        if (((b >> 12) & 0x0F) != 0) {
            DEBUG("WARNING: last character contains unusable bits\n");
        }
    } else if (last_bytes == 2) {
        b  = (0x3F & char_to_code(in[4*i]    )) << 18;
        b |= (0x3F & char_to_code(in[4*i + 1])) << 12;
        b |= (0x3F & char_to_code(in[4*i + 2])) << 6;
        out[3*i + 0] = (b >> 16) & 0xFF;
        out[3*i + 1] = (b >> 8 ) & 0xFF;
        if (((b >> 6) & 0x03) != 0) {
            DEBUG("WARNING: last character contains unusable bits\n");
        }
    }

    return result_len;
}

int bin_to_b64(const uint8_t * in, int size, char * out, int max_len) {
    int ret;

    ret = bin_to_b64_nopad(in, size, out, max_len);

    if (ret == -1) {
        return -1;
    }
    switch (ret%4) {
        case 0: /* nothing to do */
            return ret;
        case 1:
            DEBUG("ERROR: INVALID UNPADDED BASE64 STRING\n");
            return -1;
        case 2: /* 2 chars in last block, must add 2 padding char */
            if (max_len > (ret + 2 + 1)) {
                out[ret] = code_pad;
                out[ret+1] = code_pad;
                out[ret+2] = 0;
                return ret+2;
            } else {
                DEBUG("ERROR: not enough room to add padding in bin_to_b64\n");
                return -1;
            }
        case 3: /* 3 chars in last block, must add 1 padding char */
            if (max_len > (ret + 1 + 1)) {
                out[ret] = code_pad;
                out[ret+1] = 0;
                return ret+1;
            } else {
                DEBUG("ERROR: not enough room to add padding in bin_to_b64\n");
                return -1;
            }
        default:
            CRIT("switch default that should not be possible");
    }
}

int b64_to_bin(const char * in, int size, uint8_t * out, int max_len) {
    if (in == NULL) {
        DEBUG("ERROR: NULL POINTER AS OUTPUT OR INPUT IN B64_TO_BIN\n");
        return -1;
    }
    if ((size%4 == 0) && (size >= 4)) { /* potentially padded Base64 */
        if (in[size-2] == code_pad) { /* 2 padding char to ignore */
            return b64_to_bin_nopad(in, size-2, out, max_len);
        } else if (in[size-1] == code_pad) { /* 1 padding char to ignore */
            return b64_to_bin_nopad(in, size-1, out, max_len);
        } else { /* no padding to ignore */
            return b64_to_bin_nopad(in, size, out, max_len);
        }
    } else { /* treat as unpadded Base64 */
        return b64_to_bin_nopad(in, size, out, max_len);
    }
}


/* --- EOF ------------------------------------------------------------------ */
