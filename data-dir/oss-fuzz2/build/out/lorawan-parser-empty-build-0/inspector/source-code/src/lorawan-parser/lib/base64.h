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


#ifndef _BASE64_H
#define _BASE64_H

/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

#include <stdint.h>        /* C99 types */

/* -------------------------------------------------------------------------- */
/* --- PUBLIC FUNCTIONS PROTOTYPES ------------------------------------------ */

/**
@brief Encode binary data in Base64 string (no padding)
@param in pointer to a table of binary data
@param size number of bytes to be encoded to base64
@param out pointer to a string where the function will output encoded data
@param max_len max length of the out string (including null char)
@return >=0 length of the resulting string (w/o null char), -1 for error
*/
int bin_to_b64_nopad(const uint8_t * in, int size, char * out, int max_len);

/**
@brief Decode Base64 string to binary data (no padding)
@param in string containing only base64 valid characters
@param size number of characters to be decoded from base64 (w/o null char)
@param out pointer to a data buffer where the function will output decoded data
@param out_max_len usable size of the output data buffer
@return >=0 number of bytes written to the data buffer, -1 for error
*/
int b64_to_bin_nopad(const char * in, int size, uint8_t * out, int max_len);

/* === derivative functions === */

/**
@brief Encode binary data in Base64 string (with added padding)
*/
int bin_to_b64(const uint8_t * in, int size, char * out, int max_len);

/**
@brief Decode Base64 string to binary data (remove padding if necessary)
*/
int b64_to_bin(const char * in, int size, uint8_t * out, int max_len);

#endif

/* --- EOF ------------------------------------------------------------------ */
