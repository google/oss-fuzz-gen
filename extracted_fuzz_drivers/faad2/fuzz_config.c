/*
** FAAD2 - Freeware Advanced Audio (AAC) Decoder including SBR decoding
** Copyright (C) 2003-2005 M. Bakker, Nero AG, http://www.nero.com
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
** Any non-GPL usage of this software or parts of this software is strictly
** forbidden.
**
** The "appropriate copyright message" mentioned in section 2c of the GPLv2
** must read: "Code from FAAD2 is copyright (c) Nero AG, www.nero.com"
**
** Commercial non-GPL licensing of this software is possible.
** For more info contact Nero AG through Mpeg4AAClicense@nero.com.
**/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "neaacdec.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  long sink = 0;

  if (size < 1)
    return 0;
  unsigned char error_code = *(data++);
  size -= 1;

  char *error_message = NeAACDecGetErrorMessage(error_code);
  if (error_message)
    sink += strlen(error_message);

  char *id = NULL;
  char *copyright = NULL;
  sink += NeAACDecGetVersion(&id, &copyright);
  sink += strlen(id);
  sink += strlen(copyright);

  sink += (long)NeAACDecGetCapabilities();

  unsigned char *non_const_data = (unsigned char *)malloc(size);
  memcpy(non_const_data, data, size);
  mp4AudioSpecificConfig mp4ASC;

  NeAACDecAudioSpecificConfig(non_const_data, (unsigned long)size, &mp4ASC);
  free(non_const_data);

  return (sink < 0) ? sink : 0;
}
