/*
  Fuzz NMB parse_packet
  Copyright (C) Catalyst IT 2020

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../../source3/include/includes.h"
#include "fuzzing/fuzzing.h"
#include "libsmb/libsmb.h"
#include "libsmb/nmblib.h"

#define PORT 138
#define MAX_LENGTH (1024 * 1024)
char buf[MAX_LENGTH + 1];

int LLVMFuzzerTestOneInput(const uint8_t *input, size_t len) {
  struct packet_struct *p = NULL;
  struct in_addr ip = {
      0x0100007f /* 127.0.0.1 */
  };

  p = parse_packet((char *)input, len, NMB_PACKET, ip, PORT);
  /*
   * We expect NULL (parse failure) most of the time.
   *
   * When it is not NULL we want to ensure the parsed packet is
   * reasonably sound.
   */

  if (p != NULL) {
    struct nmb_packet *nmb = &p->packet.nmb;
    pull_ascii_nstring(buf, MAX_LENGTH, nmb->question.question_name.name);
    build_packet(buf, MAX_LENGTH, p);
    free_packet(p);
  }
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }
