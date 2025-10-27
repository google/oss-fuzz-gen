/*
   Fuzzing for ldap_decode.
   Copyright (C) Michael Hanselmann 2019

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

#include "fuzzing/fuzzing.h"
#include "includes.h"
#include "lib/util/asn1.h"
#include "libcli/ldap/ldap_message.h"
#include "libcli/ldap/ldap_proto.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) { return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  TALLOC_CTX *mem_ctx = talloc_init(__FUNCTION__);
  struct asn1_data *asn1;
  struct ldap_message *ldap_msg;
  struct ldap_request_limits limits = {/*
                                        * The default size is currently 256000 bytes
                                        */
                                       .max_search_size = 256000};
  NTSTATUS status;

  /*
   * Need to limit the max parse tree depth to 250 to prevent
   * ASAN detecting stack overflows.
   */
  asn1 = asn1_init(mem_ctx, 250);
  if (!asn1) {
    goto out;
  }

  asn1_load_nocopy(asn1, buf, len);

  ldap_msg = talloc(mem_ctx, struct ldap_message);
  if (!ldap_msg) {
    goto out;
  }

  status = ldap_decode(asn1, &limits, samba_ldap_control_handlers(), ldap_msg);

out:
  talloc_free(mem_ctx);

  return 0;
}
