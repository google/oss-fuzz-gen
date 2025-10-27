#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "libyang.h"

int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len) {
  struct ly_ctx *ctx = NULL;
  static bool log = false;
  const char *schema_a = "module defs {namespace urn:tests:defs;prefix d;yang-version 1.1;"
                         "identity crypto-alg; identity interface-type; identity ethernet {base interface-type;}"
                         "identity fast-ethernet {base ethernet;}}";
  const char *schema_b = "module types {namespace urn:tests:types;prefix t;yang-version 1.1; import defs {prefix defs;}"
                         "feature f; identity gigabit-ethernet { base defs:ethernet;}"
                         "container cont {leaf leaftarget {type empty;}"
                         "list listtarget {key id; max-elements 5;leaf id {type uint8;} leaf value {type string;}}"
                         "leaf-list leaflisttarget {type uint8; max-elements 5;}}"
                         "list list {key id; leaf id {type string;} leaf value {type string;} leaf-list targets {type string;}}"
                         "list list2 {key \"id value\"; leaf id {type string;} leaf value {type string;}}"
                         "list list_inst {key id; leaf id {type instance-identifier {require-instance true;}} leaf value {type string;}}"
                         "list list_ident {key id; leaf id {type identityref {base defs:interface-type;}} leaf value {type string;}}"
                         "leaf-list leaflisttarget {type string;}"
                         "leaf binary {type binary {length 5 {error-message \"This base64 value must be of length 5.\";}}}"
                         "leaf binary-norestr {type binary;}"
                         "leaf int8 {type int8 {range 10..20;}}"
                         "leaf uint8 {type uint8 {range 150..200;}}"
                         "leaf int16 {type int16 {range -20..-10;}}"
                         "leaf uint16 {type uint16 {range 150..200;}}"
                         "leaf int32 {type int32;}"
                         "leaf uint32 {type uint32;}"
                         "leaf int64 {type int64;}"
                         "leaf uint64 {type uint64;}"
                         "leaf bits {type bits {bit zero; bit one {if-feature f;} bit two;}}"
                         "leaf enums {type enumeration {enum white; enum yellow {if-feature f;}}}"
                         "leaf dec64 {type decimal64 {fraction-digits 1; range 1.5..10;}}"
                         "leaf dec64-norestr {type decimal64 {fraction-digits 18;}}"
                         "leaf str {type string {length 8..10; pattern '[a-z ]*';}}"
                         "leaf str-norestr {type string;}"
                         "leaf str-utf8 {type string{length 2..5; pattern '€*';}}"
                         "leaf bool {type boolean;}"
                         "leaf empty {type empty;}"
                         "leaf ident {type identityref {base defs:interface-type;}}"
                         "leaf inst {type instance-identifier {require-instance true;}}"
                         "leaf inst-noreq {type instance-identifier {require-instance false;}}"
                         "leaf lref {type leafref {path /leaflisttarget; require-instance true;}}"
                         "leaf lref2 {type leafref {path \"../list[id = current()/../str-norestr]/targets\"; require-instance true;}}"
                         "leaf un1 {type union {"
                         "type leafref {path /int8; require-instance true;}"
                         "type union { type identityref {base defs:interface-type;} type instance-identifier {require-instance true;} }"
                         "type string {length 1..20;}}}}";
  char *data = NULL;
  struct lyd_node *tree = NULL;
  LY_ERR err;

  if (!log) {
    ly_log_options(0);
    log = true;
  }

  err = ly_ctx_new(NULL, 0, &ctx);
  if (err != LY_SUCCESS) {
    fprintf(stderr, "Failed to create context\n");
    exit(EXIT_FAILURE);
  }

  lys_parse_mem(ctx, schema_a, LYS_IN_YANG, NULL);
  lys_parse_mem(ctx, schema_b, LYS_IN_YANG, NULL);

  data = malloc(len + 1);
  if (data == NULL) {
    return 0;
  }
  memcpy(data, buf, len);
  data[len] = 0;

  lyd_parse_data_mem(ctx, data, LYD_JSON, 0, LYD_VALIDATE_PRESENT, &tree);
  lyd_free_all(tree);
  ly_ctx_destroy(ctx);

  free(data);

  return 0;
}
