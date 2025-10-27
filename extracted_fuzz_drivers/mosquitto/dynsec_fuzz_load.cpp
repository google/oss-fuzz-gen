/*
Copyright (c) 2023 Cedalo GmbH

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <mosquitto.h>
#include <mosquitto_broker_internal.h>

#ifdef __cplusplus
}
#endif

/*
 * Test loading a file
 */

extern struct mosquitto_db db;

void run_dynsec(char *filename) {
  struct mosquitto_plugin_id_t identifier;
  struct mosquitto_opt options[1];

  db.config = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
  log__init(db.config);

  memset(&identifier, 0, sizeof(identifier));

  options[0].key = strdup("config_file");
  options[0].value = filename;

  mosquitto_plugin_init(&identifier, NULL, options, 1);
  mosquitto_plugin_cleanup(NULL, options, 1);

  free(options[0].key);
  free(db.config);
  free(identifier.plugin_name);
  free(identifier.plugin_version);
  db.config = NULL;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[100];
  FILE *fptr;

  umask(0077);

  snprintf(filename, sizeof(filename), "/tmp/dynsec%d.conf", getpid());
  fptr = fopen(filename, "wb");
  if (!fptr)
    return 1;
  fwrite(data, 1, size, fptr);
  fclose(fptr);

  run_dynsec(filename);

  unlink(filename);

  return 0;
}
