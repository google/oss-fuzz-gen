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
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "mosquitto_broker_internal.h"
#include "mosquitto_internal.h"

#ifdef __cplusplus
}
#endif

#define kMinInputLength 3
#define kMaxInputLength 268435455U

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct mosquitto *context = NULL;
  uint8_t *data_heap;
  struct mosquitto__listener listener;
  struct mosquitto__security_options secopts;
  struct mosquitto__bridge bridge;

  if (size < kMinInputLength || size > kMaxInputLength) {
    return 0;
  }

  db.config = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
  log__init(db.config);

  memset(&listener, 0, sizeof(listener));
  memset(&bridge, 0, sizeof(bridge));
  memset(&secopts, 0, sizeof(secopts));

  context = context__init();
  if (!context)
    return 1;
  listener.security_options = &secopts;
  context->listener = &listener;
  context->bridge = &bridge;

  context->state = (enum mosquitto_client_state)data[0];
  context->protocol = (enum mosquitto__protocol)data[1];
  size -= 2;

  data_heap = (uint8_t *)malloc(size);
  if (!data_heap)
    return 1;

  memcpy(data_heap, &data[2], size);

  context->in_packet.command = data_heap[0];
  context->in_packet.payload = (uint8_t *)data_heap;
  context->in_packet.packet_length = (uint32_t)size; /* Safe cast, because we've already limited the size */
  context->in_packet.remaining_length = (uint32_t)(size - 1);
  context->in_packet.pos = 1;

  handle__packet(context);

  context->bridge = NULL;
  context__cleanup(context, true);

  free(db.config);

  return 0;
}
