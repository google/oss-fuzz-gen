/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proton/connection_driver.h"
#include "proton/engine.h"
#include "proton/logger.h"
#include "proton/message.h"
#include "proton/object.h"

#include "libFuzzingEngine.h"

// This fuzzer is a variant of the receive.c proactor example

#define MAX_SIZE 1024

typedef char str[MAX_SIZE];

typedef struct app_data_t {
  str container_id;
  pn_rwbytes_t message_buffer;
  int message_count;
  int received;
} app_data_t;

static void fdc_write(pn_connection_driver_t *driver);
size_t fcd_read(pn_connection_driver_t *driver, uint8_t **data, size_t *size);
static void decode_message(pn_delivery_t *dlv);
static void handle(app_data_t *app, pn_event_t *event);
static void check_condition(pn_event_t *e, pn_condition_t *cond);

// const bool VERBOSE = true;
const bool VERBOSE = false;
// const bool ERRORS = true;
const bool ERRORS = false;

// I could not get rid of the error messages on stderr in any other way
void devnull(intptr_t context, pn_log_subsystem_t sub, pn_log_level_t sev, const char *message) {}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (VERBOSE)
    printf("BEGIN LLVMFuzzerTestOneInput\n");
  app_data_t app = {{0}};
  sprintf(app.container_id, "%s:%06x", "fuzz_connection_driver", rand() & 0xffffff);

  pn_connection_driver_t driver;
  if (pn_connection_driver_init(&driver, NULL, NULL) != 0) {
    printf("pn_connection_driver_init\n");
    exit(1);
  }

  pn_logger_set_log_sink(pn_default_logger(), devnull, 0);

  uint8_t *data = (uint8_t *)Data;
  size_t size = Size;

  fdc_write(&driver);

  pn_event_t *event;
  while ((event = pn_connection_driver_next_event(&driver)) != NULL) {
    handle(&app, event);
  }

  fdc_write(&driver);

  do {
    fdc_write(&driver);
    fcd_read(&driver, &data, &size);
    if (VERBOSE)
      printf("size is %d, data is %p\n", (int)size, (void *)data);
    while ((event = pn_connection_driver_next_event(&driver)) != NULL) {
      handle(&app, event);
    }
  } while (size > 0);

  pn_connection_driver_close(&driver);
  pn_connection_driver_destroy(&driver);
  if (VERBOSE)
    printf("END LLVMFuzzerTestOneInput\n");
  return 0;
}

static void handle(app_data_t *app, pn_event_t *event) {
  switch (pn_event_type(event)) {

  case PN_CONNECTION_INIT: {
    pn_connection_t *c = pn_event_connection(event);
    pn_connection_set_container(c, app->container_id);
    pn_connection_open(c);
    pn_session_t *s = pn_session(c);
    pn_session_open(s);
    pn_link_t *l = pn_receiver(s, "my_receiver");
    pn_terminus_set_address(pn_link_source(l), NULL);
    pn_link_open(l);
    pn_link_flow(l, 20);
  } break;

  case PN_DELIVERY: {
    /* A message has been received */
    pn_link_t *link = NULL;
    pn_delivery_t *dlv = pn_event_delivery(event);
    if (pn_delivery_readable(dlv) && !pn_delivery_partial(dlv)) {
      link = pn_delivery_link(dlv);
      decode_message(dlv);
      /* Accept the delivery */
      pn_delivery_update(dlv, PN_ACCEPTED);
      /* done with the delivery, move to the next and free it */
      pn_link_advance(link);
      pn_delivery_settle(dlv); /* dlv is now freed */
    }
  } break;

  case PN_TRANSPORT_ERROR:
    check_condition(event, pn_transport_condition(pn_event_transport(event)));
    pn_connection_close(pn_event_connection(event));
    break;

  case PN_CONNECTION_REMOTE_CLOSE:
    check_condition(event, pn_connection_remote_condition(pn_event_connection(event)));
    pn_connection_close(pn_event_connection(event));
    break;

  case PN_SESSION_REMOTE_CLOSE:
    check_condition(event, pn_session_remote_condition(pn_event_session(event)));
    pn_connection_close(pn_event_connection(event));
    break;

  case PN_LINK_REMOTE_CLOSE:
  case PN_LINK_REMOTE_DETACH:
    check_condition(event, pn_link_remote_condition(pn_event_link(event)));
    pn_connection_close(pn_event_connection(event));
    break;

  default:
    break;
  }
}

static void check_condition(pn_event_t *e, pn_condition_t *cond) {
  if (VERBOSE)
    printf("beginning check_condition\n");
  if (pn_condition_is_set(cond)) {
    if (VERBOSE || ERRORS)
      fprintf(stderr, "%s: %s: %s\n", pn_event_type_name(pn_event_type(e)), pn_condition_get_name(cond), pn_condition_get_description(cond));
  }
}

static void decode_message(pn_delivery_t *dlv) {
  static char buffer[MAX_SIZE];
  ssize_t len;
  // try to decode the message body
  if (pn_delivery_pending(dlv) < MAX_SIZE) {
    // read in the raw data
    len = pn_link_recv(pn_delivery_link(dlv), buffer, MAX_SIZE);
    if (len > 0) {
      // decode it into a proton message
      pn_message_t *m = pn_message();
      if (PN_OK == pn_message_decode(m, buffer, len)) {
        char *s = pn_tostring(pn_message_body(m));
        if (ERRORS)
          printf("%s\n", s);
        free(s);
      }
      pn_message_free(m);
    }
  }
}

// reads up to `size` bytes from `data`,
// updates `data` pointer and `size` to the unread portion of original `data`,
// returns new value of `size`
size_t fcd_read(pn_connection_driver_t *driver, uint8_t **data, size_t *size) {
  pn_rwbytes_t buf = pn_connection_driver_read_buffer(driver);
  size_t s = (*size < buf.size) ? *size : buf.size;
  if (buf.start == NULL) {
    // The engine offered a null buffer for further input.
    // This is legit, because it is just that the "socket" was closed
    //  for further input, after reading the invalid header.
    *size = 0;
    return *size;
  }
  memcpy(buf.start, *data, s);

  pn_connection_driver_read_done(driver, s);
  *data += s;
  *size -= s;

  return *size;
}

// drops the data in the buffer and reports them as written
static void fdc_write(pn_connection_driver_t *driver) {
  pn_bytes_t buffer = pn_connection_driver_write_buffer(driver);
  pn_connection_driver_write_done(driver, buffer.size);
}
