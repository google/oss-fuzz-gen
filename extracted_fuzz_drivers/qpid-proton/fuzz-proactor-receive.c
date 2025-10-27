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

#define _POSIX_C_SOURCE 200809L

#include <proton/connection.h>
#include <proton/connection_driver.h>
#include <proton/delivery.h>
#include <proton/link.h>
#include <proton/message.h>
#include <proton/object.h>
#include <proton/proactor.h>
#include <proton/session.h>
#include <proton/transport.h>
#include <proton/url.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <errno.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "libFuzzingEngine.h"

// bool VERBOSE = true;
bool VERBOSE = false;
// bool ERRORS = true;
bool ERRORS = false;

#define MAX_SIZE 1024

typedef char str[MAX_SIZE];

typedef struct app_data_t {
  str address;
  str container_id;
  pn_rwbytes_t message_buffer;
  int message_count;
  int received;
  pn_proactor_t *proactor;
  bool finished;
} app_data_t;

static const int BATCH = 1000; /* Batch size for unlimited receive */

static int exit_code = 0;

static void check_condition(pn_event_t *e, pn_condition_t *cond) {
  if (VERBOSE)
    printf("beginning check_condition\n");
  if (pn_condition_is_set(cond)) {
    exit_code = 1;
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
        printf("%s\n", s);
        free(s);
      }
      pn_message_free(m);
    }
  }
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
    pn_terminus_set_address(pn_link_source(l), app->address);
    pn_link_open(l);
    /* cannot receive without granting credit: */
    pn_link_flow(l, app->message_count ? app->message_count : BATCH);
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

      if (app->message_count == 0) {
        /* receive forever - see if more credit is needed */
        if (pn_link_credit(link) < BATCH / 2) {
          /* Grant enough credit to bring it up to BATCH: */
          pn_link_flow(link, BATCH - pn_link_credit(link));
        }
      } else if (++app->received >= app->message_count) {
        /* done receiving, close the endpoints */
        printf("%d messages received\n", app->received);
        pn_session_t *ssn = pn_link_session(link);
        pn_link_close(link);
        pn_session_close(ssn);
        pn_connection_close(pn_session_connection(ssn));
      }
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

  case PN_PROACTOR_INACTIVE:
    app->finished = true;
    break;

  default:
    break;
  }
}

double now(void) {
  struct timespec spec;
  if (clock_gettime(CLOCK_MONOTONIC, &spec) != 0) {
    perror("clock_gettime");
    exit(errno);
  }
  return (double)spec.tv_sec + (double)spec.tv_nsec / 1000000.0;
}

int sut(void) {
  /* Default values for application and connection. */
  app_data_t app = {{0}};
  app.message_count = 2;

  snprintf(app.container_id, sizeof(app.container_id), "%s:%d", "fuzz_proactor_recv", getpid());

  const char *address = "127.0.0.1:amqp";
  strncpy(app.address, "jms.queue.example", sizeof(app.address));

  if (VERBOSE)
    printf("before proactor\n");
  /* Create the proactor and connect */
  app.proactor = pn_proactor();
  pn_proactor_connect(app.proactor, pn_connection(), address);

  if (VERBOSE)
    printf("before loop\n");
  double thence = now();
  do {
    if (VERBOSE)
      printf("before set proactor timeout\n");
    pn_proactor_set_timeout(app.proactor, 100);
    if (VERBOSE)
      printf("before proactor wait\n");
    pn_event_batch_t *events = pn_proactor_wait(app.proactor);
    pn_event_t *e;
    if (VERBOSE)
      printf("before proactor next batch\n");
    while ((e = pn_event_batch_next(events))) {
      handle(&app, e);
    }
    pn_proactor_done(app.proactor, events);

    if (VERBOSE)
      printf("before reloop\n");
    double deltat = now() - thence;
    if (VERBOSE)
      printf("deltat %f", deltat);
    if (deltat > 1) {
      app.finished = true;
    }
  } while (!app.finished);

  if (VERBOSE)
    printf("after loop\n");
  pn_proactor_free(app.proactor);
  free(app.message_buffer.start);
  return exit_code;
}

void serve_data(const uint8_t *Data, size_t Size) {
  int sockfd;
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    _Exit(errno);
  }
  int reuseaddr = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
    perror("setsockopt");
    _Exit(errno);
  }
  struct sockaddr_in self;
  memset(&self, 0, sizeof(self));
  self.sin_family = AF_INET;
  self.sin_port = htons(5672);
  self.sin_addr.s_addr = INADDR_ANY;
  if (bind(sockfd, (struct sockaddr *)&self, sizeof(self)) != 0) {
    perror("bind");

    // Lets unblock the old child that listens by starting new client to read
    // from it. It breaks the fuzzing somewhat, but it is better to mess up one
    // than many inputs.
    if (VERBOSE)
      printf("unblocking old bound child\n");
    kill(getppid(), SIGUSR1);

    _Exit(errno);
  }
  if (VERBOSE)
    printf("bound\n");
  if (listen(sockfd, 1) != 0) {
    perror("listen");
    _Exit(errno);
  }

  if (VERBOSE)
    printf("listened, lets run sut\n");
  kill(getppid(), SIGUSR1);

  struct sockaddr_in client_addr;
  socklen_t addrlen = sizeof(client_addr);
  int clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &addrlen);
  if (VERBOSE)
    printf("%s:%d connected\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
  if (VERBOSE)
    printf("will send\n");
  send(clientfd, Data, Size, 0);
  //     sleep(1);
  close(clientfd);
  close(sockfd);
  if (VERBOSE)
    printf("done serving\n");
}

void run_sut(int s) {
  if (VERBOSE)
    printf("running sut\n");
  sut();
  if (VERBOSE)
    printf("finished running sut\n");
}

void signal_callback_handler(int signum) {
  if (VERBOSE)
    printf("Caught signal SIGPIPE %d\n", signum);
}

bool DoInitialization(void) {
  struct sigaction sa;
  sa.sa_handler = run_sut;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; /* Restart functions if interrupted by handler */
  if (sigaction(SIGUSR1, &sa, NULL) == -1) {
    perror("sigaction");
    exit(2);
  }
  sa.sa_handler = signal_callback_handler;
  if (sigaction(SIGPIPE, &sa, NULL) == -1) {
    perror("sigaction");
    exit(2);
  }
  return true;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  DoInitialization();
  return 0;
}

int prev_pid = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // sometimes, esp. with AFL, but libFuzz too,
  // the old socket is still bound for new run and
  // it skips all new runs...
  if (prev_pid != 0) {
    kill(SIGKILL, prev_pid);
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(errno);
  }
  if (pid == 0) { // child
    serve_data(Data, Size);
    _Exit(0);
  } else { // parent
    prev_pid = pid;
    if (VERBOSE)
      printf("waiting for child\n");
    siginfo_t status;
    waitid(P_PID, pid, &status, WEXITED);
    if (VERBOSE)
      printf("finished waiting for child\n");
  }
  return 0;
}
