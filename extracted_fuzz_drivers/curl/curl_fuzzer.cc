/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017 - 2022, Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_fuzzer.h"
#include <curl/curl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Fuzzing entry point. This function is passed a buffer containing a test
 * case.  This test case should drive the CURL API into making a request.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int rc = 0;
  int tlv_rc;
  FUZZ_DATA fuzz;
  TLV tlv;

  /* Ignore SIGPIPE errors. We'll handle the errors ourselves. */
  signal(SIGPIPE, SIG_IGN);

  /* Have to set all fields to zero before getting to the terminate function */
  memset(&fuzz, 0, sizeof(FUZZ_DATA));

  if (size < sizeof(TLV_RAW)) {
    /* Not enough data for a single TLV - don't continue */
    goto EXIT_LABEL;
  }

  /* Try to initialize the fuzz data */
  FTRY(fuzz_initialize_fuzz_data(&fuzz, data, size));

  for (tlv_rc = fuzz_get_first_tlv(&fuzz, &tlv); tlv_rc == 0; tlv_rc = fuzz_get_next_tlv(&fuzz, &tlv)) {

    /* Have the TLV in hand. Parse the TLV. */
    rc = fuzz_parse_tlv(&fuzz, &tlv);

    if (rc != 0) {
      /* Failed to parse the TLV. Can't continue. */
      goto EXIT_LABEL;
    }
  }

  if (tlv_rc != TLV_RC_NO_MORE_TLVS) {
    /* A TLV call failed. Can't continue. */
    goto EXIT_LABEL;
  }

  /* Set up the standard easy options. */
  FTRY(fuzz_set_easy_options(&fuzz));

  /**
   * Add in more curl options that have been accumulated over possibly
   * multiple TLVs.
   */
  if (fuzz.header_list != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_HTTPHEADER, fuzz.header_list);
  }

  if (fuzz.mail_recipients_list != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_MAIL_RCPT, fuzz.mail_recipients_list);
  }

  if (fuzz.mime != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_MIMEPOST, fuzz.mime);
  }

  if (fuzz.httppost != NULL) {
    curl_easy_setopt(fuzz.easy, CURLOPT_HTTPPOST, fuzz.httppost);
  }

  /* Run the transfer. */
  fuzz_handle_transfer(&fuzz);

EXIT_LABEL:

  fuzz_terminate_fuzz_data(&fuzz);

  /* This function must always return 0. Non-zero codes are reserved. */
  return 0;
}

/**
 * Utility function to convert 4 bytes to a u32 predictably.
 */
uint32_t to_u32(const uint8_t b[4]) {
  uint32_t u;
  u = (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3];
  return u;
}

/**
 * Utility function to convert 2 bytes to a u16 predictably.
 */
uint16_t to_u16(const uint8_t b[2]) {
  uint16_t u;
  u = (b[0] << 8) + b[1];
  return u;
}

/**
 * Initialize the local fuzz data structure.
 */
int fuzz_initialize_fuzz_data(FUZZ_DATA *fuzz, const uint8_t *data, size_t data_len) {
  int rc = 0;
  int ii;

  /* Initialize the fuzz data. */
  memset(fuzz, 0, sizeof(FUZZ_DATA));

  /* Create an easy handle. This will have all of the settings configured on
     it. */
  fuzz->easy = curl_easy_init();
  FCHECK(fuzz->easy != NULL);

  /* Set up the state parser */
  fuzz->state.data = data;
  fuzz->state.data_len = data_len;

  /* Set up the state of the server sockets. */
  for (ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
    fuzz->sockman[ii].index = ii;
    fuzz->sockman[ii].fd_state = FUZZ_SOCK_CLOSED;
  }

  /* Check for verbose mode. */
  fuzz->verbose = (getenv("FUZZ_VERBOSE") != NULL);

  FCHECK(setenv("CURL_HSTS_HTTP", "1", 0) == 0);
  FCHECK(setenv("CURL_ALTSVC_HTTP", "1", 0) == 0);

EXIT_LABEL:

  return rc;
}

/**
 * Set standard options on the curl easy.
 */
int fuzz_set_easy_options(FUZZ_DATA *fuzz) {
  int rc = 0;
  unsigned long allowed_protocols;

  /* Set some standard options on the CURL easy handle. We need to override the
     socket function so that we create our own sockets to present to CURL. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_OPENSOCKETFUNCTION, fuzz_open_socket));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_OPENSOCKETDATA, fuzz));

  /* In case something tries to set a socket option, intercept this. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_SOCKOPTFUNCTION, fuzz_sockopt_callback));

  /* Set the standard read function callback. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_READFUNCTION, fuzz_read_callback));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_READDATA, fuzz));

  /* Set the standard write function callback. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_WRITEFUNCTION, fuzz_write_callback));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_WRITEDATA, fuzz));

  /* Set the writable cookie jar path so cookies are tested. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_COOKIEJAR, FUZZ_COOKIE_JAR_PATH));

  /* Set the RO cookie file path so cookies are tested. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_COOKIEFILE, FUZZ_RO_COOKIE_FILE_PATH));

  /* Set altsvc header cache filepath so that it can be fuzzed. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_ALTSVC, FUZZ_ALT_SVC_HEADER_CACHE_PATH));

  /* Set the hsts header cache filepath so that it can be fuzzed. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_HSTS, FUZZ_HSTS_HEADER_CACHE_PATH));

  /* Set the Certificate Revocation List file path so it can be fuzzed */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_CRLFILE, FUZZ_CRL_FILE_PATH));

  /* Set the .netrc file path so it can be fuzzed */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_NETRC_FILE, FUZZ_NETRC_FILE_PATH));

  /* Time out requests quickly. */
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_TIMEOUT_MS, 200L));
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_SERVER_RESPONSE_TIMEOUT, 1L));

  /* Can enable verbose mode by having the environment variable FUZZ_VERBOSE. */
  if (fuzz->verbose) {
    FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_VERBOSE, 1L));
  }

  /* Force resolution of all addresses to a specific IP address. */
  fuzz->connect_to_list = curl_slist_append(NULL, "::127.0.1.127:");
  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_CONNECT_TO, fuzz->connect_to_list));

  /* Limit the protocols in use by this fuzzer. */
  FTRY(fuzz_set_allowed_protocols(fuzz));

EXIT_LABEL:

  return rc;
}

/**
 * Terminate the fuzz data structure, including freeing any allocated memory.
 */
void fuzz_terminate_fuzz_data(FUZZ_DATA *fuzz) {
  int ii;

  fuzz_free((void **)&fuzz->postfields);

  for (ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
    if (fuzz->sockman[ii].fd_state != FUZZ_SOCK_CLOSED) {
      close(fuzz->sockman[ii].fd);
      fuzz->sockman[ii].fd_state = FUZZ_SOCK_CLOSED;
    }
  }

  if (fuzz->connect_to_list != NULL) {
    curl_slist_free_all(fuzz->connect_to_list);
    fuzz->connect_to_list = NULL;
  }

  if (fuzz->header_list != NULL) {
    curl_slist_free_all(fuzz->header_list);
    fuzz->header_list = NULL;
  }

  if (fuzz->mail_recipients_list != NULL) {
    curl_slist_free_all(fuzz->mail_recipients_list);
    fuzz->mail_recipients_list = NULL;
  }

  if (fuzz->mime != NULL) {
    curl_mime_free(fuzz->mime);
    fuzz->mime = NULL;
  }

  if (fuzz->easy != NULL) {
    curl_easy_cleanup(fuzz->easy);
    fuzz->easy = NULL;
  }

  /* When you have passed the struct curl_httppost pointer to curl_easy_setopt
   * (using the CURLOPT_HTTPPOST option), you must not free the list until after
   *  you have called curl_easy_cleanup for the curl handle.
   *  https://curl.se/libcurl/c/curl_formadd.html */
  if (fuzz->httppost != NULL) {
    curl_formfree(fuzz->httppost);
    fuzz->httppost = NULL;
  }

  // free after httppost and last_post_part.
  if (fuzz->post_body != NULL) {
    fuzz_free((void **)&fuzz->post_body);
  }
}

/**
 * If a pointer has been allocated, free that pointer.
 */
void fuzz_free(void **ptr) {
  if (*ptr != NULL) {
    free(*ptr);
    *ptr = NULL;
  }
}

/**
 * Function for handling the fuzz transfer, including sending responses to
 * requests.
 */
int fuzz_handle_transfer(FUZZ_DATA *fuzz) {
  int rc = 0;
  CURLM *multi_handle;
  int still_running; /* keep number of running handles */
  CURLMsg *msg;      /* for picking up messages with the transfer status */
  int msgs_left;     /* how many messages are left */
  int double_timeout = 0;
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;
  struct timeval timeout;
  int select_rc;
  CURLMcode mc;
  int maxfd = -1;
  long curl_timeo = -1;
  int ii;
  FUZZ_SOCKET_MANAGER *sman[FUZZ_NUM_CONNECTIONS];

  for (ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
    sman[ii] = &fuzz->sockman[ii];

    /* Set up the starting index for responses. */
    sman[ii]->response_index = 1;
  }

  /* init a multi stack */
  multi_handle = curl_multi_init();

  /* add the individual transfers */
  curl_multi_add_handle(multi_handle, fuzz->easy);

  /* Do an initial process. This might end the transfer immediately. */
  curl_multi_perform(multi_handle, &still_running);
  FV_PRINTF(fuzz, "FUZZ: Initial perform; still running? %d \n", still_running);

  while (still_running) {
    /* Reset the sets of file descriptors. */
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* Set a timeout of 10ms. This is lower than recommended by the multi guide
       but we're not going to any remote servers, so everything should complete
       very quickly. */
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;

    /* get file descriptors from the transfers */
    mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
    if (mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
      rc = -1;
      break;
    }

    for (ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
      /* Add the socket FD into the readable set if connected. */
      if (sman[ii]->fd_state == FUZZ_SOCK_OPEN) {
        FD_SET(sman[ii]->fd, &fdread);

        /* Work out the maximum FD between the cURL file descriptors and the
           server FD. */
        maxfd = FUZZ_MAX(sman[ii]->fd, maxfd);
      }
    }

    /* Work out what file descriptors need work. */
    rc = fuzz_select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    if (rc == -1) {
      /* Had an issue while selecting a file descriptor. Let's just exit. */
      FV_PRINTF(fuzz, "FUZZ: select failed, exiting \n");
      break;
    } else if (rc == 0) {
      FV_PRINTF(fuzz, "FUZZ: Timed out; double timeout? %d \n", double_timeout);

      /* Timed out. */
      if (double_timeout == 1) {
        /* We don't expect multiple timeouts in a row. If there are double
           timeouts then exit. */
        break;
      } else {
        /* Set the timeout flag for the next time we select(). */
        double_timeout = 1;
      }
    } else {
      /* There's an active file descriptor. Reset the timeout flag. */
      double_timeout = 0;
    }

    /* Check to see if a server file descriptor is readable. If it is,
       then send the next response from the fuzzing data. */
    for (ii = 0; ii < FUZZ_NUM_CONNECTIONS; ii++) {
      if (sman[ii]->fd_state == FUZZ_SOCK_OPEN && FD_ISSET(sman[ii]->fd, &fdread)) {
        rc = fuzz_send_next_response(fuzz, sman[ii]);
        if (rc != 0) {
          /* Failed to send a response. Break out here. */
          break;
        }
      }
    }

    curl_multi_perform(multi_handle, &still_running);
  }

  /* Remove the easy handle from the multi stack. */
  curl_multi_remove_handle(multi_handle, fuzz->easy);

  /* Clean up the multi handle - the top level function will handle the easy
     handle. */
  curl_multi_cleanup(multi_handle);

  return (rc);
}

/**
 * Sends the next fuzzing response to the server file descriptor.
 */
int fuzz_send_next_response(FUZZ_DATA *fuzz, FUZZ_SOCKET_MANAGER *sman) {
  int rc = 0;
  ssize_t ret_in;
  ssize_t ret_out;
  char buffer[8192];
  const uint8_t *data;
  size_t data_len;

  /* Need to read all data sent by the client so the file descriptor becomes
     unreadable. Because the file descriptor is non-blocking we won't just
     hang here. */
  do {
    ret_in = read(sman->fd, buffer, sizeof(buffer));
    if (fuzz->verbose && ret_in > 0) {
      printf("FUZZ[%d]: Received %zu bytes \n==>\n", sman->index, ret_in);
      fwrite(buffer, ret_in, 1, stdout);
      printf("\n<==\n");
    }
  } while (ret_in > 0);

  /* Now send a response to the request that the client just made. */
  FV_PRINTF(fuzz, "FUZZ[%d]: Sending next response: %d \n", sman->index, sman->response_index);
  data = sman->responses[sman->response_index].data;
  data_len = sman->responses[sman->response_index].data_len;

  if (data != NULL) {
    if (write(sman->fd, data, data_len) != (ssize_t)data_len) {
      /* Failed to write the data back to the client. Prevent any further
         testing. */
      rc = -1;
    }
  }

  /* Work out if there are any more responses. If not, then shut down the
     server. */
  sman->response_index++;

  if (sman->response_index >= TLV_MAX_NUM_RESPONSES || sman->responses[sman->response_index].data == NULL) {
    FV_PRINTF(fuzz, "FUZZ[%d]: Shutting down server socket: %d \n", sman->index, sman->fd);
    shutdown(sman->fd, SHUT_WR);
    sman->fd_state = FUZZ_SOCK_SHUTDOWN;
  }

  return (rc);
}

/**
 * Wrapper for select() so profiling can track it.
 */
int fuzz_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) { return select(nfds, readfds, writefds, exceptfds, timeout); }

/**
 * Set allowed protocols based on the compile options.
 *
 * Note that it can only use ONE of the FUZZ_PROTOCOLS_* defines.a
 */
int fuzz_set_allowed_protocols(FUZZ_DATA *fuzz) {
  int rc = 0;
  const char *allowed_protocols = "";

#ifdef FUZZ_PROTOCOLS_ALL
  /* Do not allow telnet currently as it accepts input from stdin. */
  allowed_protocols = "dict,file,ftp,ftps,gopher,gophers,http,https,imap,imaps,"
                      "mqtt,pop3,pop3s,"
                      "rtsp,smb,smbs,smtp,smtps,tftp";
#endif
#ifdef FUZZ_PROTOCOLS_DICT
  allowed_protocols = "dict";
#endif
#ifdef FUZZ_PROTOCOLS_FILE
  allowed_protocols = "file";
#endif
#ifdef FUZZ_PROTOCOLS_FTP
  allowed_protocols = "ftp,ftps";
#endif
#ifdef FUZZ_PROTOCOLS_GOPHER
  allowed_protocols = "gopher,gophers";
#endif
#ifdef FUZZ_PROTOCOLS_HTTP
  allowed_protocols = "http";
#endif
#ifdef FUZZ_PROTOCOLS_HTTPS
  allowed_protocols = "https";
#endif
#ifdef FUZZ_PROTOCOLS_IMAP
  allowed_protocols = "imap,imaps";
#endif
#ifdef FUZZ_PROTOCOLS_LDAP
  allowed_protocols = "ldap,ldaps";
#endif
#ifdef FUZZ_PROTOCOLS_MQTT
  allowed_protocols = "mqtt";
#endif
#ifdef FUZZ_PROTOCOLS_POP3
  allowed_protocols = "pop3,pop3s";
#endif
#ifdef FUZZ_PROTOCOLS_RTMP
  allowed_protocols = "rtmp,rtmpe,rtmps,rtmpt,rtmpte,rtmpts";
#endif
#ifdef FUZZ_PROTOCOLS_RTSP
  allowed_protocols = "rtsp";
#endif
#ifdef FUZZ_PROTOCOLS_SCP
  allowed_protocols = "scp";
#endif
#ifdef FUZZ_PROTOCOLS_SFTP
  allowed_protocols = "sftp";
#endif
#ifdef FUZZ_PROTOCOLS_SMB
  allowed_protocols = "smb,smbs";
#endif
#ifdef FUZZ_PROTOCOLS_SMTP
  allowed_protocols = "smtp,smtps";
#endif
#ifdef FUZZ_PROTOCOLS_TFTP
  allowed_protocols = "tftp";
#endif
#ifdef FUZZ_PROTOCOLS_WS
  allowed_protocols = "ws,wss";
#endif

  FTRY(curl_easy_setopt(fuzz->easy, CURLOPT_PROTOCOLS_STR, allowed_protocols));

EXIT_LABEL:

  return rc;
}
