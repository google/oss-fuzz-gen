/*
 * Copyright (c) 2017 Nest Labs, Inc.
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *    Description:
 *		This file implements the wpantund fuzzer.
 *
 */

#define main __XX_main
#include "wpantund.cpp"

#include "util/SocketWrapper.h"
#include <poll.h>
#include <sys/cdefs.h>
#include <sys/select.h>
#include <unistd.h>

#define HDLC_BYTE_FLAG 0x7E
#define HDLC_BYTE_ESC 0x7D
#define HDLC_BYTE_XON 0x11
#define HDLC_BYTE_XOFF 0x13
#define HDLC_BYTE_SPECIAL 0xF8
#define HDLC_ESCAPE_XFORM 0x20

void fuzz_trap() {
  sleep(1);
  abort();
}

int count_open_fds() {
  int i;
  int count = 0;

  for (i = 0; i < FD_SETSIZE; i++) {
    int fd = dup(i);

    if (fd >= 0) {
      count++;
      if (close(fd) < 0) {
        perror("count_open_fds");
        fuzz_trap();
      }
    }
  }

  return count;
}

int ConfigFileFuzzTarget(const uint8_t *data, size_t size) {
  std::map<std::string, std::string> settings;
  FILE *file = tmpfile();

  fwrite(data, 1, size, file);
  fflush(file);
  rewind(file);
  fread_config(file, &add_to_map, &settings);
  fclose(file);

  if (!settings.empty()) {
    std::map<std::string, std::string>::const_iterator iter;

    for (iter = settings.begin(); iter != settings.end(); iter++) {
      set_config_param(NULL, iter->first.c_str(), iter->second.c_str());
    }

    try {
      MainLoop main_loop(settings);
    } catch (nl::SocketError x) {
      // Ignore socket errors
    } catch (std::invalid_argument x) {
      // Ignore invalid argument errors
    }
  }

  return 0;
}

#define FUZZ_SPECIAL_WAIT_FOR_FRAME 0
#define FUZZ_SPECIAL_FF_DECISECONDS 1

int NCPInputFuzzTarget(const uint8_t *data, size_t size) {
  std::map<std::string, std::string> settings;

  int fd[2] = {-1, -1};
  uint8_t data_out[100];
  uint32_t i = 0;
  const uint32_t max_iterations = 10000000;
  static const uint8_t hdlc_flag = HDLC_BYTE_FLAG;

  gRet = 0;

  if (socketpair(PF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    syslog(LOG_ALERT, "Call to socketpair() failed: %s (%d)", strerror(errno), errno);
    fuzz_trap();
  }

  {
    char *fd_string = NULL;

    if (0 >= asprintf(&fd_string, "fd:%d", fd[1])) {
      syslog(LOG_ALERT, "Call to asprintf() failed: %s (%d)", strerror(errno), errno);
      fuzz_trap();
    }

    assert(fd_string != NULL);

    settings[kWPANTUNDProperty_ConfigNCPSocketPath] = fd_string;

    free(fd_string);
  }

  try {

    MainLoop main_loop(settings);

    // wpantund dup'd the file descriptor we gave it,
    // so we should close this one here.
    close(fd[1]);
    fd[1] = -1;

    for (i = 0; (i < 10) && main_loop.block_until_ready(); i++) {
      main_loop.process();
    }
    main_loop.process();

    while (size > 0 && gRet == 0) {
      uint8_t c = *data++;
      size--;

      // Special command.
      if ((size > 0) && (c == HDLC_BYTE_SPECIAL)) {
        c = *data++;
        size--;

        if (c == FUZZ_SPECIAL_WAIT_FOR_FRAME) {
          for (i = 0; i < 5 && checkpoll(fd[0], POLLIN | POLLERR | POLLHUP) == 0; i++) {
            if (main_loop.block_until_ready()) {
              main_loop.process();
            } else {
              break;
            }
          }

          while (checkpoll(fd[0], POLLIN | POLLERR | POLLHUP) != 0 && gRet == 0) {
            ssize_t bytesread = read(fd[0], data_out, sizeof(data_out));
            if (bytesread <= 0) {
              syslog(LOG_WARNING, "Call to read() failed: %s (%d)", strerror(errno), errno);
              goto bail;
            }

            if (main_loop.block_until_ready()) {
              main_loop.process();
            } else {
              break;
            }
#if DEBUG
            fprintf(stderr, "NCPInputFuzzTarget: Got %lu bytes from wpantund\n", bytesread);
#endif
          }
          continue;
        } else if ((c == FUZZ_SPECIAL_FF_DECISECONDS) && (size > 0)) {
          c = *data++;
          size--;
          // Fast forward the given number of deciseconds
          fuzz_ff_cms(c * (MSEC_PER_SEC / 10));
        }
      }

      while (checkpoll(fd[0], POLLOUT | POLLERR | POLLHUP) == 0 && gRet == 0) {
        main_loop.block_until_ready();
        main_loop.process();
      }

      ssize_t byteswritten = write(fd[0], &c, 1);
      if (byteswritten <= 0) {
        syslog(LOG_WARNING, "Call to write() failed: %s (%d)", strerror(errno), errno);
        goto bail;
        ;
      }

      main_loop.block_until_ready();
      main_loop.process();
    }

    for (i = 0; (i < 10) && main_loop.block_until_ready(); i++) {
      main_loop.process();
    }
    main_loop.process();

    if (size != 0) {
      syslog(LOG_ALERT, "Did not consume all data");
      fuzz_trap();
    }

    if (gRet != 0) {
      syslog(LOG_ALERT, "gRet = %d", gRet);
      fuzz_trap();
    }

  } catch (nl::SocketError x) {
    // Ignore socket wrapper errors
  }

bail:
  close(fd[0]);
  close(fd[1]);

  return 0;
}

int NCPControlInterfaceFuzzTarget(const uint8_t *data, size_t size) {
  // TODO: Write me!
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int ret = 0;
  static bool did_init;

  if (!did_init) {
    did_init = true;

    openlog("wpantund-fuzz", LOG_PERROR | LOG_NDELAY, LOG_USER);

#if DEBUG
    setlogmask(LOG_UPTO(LOG_INFO));
#else
    setlogmask(LOG_UPTO(LOG_ALERT));
#endif

    signal(SIGPIPE, SIG_IGN);
  }

  fuzz_set_cms(0);

  int fd_count_before = -1;
  int fd_count_after = -1;

  // Count the number of FDs before starting fuzzing.
  fd_count_before = count_open_fds();
  if (fd_count_before > 1000) {
    syslog(LOG_ALERT, "Too many file descriptors open: %d (max %d)", fd_count_before, 1000);
    fuzz_trap();
  }

  if (size >= 1) {
    char type = *data++;
    size--;
    switch (type) {
    case '0': // Config file fuzzing
      ret = ConfigFileFuzzTarget(data, size);
      break;

    case '1': // NCP Input fuzzing
      ret = NCPInputFuzzTarget(data, size);
      break;

    case '2': // NCPControlInterface fuzzing
      ret = NCPControlInterfaceFuzzTarget(data, size);
      break;

    default:
      break;
    }
  }

  // Count the number of FDs after finishing fuzzing.
  fd_count_after = count_open_fds();
  if (fd_count_before != fd_count_after) {
    syslog(LOG_ALERT, "File descriptor count changed durring run! before=%d after=%d", fd_count_before, fd_count_after);
    fuzz_trap();
  }

  return ret;
}
