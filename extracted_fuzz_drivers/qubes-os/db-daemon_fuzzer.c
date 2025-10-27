
/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2019 Marta Marczykowska-Górecka
 *                                       <marmarta@invisiblethingslab.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
#include "qubesdb.h"
#include "qubesdb_internal.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#error "This file is meant only for fuzzing build"
#endif

const uint8_t *fuzz_data;
size_t fuzz_size = 0;
int fuzz_offset = 0;

typedef int EVTCHN;
struct libvchan;
typedef struct libvchan libvchan_t;

int libvchan_write(libvchan_t *ctrl, const void *data, size_t size) { return (int)size; };

int libvchan_send(libvchan_t *ctrl, const void *data, size_t size) { return (int)size; };

int libvchan_read(libvchan_t *ctrl, void *data, size_t size) {
  if (fuzz_size < size) {
    size = fuzz_size;
  }

  memcpy(data, fuzz_data + fuzz_offset, size);

  fuzz_size -= size;
  fuzz_offset += size;

  return (int)size;
};

int libvchan_recv(libvchan_t *ctrl, void *data, size_t size) {
  if (fuzz_size < size) {
    errno = EIO;
    return -1;
  }

  memcpy(data, fuzz_data + fuzz_offset, size);

  fuzz_size -= size;
  fuzz_offset += size;

  return (int)size;
};

int libvchan_wait(libvchan_t *ctrl) {
  return 0; // ??
};

void libvchan_close(libvchan_t *ctrl) { return; };

EVTCHN libvchan_fd_for_select(libvchan_t *ctrl) {
  return 0; // ???!@#?
};

int libvchan_is_open(libvchan_t *ctrl) { return 1; };

int libvchan_data_ready(libvchan_t *ctrl) { return fuzz_size; };

int libvchan_buffer_space(libvchan_t *ctrl) { return 4096; };

libvchan_t *libvchan_server_init(int domain, int port, size_t read_min, size_t write_min) {
  libvchan_t *result = (libvchan_t *)1;
  return result;
};

libvchan_t *libvchan_client_init(int domain, int port) {
  libvchan_t *result = (libvchan_t *)1;
  return result;
};

int sd_notify(int unset_environment, const char *state) { return 0; };

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) { return 0; };

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  fuzz_data = Data;
  fuzz_size = Size;
  fuzz_offset = 0;

  struct db_daemon_data d;
  memset(&d, 0, sizeof(d));
  d.remote_name = "test";
  d.db = qubesdb_init(write_client_buffered);
  d.vchan = (libvchan_t *)1; // any not-null pointer is needed

  while (fuzz_size && handle_vchan_data(&d))
    ;

  qubesdb_destroy(d.db);

  return 0;
};
