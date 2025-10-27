/*
 * The Qubes OS Project, http://www.qubes-os.org
 *
 * Copyright (C) 2018 Marek Marczykowski-Górecki
 *                                       <marmarek@invisiblethingslab.com>
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

#include "common.h"
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* hardcode pipe size for speed, verify from time to time with F_GETPIPE_SZ ioctl */
#define PIPE_SZ 65536

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#error "This file is meant only for fuzzing build"
#endif

/* too lazy to create one-line header file */
int input_proxy_receiver_main(int argc, char **argv);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int pipe_fd[2];
  char *argv[] = {
      "input-proxy-receiver", "--mouse", "--keyboard", "--tablet", "--quiet",
  };

  if (Size > PIPE_SZ) {
    /* sorry, too large - would deadlock */
    goto out;
  }

  if (pipe(pipe_fd) == -1) {
    perror("pipe");
    goto out;
  }

  if (write_all(pipe_fd[1], Data, Size) != Size) {
    perror("failed to write all data to pipe");
    goto out_pipe;
  }

  /* put pipe read end on stdin */
  if (dup2(pipe_fd[0], 0) == -1) {
    perror("dup pipe to stdin");
    goto out_pipe;
  }
  close(pipe_fd[0]);
  /* not needed anymore since we'we written all the data */
  close(pipe_fd[1]);

  input_proxy_receiver_main(5, argv);
  return 0;

out_pipe:
  close(pipe_fd[0]);
  close(pipe_fd[1]);
out:
  return 0;
}
