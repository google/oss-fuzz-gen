#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <threads.h>
#include <unistd.h>

#include "rtpp_cfg.h"
#include "rtpp_command.h"
#include "rtpp_command_args.h"
#include "rtpp_command_async.h"
#include "rtpp_command_private.h"
#include "rtpp_command_sub.h"
#include "rtpp_hash_table.h"
#include "rtpp_log_obj.h"
#include "rtpp_log_stand.h"
#include "rtpp_proc_async.h"
#include "rtpp_refcnt.h"
#include "rtpp_sessinfo.h"
#include "rtpp_stats.h"
#include "rtpp_time.h"
#include "rtpp_types.h"
#include "rtpp_weakref.h"

#include "librtpproxy.h"

#include "fuzz_standalone.h"

#define howmany(x, y) (sizeof(x) / sizeof(y))

static struct {
  struct rtpp_cfg *cfsp;
  int tfd;
} gconf;

static void cleanupHandler(void) {
  printf("Cleaning up before exit...\n");
  rtpp_shutdown(gconf.cfsp);
  close(gconf.tfd);
}

__attribute__((constructor)) void rtpp_init() {
  char *argv[] = {
      "rtpproxy", "-f", "-T", "1", "-W", "1", "-s", "stdio:", "-d", "crit", "-n", "tcp:127.0.0.1:9642", "-S", "/tmp", "-r", ".", "--dso", "acct_csv", "--dso", "catch_dtmf", "--dso", "dtls_gw",
  };
  int argc = howmany(argv, *argv);
  struct rtpp_cfg *cfsp;

  OPT_SAVE();
  cfsp = rtpp_main(argc, argv);
  OPT_RESTORE();
  assert(cfsp != NULL);
  cfsp->no_resolve = 1;
  gconf.tfd = open("/dev/null", O_WRONLY, 0);
  assert(gconf.tfd >= 0);
  gconf.cfsp = cfsp;
  atexit(cleanupHandler);
}

int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  struct rtpp_timestamp dtime = {};
  static struct rtpp_command_stats cstat = {};
  struct rtpp_command *cmd;
  int rval = -1;

  if (size > RTPP_CMD_BUFLEN)
    return (0);

  cmd = rtpp_command_ctor(gconf.cfsp, gconf.tfd, &dtime, &cstat, 0);
  assert(cmd != NULL);
  memcpy(cmd->buf, data, size);
  cmd->buf[size == RTPP_CMD_BUFLEN ? size - 1 : size] = '\0';

  if (rtpp_command_split(cmd, size, &rval, NULL) == 0) {
    handle_command(gconf.cfsp, cmd);
  }
  free_command(cmd);
  return (0);
}
