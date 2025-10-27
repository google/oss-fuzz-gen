#include <stdio.h>
#include <unistd.h>

#include <gpac/constants.h>
#include <gpac/filters.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  char argname[300];
  GF_Err e;
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp)
    return 0;
  fwrite(data, size, 1, fp);
  fclose(fp);

  gf_sys_init(0, "0");
  const char *args[2];
  args[0] = "gpac";
  sprintf(argname, "-netcap=src=%s,nrt", filename);
  args[1] = argname;
  e = gf_sys_set_args(2, args);

  if (e == GF_OK) {
    const char *url = "route://234.0.0.1:1234/live.mpd";
    GF_FilterSession *fs = gf_fs_new_defaults(0);
    GF_Filter *src = gf_fs_load_source(fs, url, NULL, NULL, &e);
    GF_Filter *insp = gf_fs_load_filter(fs, "inspect:deep", &e);
    gf_fs_run(fs);
    gf_fs_del(fs);
  }

  gf_sys_close();
  unlink(filename);
  return 0;
}
