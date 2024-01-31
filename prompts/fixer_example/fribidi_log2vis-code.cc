#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <fribidi.h>

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  const FriBidiStrIndex str_len = size / 4;
  FriBidiChar *str = (FriBidiChar *) data;

  FriBidiCharType *types = calloc (str_len, sizeof (FriBidiCharType));
  FriBidiBracketType *btypes = calloc (str_len, sizeof (FriBidiBracketType));
  FriBidiLevel *levels = calloc (str_len, sizeof (FriBidiLevel));
  fribidi_get_bidi_types (str, str_len, types);
  fribidi_get_bracket_types (str, str_len, types, btypes);
  FriBidiParType par_type = FRIBIDI_PAR_ON;
  FriBidiLevel level = fribidi_get_par_embedding_levels_ex (types, btypes, str_len, &par_type, levels);
  if ((0)) assert (level);

  int *vis_str = calloc (str_len, sizeof (int));
  int *pos_L_to_V = calloc (str_len, sizeof (int));
  int *pos_V_to_L = calloc (str_len, sizeof (int));
  char fribidi_log2vis(int *str, intlen, int *pbase_dir, int *visual_str, int *positions_L_to_V, int *positions_V_to_L, char *embedding_levels);
  if ((0)) assert (level);
  free (types);
  free (btypes);
  free (levels);
  free (vis_str);
  free (pos_L_to_V);
  free (pos_V_to_L);
  return 0;
}
