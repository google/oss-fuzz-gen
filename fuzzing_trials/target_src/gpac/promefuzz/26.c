// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_reset_fragment_info at isom_read.c:4976:6 in isomedia.h
// gf_isom_has_keep_utc_times at isom_read.c:5550:6 in isomedia.h
// gf_isom_is_fragmented at movie_fragments.c:3523:6 in isomedia.h
// gf_isom_is_smooth_streaming_moov at isom_read.c:5848:6 in isomedia.h
// gf_isom_has_sync_shadows at isom_read.c:1894:6 in isomedia.h
// gf_isom_get_fragments_count at isom_read.c:5418:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

// Dummy implementation of GF_ISOFile for fuzzing purposes
struct __tag_isom {
    GF_Err LastError;
    char *fileName;
    void *movieFileMap; // Use void* for unknown types
    char *finalName;
    void *editFileMap; // Use void* for unknown types
    u32 interleavingTime;
    GF_ISOTrackID last_created_track_id;
    GF_ISOOpenMode openMode;
    u8 storageMode;
    u8 convert_streaming_text;
    u8 is_jp2;
    u8 force_co64;
    u8 disable_odf_translate;
    u8 disable_brand_rewrite;
    u64 next_flush_chunk_time;
    Bool keep_utc;
    void *moov; // Use void* for unknown types
    void *mdat; // Use void* for unknown types
    void *brand; // Use void* for unknown types
    void *otyp; // Use void* for unknown types
    void *pdin; // Use void* for unknown types
    void *meta; // Use void* for unknown types
    s64 read_byte_offset;
    u64 bytes_removed;
    u32 compress_flags;
    u32 pad_cmov;
    void (*progress_cbk)(void *udta, u64 nb_done, u64 nb_total);
    void *progress_cbk_udta;
    u64 current_top_box_start;
    Bool signal_frag_bounds;
    Bool sample_groups_in_traf;
    u32 FragmentsFlags;
    u32 NextMoofNumber;
    void *moof; // Use void* for unknown types
    u64 segment_start;
    void *moof_list; // Use void* for unknown types
    Bool use_segments, moof_first, append_segment, force_moof_base_offset;
    u32 write_styp;
    void *emsgs; // Use void* for unknown types
    Bool in_sidx_write;
    void *root_sidx; // Use void* for unknown types
    u64 root_sidx_offset;
    u32 root_sidx_index;
    Bool dyn_root_sidx;
    void *root_ssix; // Use void* for unknown types
    Bool is_index_segment;
    void *segment_bs; // Use void* for unknown types
    Bool single_moof_mode;
    u32 single_moof_state;
    Bool force_sidx_v1;
    void *mfra; // Use void* for unknown types
    Bool store_traf_map;
    u64 root_sidx_start_offset, root_sidx_end_offset;
    u64 sidx_start_offset, sidx_end_offset;
    u64 styp_start_offset;
    u64 mdat_end_offset;
    void *seg_ssix, *seg_styp; // Use void* for unknown types
    u32 sidx_pts_store_alloc, sidx_pts_store_count;
    u64 *sidx_pts_store, *sidx_pts_next_store;
    void *main_sidx; // Use void* for unknown types
    u64 main_sidx_end_pos;
    Bool has_pssh_moof;
    void *last_producer_ref_time; // Use void* for unknown types
    void *TopBoxes; // Use void* for unknown types
    s32 es_id_default_sync;
    Bool is_smooth;
    GF_Err (*on_block_out)(void *usr_data, u8 *block, u32 block_size, void *cbk_data, u32 cbk_magic);
    GF_Err (*on_block_patch)(void *usr_data, u8 *block, u32 block_size, u64 block_offset, Bool is_insert);
    void (*on_last_block_start)(void *usr_data);
    void *on_block_out_usr_data;
    u32 on_block_out_block_size;
    u64 fragmented_file_pos;
    u8 *block_buffer;
    u32 block_buffer_size;
    Bool blocks_sent;
    u32 nb_box_init_seg;
    Bool no_inplace_rewrite;
    u32 padding;
    u64 original_moov_offset, original_meta_offset, first_data_toplevel_offset, first_data_toplevel_size;
};

static GF_ISOFile* create_dummy_isofile() {
    GF_ISOFile *isom_file = (GF_ISOFile *)malloc(sizeof(GF_ISOFile));
    if (!isom_file) return NULL;
    memset(isom_file, 0, sizeof(GF_ISOFile));
    return isom_file;
}

static void destroy_dummy_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        free(isom_file);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy ISO file structure
    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    // Use the first byte of data to determine the boolean value
    Bool bool_value = Data[0] % 2 == 0 ? GF_TRUE : GF_FALSE;

    // Call each target function with the dummy ISO file and the boolean value
    gf_isom_reset_fragment_info(isom_file, bool_value);
    gf_isom_has_keep_utc_times(isom_file);
    gf_isom_is_fragmented(isom_file);
    gf_isom_is_smooth_streaming_moov(isom_file);

    // Use the second byte of data for trackNumber if size permits
    u32 trackNumber = (Size > 1) ? Data[1] : 0;
    gf_isom_has_sync_shadows(isom_file, trackNumber);

    // Call gf_isom_get_fragments_count with the boolean value
    gf_isom_get_fragments_count(isom_file, bool_value);

    // Cleanup
    destroy_dummy_isofile(isom_file);

    return 0;
}
    #ifdef INC_MAIN
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    int main(int argc, char *argv[])
    {
        FILE *f;
        uint8_t *data = NULL;
        long size;

        if(argc < 2)
            exit(0);

        f = fopen(argv[1], "rb");
        if(f == NULL)
            exit(0);

        fseek(f, 0, SEEK_END);

        size = ftell(f);
        rewind(f);

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    