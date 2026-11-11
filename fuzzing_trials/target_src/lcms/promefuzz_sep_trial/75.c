// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsOpenProfileFromFile at cmsio0.c:1232:23 in lcms2.h
// cmsIsMatrixShaper at cmsio1.c:806:20 in lcms2.h
// cmsIsTag at cmsio0.c:709:19 in lcms2.h
// cmsSaveProfileToFile at cmsio0.c:1503:20 in lcms2.h
// cmsMD5computeID at cmsmd5.c:257:19 in lcms2.h
// cmsGetTagCount at cmsio0.c:581:26 in lcms2.h
// cmsGetEncodedCMMversion at cmserr.c:30:15 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"

static cmsHPROFILE create_profile_from_data(const uint8_t *Data, size_t Size) {
    // Create a temporary file to store the profile data
    const char *temp_filename = "./dummy_profile.icc";
    FILE *file = fopen(temp_filename, "wb");
    if (!file) {
        return NULL;
    }

    // Write the provided data into the temporary file
    if (fwrite(Data, 1, Size, file) != Size) {
        fclose(file);
        return NULL;
    }
    fclose(file);

    // Open the profile from the temporary file
    cmsHPROFILE hProfile = cmsOpenProfileFromFile(temp_filename, "r");
    remove(temp_filename); // Clean up the temporary file
    return hProfile;
}

static void fuzz_cmsIsMatrixShaper(cmsHPROFILE hProfile) {
    if (hProfile) {
        cmsIsMatrixShaper(hProfile);
    }
}

static void fuzz_cmsIsTag(cmsHPROFILE hProfile) {
    if (hProfile) {
        cmsTagSignature sig = (cmsTagSignature)(rand() % 256); // Random tag signature
        cmsIsTag(hProfile, sig);
    }
}

static void fuzz_cmsSaveProfileToFile(cmsHPROFILE hProfile) {
    if (hProfile) {
        cmsSaveProfileToFile(hProfile, "./dummy_file");
    }
}

static void fuzz_cmsMD5computeID(cmsHPROFILE hProfile) {
    if (hProfile) {
        cmsMD5computeID(hProfile);
    }
}

static void fuzz_cmsGetTagCount(cmsHPROFILE hProfile) {
    if (hProfile) {
        cmsGetTagCount(hProfile);
    }
}

static void fuzz_cmsGetEncodedCMMversion() {
    cmsGetEncodedCMMversion();
}

int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    cmsHPROFILE hProfile = create_profile_from_data(Data, Size);

    fuzz_cmsIsMatrixShaper(hProfile);
    fuzz_cmsIsTag(hProfile);
    fuzz_cmsSaveProfileToFile(hProfile);
    fuzz_cmsMD5computeID(hProfile);
    fuzz_cmsGetTagCount(hProfile);
    fuzz_cmsGetEncodedCMMversion();

    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}