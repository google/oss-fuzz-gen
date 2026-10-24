// This is the entry of 218 fuzz drivers:
// 1, 2, 3, 4, 5, 7, 8, 9, 10, 14, 15, 16, 17, 19, 20, 21, 23, 25, 26, 27, 28, 29, 
// 30, 31, 32, 33, 35, 36, 37, 38, 39, 40, 42, 43, 44, 45, 46, 47, 48, 49, 50, 52, 
// 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 67, 68, 70, 73, 74, 75, 76, 
// 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 90, 91, 93, 95, 96, 97, 98, 99, 
// 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 113, 114, 115, 117, 
// 118, 119, 120, 121, 122, 123, 124, 125, 127, 129, 130, 133, 134, 136, 137, 140, 
// 141, 144, 145, 148, 149, 150, 152, 154, 155, 156, 158, 160, 162, 165, 166, 167, 
// 169, 171, 172, 173, 174, 175, 177, 179, 180, 181, 182, 183, 184, 187, 188, 191, 
// 192, 193, 194, 195, 196, 197, 199, 200, 201, 202, 203, 204, 205, 206, 208, 209, 
// 210, 211, 212, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 
// 228, 229, 230, 232, 234, 235, 236, 237, 238, 239, 240, 243, 244, 245, 246, 247, 
// 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 
// 264, 266, 267, 268, 269, 270, 273, 274
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_56(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_61(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_70(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_73(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_74(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_77(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_81(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_82(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_83(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_86(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_87(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_89(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_90(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_93(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_97(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_98(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_99(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_100(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_101(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_102(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_103(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_104(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_105(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_106(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_107(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_108(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_109(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_110(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_111(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_113(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_114(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_115(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_117(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_118(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_119(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_120(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_121(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_122(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_123(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_124(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_125(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_127(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_129(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_130(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_133(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_134(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_136(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_137(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_140(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_144(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_145(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_148(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_149(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_150(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_152(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_154(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_155(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_156(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_158(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_160(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_162(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_165(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_166(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_167(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_169(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_171(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_172(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_173(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_174(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_175(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_177(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_179(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_180(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_181(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_182(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_183(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_184(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_187(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_188(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_191(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_192(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_193(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_194(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_195(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_196(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_197(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_199(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_200(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_201(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_202(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_203(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_204(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_205(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_206(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_208(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_209(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_210(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_211(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_212(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_214(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_215(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_216(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_217(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_218(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_219(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_220(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_221(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_222(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_223(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_224(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_225(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_226(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_228(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_229(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_230(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_232(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_234(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_235(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_236(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_237(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_238(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_239(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_240(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_243(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_244(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_245(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_246(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_247(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_248(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_249(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_250(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_251(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_252(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_253(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_254(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_255(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_256(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_257(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_258(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_259(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_260(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_261(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_262(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_263(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_264(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_266(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_267(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_268(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_269(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_270(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_273(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_274(const uint8_t *Data, size_t Size);

// Entry function
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Driver selector
    if (Size < 1) {
        return 0;
    }
    const uint8_t *selector = Data;
    unsigned int driverIndex = 0;
    memcpy(&driverIndex, selector, 1);

    // Remain data and size
    const uint8_t *remainData = Data + 1;
    size_t remainSize = Size - 1;
    if (remainSize == 0) {
        return 0;
    }

    // Select driver
    switch (driverIndex % 218) {
        case 0:
            return LLVMFuzzerTestOneInput_1(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_3(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_5(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_14(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_17(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_19(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_20(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_21(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_23(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_25(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_27(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_28(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_31(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_33(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_35(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_36(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_37(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_38(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_40(remainData, remainSize);
        case 32:
            return LLVMFuzzerTestOneInput_42(remainData, remainSize);
        case 33:
            return LLVMFuzzerTestOneInput_43(remainData, remainSize);
        case 34:
            return LLVMFuzzerTestOneInput_44(remainData, remainSize);
        case 35:
            return LLVMFuzzerTestOneInput_45(remainData, remainSize);
        case 36:
            return LLVMFuzzerTestOneInput_46(remainData, remainSize);
        case 37:
            return LLVMFuzzerTestOneInput_47(remainData, remainSize);
        case 38:
            return LLVMFuzzerTestOneInput_48(remainData, remainSize);
        case 39:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 40:
            return LLVMFuzzerTestOneInput_50(remainData, remainSize);
        case 41:
            return LLVMFuzzerTestOneInput_52(remainData, remainSize);
        case 42:
            return LLVMFuzzerTestOneInput_53(remainData, remainSize);
        case 43:
            return LLVMFuzzerTestOneInput_54(remainData, remainSize);
        case 44:
            return LLVMFuzzerTestOneInput_55(remainData, remainSize);
        case 45:
            return LLVMFuzzerTestOneInput_56(remainData, remainSize);
        case 46:
            return LLVMFuzzerTestOneInput_57(remainData, remainSize);
        case 47:
            return LLVMFuzzerTestOneInput_58(remainData, remainSize);
        case 48:
            return LLVMFuzzerTestOneInput_59(remainData, remainSize);
        case 49:
            return LLVMFuzzerTestOneInput_60(remainData, remainSize);
        case 50:
            return LLVMFuzzerTestOneInput_61(remainData, remainSize);
        case 51:
            return LLVMFuzzerTestOneInput_62(remainData, remainSize);
        case 52:
            return LLVMFuzzerTestOneInput_63(remainData, remainSize);
        case 53:
            return LLVMFuzzerTestOneInput_64(remainData, remainSize);
        case 54:
            return LLVMFuzzerTestOneInput_65(remainData, remainSize);
        case 55:
            return LLVMFuzzerTestOneInput_67(remainData, remainSize);
        case 56:
            return LLVMFuzzerTestOneInput_68(remainData, remainSize);
        case 57:
            return LLVMFuzzerTestOneInput_70(remainData, remainSize);
        case 58:
            return LLVMFuzzerTestOneInput_73(remainData, remainSize);
        case 59:
            return LLVMFuzzerTestOneInput_74(remainData, remainSize);
        case 60:
            return LLVMFuzzerTestOneInput_75(remainData, remainSize);
        case 61:
            return LLVMFuzzerTestOneInput_76(remainData, remainSize);
        case 62:
            return LLVMFuzzerTestOneInput_77(remainData, remainSize);
        case 63:
            return LLVMFuzzerTestOneInput_78(remainData, remainSize);
        case 64:
            return LLVMFuzzerTestOneInput_79(remainData, remainSize);
        case 65:
            return LLVMFuzzerTestOneInput_80(remainData, remainSize);
        case 66:
            return LLVMFuzzerTestOneInput_81(remainData, remainSize);
        case 67:
            return LLVMFuzzerTestOneInput_82(remainData, remainSize);
        case 68:
            return LLVMFuzzerTestOneInput_83(remainData, remainSize);
        case 69:
            return LLVMFuzzerTestOneInput_84(remainData, remainSize);
        case 70:
            return LLVMFuzzerTestOneInput_85(remainData, remainSize);
        case 71:
            return LLVMFuzzerTestOneInput_86(remainData, remainSize);
        case 72:
            return LLVMFuzzerTestOneInput_87(remainData, remainSize);
        case 73:
            return LLVMFuzzerTestOneInput_89(remainData, remainSize);
        case 74:
            return LLVMFuzzerTestOneInput_90(remainData, remainSize);
        case 75:
            return LLVMFuzzerTestOneInput_91(remainData, remainSize);
        case 76:
            return LLVMFuzzerTestOneInput_93(remainData, remainSize);
        case 77:
            return LLVMFuzzerTestOneInput_95(remainData, remainSize);
        case 78:
            return LLVMFuzzerTestOneInput_96(remainData, remainSize);
        case 79:
            return LLVMFuzzerTestOneInput_97(remainData, remainSize);
        case 80:
            return LLVMFuzzerTestOneInput_98(remainData, remainSize);
        case 81:
            return LLVMFuzzerTestOneInput_99(remainData, remainSize);
        case 82:
            return LLVMFuzzerTestOneInput_100(remainData, remainSize);
        case 83:
            return LLVMFuzzerTestOneInput_101(remainData, remainSize);
        case 84:
            return LLVMFuzzerTestOneInput_102(remainData, remainSize);
        case 85:
            return LLVMFuzzerTestOneInput_103(remainData, remainSize);
        case 86:
            return LLVMFuzzerTestOneInput_104(remainData, remainSize);
        case 87:
            return LLVMFuzzerTestOneInput_105(remainData, remainSize);
        case 88:
            return LLVMFuzzerTestOneInput_106(remainData, remainSize);
        case 89:
            return LLVMFuzzerTestOneInput_107(remainData, remainSize);
        case 90:
            return LLVMFuzzerTestOneInput_108(remainData, remainSize);
        case 91:
            return LLVMFuzzerTestOneInput_109(remainData, remainSize);
        case 92:
            return LLVMFuzzerTestOneInput_110(remainData, remainSize);
        case 93:
            return LLVMFuzzerTestOneInput_111(remainData, remainSize);
        case 94:
            return LLVMFuzzerTestOneInput_113(remainData, remainSize);
        case 95:
            return LLVMFuzzerTestOneInput_114(remainData, remainSize);
        case 96:
            return LLVMFuzzerTestOneInput_115(remainData, remainSize);
        case 97:
            return LLVMFuzzerTestOneInput_117(remainData, remainSize);
        case 98:
            return LLVMFuzzerTestOneInput_118(remainData, remainSize);
        case 99:
            return LLVMFuzzerTestOneInput_119(remainData, remainSize);
        case 100:
            return LLVMFuzzerTestOneInput_120(remainData, remainSize);
        case 101:
            return LLVMFuzzerTestOneInput_121(remainData, remainSize);
        case 102:
            return LLVMFuzzerTestOneInput_122(remainData, remainSize);
        case 103:
            return LLVMFuzzerTestOneInput_123(remainData, remainSize);
        case 104:
            return LLVMFuzzerTestOneInput_124(remainData, remainSize);
        case 105:
            return LLVMFuzzerTestOneInput_125(remainData, remainSize);
        case 106:
            return LLVMFuzzerTestOneInput_127(remainData, remainSize);
        case 107:
            return LLVMFuzzerTestOneInput_129(remainData, remainSize);
        case 108:
            return LLVMFuzzerTestOneInput_130(remainData, remainSize);
        case 109:
            return LLVMFuzzerTestOneInput_133(remainData, remainSize);
        case 110:
            return LLVMFuzzerTestOneInput_134(remainData, remainSize);
        case 111:
            return LLVMFuzzerTestOneInput_136(remainData, remainSize);
        case 112:
            return LLVMFuzzerTestOneInput_137(remainData, remainSize);
        case 113:
            return LLVMFuzzerTestOneInput_140(remainData, remainSize);
        case 114:
            return LLVMFuzzerTestOneInput_141(remainData, remainSize);
        case 115:
            return LLVMFuzzerTestOneInput_144(remainData, remainSize);
        case 116:
            return LLVMFuzzerTestOneInput_145(remainData, remainSize);
        case 117:
            return LLVMFuzzerTestOneInput_148(remainData, remainSize);
        case 118:
            return LLVMFuzzerTestOneInput_149(remainData, remainSize);
        case 119:
            return LLVMFuzzerTestOneInput_150(remainData, remainSize);
        case 120:
            return LLVMFuzzerTestOneInput_152(remainData, remainSize);
        case 121:
            return LLVMFuzzerTestOneInput_154(remainData, remainSize);
        case 122:
            return LLVMFuzzerTestOneInput_155(remainData, remainSize);
        case 123:
            return LLVMFuzzerTestOneInput_156(remainData, remainSize);
        case 124:
            return LLVMFuzzerTestOneInput_158(remainData, remainSize);
        case 125:
            return LLVMFuzzerTestOneInput_160(remainData, remainSize);
        case 126:
            return LLVMFuzzerTestOneInput_162(remainData, remainSize);
        case 127:
            return LLVMFuzzerTestOneInput_165(remainData, remainSize);
        case 128:
            return LLVMFuzzerTestOneInput_166(remainData, remainSize);
        case 129:
            return LLVMFuzzerTestOneInput_167(remainData, remainSize);
        case 130:
            return LLVMFuzzerTestOneInput_169(remainData, remainSize);
        case 131:
            return LLVMFuzzerTestOneInput_171(remainData, remainSize);
        case 132:
            return LLVMFuzzerTestOneInput_172(remainData, remainSize);
        case 133:
            return LLVMFuzzerTestOneInput_173(remainData, remainSize);
        case 134:
            return LLVMFuzzerTestOneInput_174(remainData, remainSize);
        case 135:
            return LLVMFuzzerTestOneInput_175(remainData, remainSize);
        case 136:
            return LLVMFuzzerTestOneInput_177(remainData, remainSize);
        case 137:
            return LLVMFuzzerTestOneInput_179(remainData, remainSize);
        case 138:
            return LLVMFuzzerTestOneInput_180(remainData, remainSize);
        case 139:
            return LLVMFuzzerTestOneInput_181(remainData, remainSize);
        case 140:
            return LLVMFuzzerTestOneInput_182(remainData, remainSize);
        case 141:
            return LLVMFuzzerTestOneInput_183(remainData, remainSize);
        case 142:
            return LLVMFuzzerTestOneInput_184(remainData, remainSize);
        case 143:
            return LLVMFuzzerTestOneInput_187(remainData, remainSize);
        case 144:
            return LLVMFuzzerTestOneInput_188(remainData, remainSize);
        case 145:
            return LLVMFuzzerTestOneInput_191(remainData, remainSize);
        case 146:
            return LLVMFuzzerTestOneInput_192(remainData, remainSize);
        case 147:
            return LLVMFuzzerTestOneInput_193(remainData, remainSize);
        case 148:
            return LLVMFuzzerTestOneInput_194(remainData, remainSize);
        case 149:
            return LLVMFuzzerTestOneInput_195(remainData, remainSize);
        case 150:
            return LLVMFuzzerTestOneInput_196(remainData, remainSize);
        case 151:
            return LLVMFuzzerTestOneInput_197(remainData, remainSize);
        case 152:
            return LLVMFuzzerTestOneInput_199(remainData, remainSize);
        case 153:
            return LLVMFuzzerTestOneInput_200(remainData, remainSize);
        case 154:
            return LLVMFuzzerTestOneInput_201(remainData, remainSize);
        case 155:
            return LLVMFuzzerTestOneInput_202(remainData, remainSize);
        case 156:
            return LLVMFuzzerTestOneInput_203(remainData, remainSize);
        case 157:
            return LLVMFuzzerTestOneInput_204(remainData, remainSize);
        case 158:
            return LLVMFuzzerTestOneInput_205(remainData, remainSize);
        case 159:
            return LLVMFuzzerTestOneInput_206(remainData, remainSize);
        case 160:
            return LLVMFuzzerTestOneInput_208(remainData, remainSize);
        case 161:
            return LLVMFuzzerTestOneInput_209(remainData, remainSize);
        case 162:
            return LLVMFuzzerTestOneInput_210(remainData, remainSize);
        case 163:
            return LLVMFuzzerTestOneInput_211(remainData, remainSize);
        case 164:
            return LLVMFuzzerTestOneInput_212(remainData, remainSize);
        case 165:
            return LLVMFuzzerTestOneInput_214(remainData, remainSize);
        case 166:
            return LLVMFuzzerTestOneInput_215(remainData, remainSize);
        case 167:
            return LLVMFuzzerTestOneInput_216(remainData, remainSize);
        case 168:
            return LLVMFuzzerTestOneInput_217(remainData, remainSize);
        case 169:
            return LLVMFuzzerTestOneInput_218(remainData, remainSize);
        case 170:
            return LLVMFuzzerTestOneInput_219(remainData, remainSize);
        case 171:
            return LLVMFuzzerTestOneInput_220(remainData, remainSize);
        case 172:
            return LLVMFuzzerTestOneInput_221(remainData, remainSize);
        case 173:
            return LLVMFuzzerTestOneInput_222(remainData, remainSize);
        case 174:
            return LLVMFuzzerTestOneInput_223(remainData, remainSize);
        case 175:
            return LLVMFuzzerTestOneInput_224(remainData, remainSize);
        case 176:
            return LLVMFuzzerTestOneInput_225(remainData, remainSize);
        case 177:
            return LLVMFuzzerTestOneInput_226(remainData, remainSize);
        case 178:
            return LLVMFuzzerTestOneInput_228(remainData, remainSize);
        case 179:
            return LLVMFuzzerTestOneInput_229(remainData, remainSize);
        case 180:
            return LLVMFuzzerTestOneInput_230(remainData, remainSize);
        case 181:
            return LLVMFuzzerTestOneInput_232(remainData, remainSize);
        case 182:
            return LLVMFuzzerTestOneInput_234(remainData, remainSize);
        case 183:
            return LLVMFuzzerTestOneInput_235(remainData, remainSize);
        case 184:
            return LLVMFuzzerTestOneInput_236(remainData, remainSize);
        case 185:
            return LLVMFuzzerTestOneInput_237(remainData, remainSize);
        case 186:
            return LLVMFuzzerTestOneInput_238(remainData, remainSize);
        case 187:
            return LLVMFuzzerTestOneInput_239(remainData, remainSize);
        case 188:
            return LLVMFuzzerTestOneInput_240(remainData, remainSize);
        case 189:
            return LLVMFuzzerTestOneInput_243(remainData, remainSize);
        case 190:
            return LLVMFuzzerTestOneInput_244(remainData, remainSize);
        case 191:
            return LLVMFuzzerTestOneInput_245(remainData, remainSize);
        case 192:
            return LLVMFuzzerTestOneInput_246(remainData, remainSize);
        case 193:
            return LLVMFuzzerTestOneInput_247(remainData, remainSize);
        case 194:
            return LLVMFuzzerTestOneInput_248(remainData, remainSize);
        case 195:
            return LLVMFuzzerTestOneInput_249(remainData, remainSize);
        case 196:
            return LLVMFuzzerTestOneInput_250(remainData, remainSize);
        case 197:
            return LLVMFuzzerTestOneInput_251(remainData, remainSize);
        case 198:
            return LLVMFuzzerTestOneInput_252(remainData, remainSize);
        case 199:
            return LLVMFuzzerTestOneInput_253(remainData, remainSize);
        case 200:
            return LLVMFuzzerTestOneInput_254(remainData, remainSize);
        case 201:
            return LLVMFuzzerTestOneInput_255(remainData, remainSize);
        case 202:
            return LLVMFuzzerTestOneInput_256(remainData, remainSize);
        case 203:
            return LLVMFuzzerTestOneInput_257(remainData, remainSize);
        case 204:
            return LLVMFuzzerTestOneInput_258(remainData, remainSize);
        case 205:
            return LLVMFuzzerTestOneInput_259(remainData, remainSize);
        case 206:
            return LLVMFuzzerTestOneInput_260(remainData, remainSize);
        case 207:
            return LLVMFuzzerTestOneInput_261(remainData, remainSize);
        case 208:
            return LLVMFuzzerTestOneInput_262(remainData, remainSize);
        case 209:
            return LLVMFuzzerTestOneInput_263(remainData, remainSize);
        case 210:
            return LLVMFuzzerTestOneInput_264(remainData, remainSize);
        case 211:
            return LLVMFuzzerTestOneInput_266(remainData, remainSize);
        case 212:
            return LLVMFuzzerTestOneInput_267(remainData, remainSize);
        case 213:
            return LLVMFuzzerTestOneInput_268(remainData, remainSize);
        case 214:
            return LLVMFuzzerTestOneInput_269(remainData, remainSize);
        case 215:
            return LLVMFuzzerTestOneInput_270(remainData, remainSize);
        case 216:
            return LLVMFuzzerTestOneInput_273(remainData, remainSize);
        case 217:
            return LLVMFuzzerTestOneInput_274(remainData, remainSize);
        default:
            return 0;
    }
    return 0;
}

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

    if(size < 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size+1);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);
    data[size] = '\0';

    LLVMFuzzerTestOneInput(data, size);

    free(data);
    fclose(f);
    return 0;
}

