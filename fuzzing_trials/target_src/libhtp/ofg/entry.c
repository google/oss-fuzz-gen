// This is the entry of 158 fuzz drivers:
// 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 2
// 3, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 4
// 3, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 6
// 3, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 8
// 3, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102
// , 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118
// , 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134
// , 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150
// , 151, 152, 153, 154, 155, 156, 157, 158
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_37(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_50(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size);
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
int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_70(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size);
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
int LLVMFuzzerTestOneInput_88(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_89(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_90(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_92(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_93(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_94(const uint8_t *Data, size_t Size);
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
int LLVMFuzzerTestOneInput_112(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_113(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_114(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_115(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_116(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_117(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_118(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_119(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_120(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_121(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_122(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_123(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_124(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_125(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_126(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_127(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_128(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_129(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_130(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_131(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_132(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_133(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_134(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_135(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_136(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_137(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_138(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_139(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_140(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_142(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_143(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_144(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_145(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_146(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_147(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_148(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_149(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_150(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_151(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_152(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_153(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_154(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_155(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_156(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_157(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_158(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 158) {
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
            return LLVMFuzzerTestOneInput_6(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_7(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_10(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_12(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_14(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_15(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_16(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_17(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_18(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_19(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_20(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_21(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_22(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_23(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_24(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_25(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_27(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_28(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_30(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_31(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 32:
            return LLVMFuzzerTestOneInput_33(remainData, remainSize);
        case 33:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 34:
            return LLVMFuzzerTestOneInput_35(remainData, remainSize);
        case 35:
            return LLVMFuzzerTestOneInput_36(remainData, remainSize);
        case 36:
            return LLVMFuzzerTestOneInput_37(remainData, remainSize);
        case 37:
            return LLVMFuzzerTestOneInput_38(remainData, remainSize);
        case 38:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 39:
            return LLVMFuzzerTestOneInput_40(remainData, remainSize);
        case 40:
            return LLVMFuzzerTestOneInput_41(remainData, remainSize);
        case 41:
            return LLVMFuzzerTestOneInput_42(remainData, remainSize);
        case 42:
            return LLVMFuzzerTestOneInput_43(remainData, remainSize);
        case 43:
            return LLVMFuzzerTestOneInput_44(remainData, remainSize);
        case 44:
            return LLVMFuzzerTestOneInput_45(remainData, remainSize);
        case 45:
            return LLVMFuzzerTestOneInput_46(remainData, remainSize);
        case 46:
            return LLVMFuzzerTestOneInput_47(remainData, remainSize);
        case 47:
            return LLVMFuzzerTestOneInput_48(remainData, remainSize);
        case 48:
            return LLVMFuzzerTestOneInput_49(remainData, remainSize);
        case 49:
            return LLVMFuzzerTestOneInput_50(remainData, remainSize);
        case 50:
            return LLVMFuzzerTestOneInput_51(remainData, remainSize);
        case 51:
            return LLVMFuzzerTestOneInput_52(remainData, remainSize);
        case 52:
            return LLVMFuzzerTestOneInput_53(remainData, remainSize);
        case 53:
            return LLVMFuzzerTestOneInput_54(remainData, remainSize);
        case 54:
            return LLVMFuzzerTestOneInput_55(remainData, remainSize);
        case 55:
            return LLVMFuzzerTestOneInput_56(remainData, remainSize);
        case 56:
            return LLVMFuzzerTestOneInput_57(remainData, remainSize);
        case 57:
            return LLVMFuzzerTestOneInput_58(remainData, remainSize);
        case 58:
            return LLVMFuzzerTestOneInput_59(remainData, remainSize);
        case 59:
            return LLVMFuzzerTestOneInput_60(remainData, remainSize);
        case 60:
            return LLVMFuzzerTestOneInput_61(remainData, remainSize);
        case 61:
            return LLVMFuzzerTestOneInput_62(remainData, remainSize);
        case 62:
            return LLVMFuzzerTestOneInput_63(remainData, remainSize);
        case 63:
            return LLVMFuzzerTestOneInput_64(remainData, remainSize);
        case 64:
            return LLVMFuzzerTestOneInput_65(remainData, remainSize);
        case 65:
            return LLVMFuzzerTestOneInput_66(remainData, remainSize);
        case 66:
            return LLVMFuzzerTestOneInput_67(remainData, remainSize);
        case 67:
            return LLVMFuzzerTestOneInput_68(remainData, remainSize);
        case 68:
            return LLVMFuzzerTestOneInput_69(remainData, remainSize);
        case 69:
            return LLVMFuzzerTestOneInput_70(remainData, remainSize);
        case 70:
            return LLVMFuzzerTestOneInput_71(remainData, remainSize);
        case 71:
            return LLVMFuzzerTestOneInput_72(remainData, remainSize);
        case 72:
            return LLVMFuzzerTestOneInput_73(remainData, remainSize);
        case 73:
            return LLVMFuzzerTestOneInput_74(remainData, remainSize);
        case 74:
            return LLVMFuzzerTestOneInput_75(remainData, remainSize);
        case 75:
            return LLVMFuzzerTestOneInput_76(remainData, remainSize);
        case 76:
            return LLVMFuzzerTestOneInput_77(remainData, remainSize);
        case 77:
            return LLVMFuzzerTestOneInput_78(remainData, remainSize);
        case 78:
            return LLVMFuzzerTestOneInput_79(remainData, remainSize);
        case 79:
            return LLVMFuzzerTestOneInput_80(remainData, remainSize);
        case 80:
            return LLVMFuzzerTestOneInput_81(remainData, remainSize);
        case 81:
            return LLVMFuzzerTestOneInput_82(remainData, remainSize);
        case 82:
            return LLVMFuzzerTestOneInput_83(remainData, remainSize);
        case 83:
            return LLVMFuzzerTestOneInput_84(remainData, remainSize);
        case 84:
            return LLVMFuzzerTestOneInput_85(remainData, remainSize);
        case 85:
            return LLVMFuzzerTestOneInput_86(remainData, remainSize);
        case 86:
            return LLVMFuzzerTestOneInput_87(remainData, remainSize);
        case 87:
            return LLVMFuzzerTestOneInput_88(remainData, remainSize);
        case 88:
            return LLVMFuzzerTestOneInput_89(remainData, remainSize);
        case 89:
            return LLVMFuzzerTestOneInput_90(remainData, remainSize);
        case 90:
            return LLVMFuzzerTestOneInput_91(remainData, remainSize);
        case 91:
            return LLVMFuzzerTestOneInput_92(remainData, remainSize);
        case 92:
            return LLVMFuzzerTestOneInput_93(remainData, remainSize);
        case 93:
            return LLVMFuzzerTestOneInput_94(remainData, remainSize);
        case 94:
            return LLVMFuzzerTestOneInput_95(remainData, remainSize);
        case 95:
            return LLVMFuzzerTestOneInput_96(remainData, remainSize);
        case 96:
            return LLVMFuzzerTestOneInput_97(remainData, remainSize);
        case 97:
            return LLVMFuzzerTestOneInput_98(remainData, remainSize);
        case 98:
            return LLVMFuzzerTestOneInput_99(remainData, remainSize);
        case 99:
            return LLVMFuzzerTestOneInput_100(remainData, remainSize);
        case 100:
            return LLVMFuzzerTestOneInput_101(remainData, remainSize);
        case 101:
            return LLVMFuzzerTestOneInput_102(remainData, remainSize);
        case 102:
            return LLVMFuzzerTestOneInput_103(remainData, remainSize);
        case 103:
            return LLVMFuzzerTestOneInput_104(remainData, remainSize);
        case 104:
            return LLVMFuzzerTestOneInput_105(remainData, remainSize);
        case 105:
            return LLVMFuzzerTestOneInput_106(remainData, remainSize);
        case 106:
            return LLVMFuzzerTestOneInput_107(remainData, remainSize);
        case 107:
            return LLVMFuzzerTestOneInput_108(remainData, remainSize);
        case 108:
            return LLVMFuzzerTestOneInput_109(remainData, remainSize);
        case 109:
            return LLVMFuzzerTestOneInput_110(remainData, remainSize);
        case 110:
            return LLVMFuzzerTestOneInput_111(remainData, remainSize);
        case 111:
            return LLVMFuzzerTestOneInput_112(remainData, remainSize);
        case 112:
            return LLVMFuzzerTestOneInput_113(remainData, remainSize);
        case 113:
            return LLVMFuzzerTestOneInput_114(remainData, remainSize);
        case 114:
            return LLVMFuzzerTestOneInput_115(remainData, remainSize);
        case 115:
            return LLVMFuzzerTestOneInput_116(remainData, remainSize);
        case 116:
            return LLVMFuzzerTestOneInput_117(remainData, remainSize);
        case 117:
            return LLVMFuzzerTestOneInput_118(remainData, remainSize);
        case 118:
            return LLVMFuzzerTestOneInput_119(remainData, remainSize);
        case 119:
            return LLVMFuzzerTestOneInput_120(remainData, remainSize);
        case 120:
            return LLVMFuzzerTestOneInput_121(remainData, remainSize);
        case 121:
            return LLVMFuzzerTestOneInput_122(remainData, remainSize);
        case 122:
            return LLVMFuzzerTestOneInput_123(remainData, remainSize);
        case 123:
            return LLVMFuzzerTestOneInput_124(remainData, remainSize);
        case 124:
            return LLVMFuzzerTestOneInput_125(remainData, remainSize);
        case 125:
            return LLVMFuzzerTestOneInput_126(remainData, remainSize);
        case 126:
            return LLVMFuzzerTestOneInput_127(remainData, remainSize);
        case 127:
            return LLVMFuzzerTestOneInput_128(remainData, remainSize);
        case 128:
            return LLVMFuzzerTestOneInput_129(remainData, remainSize);
        case 129:
            return LLVMFuzzerTestOneInput_130(remainData, remainSize);
        case 130:
            return LLVMFuzzerTestOneInput_131(remainData, remainSize);
        case 131:
            return LLVMFuzzerTestOneInput_132(remainData, remainSize);
        case 132:
            return LLVMFuzzerTestOneInput_133(remainData, remainSize);
        case 133:
            return LLVMFuzzerTestOneInput_134(remainData, remainSize);
        case 134:
            return LLVMFuzzerTestOneInput_135(remainData, remainSize);
        case 135:
            return LLVMFuzzerTestOneInput_136(remainData, remainSize);
        case 136:
            return LLVMFuzzerTestOneInput_137(remainData, remainSize);
        case 137:
            return LLVMFuzzerTestOneInput_138(remainData, remainSize);
        case 138:
            return LLVMFuzzerTestOneInput_139(remainData, remainSize);
        case 139:
            return LLVMFuzzerTestOneInput_140(remainData, remainSize);
        case 140:
            return LLVMFuzzerTestOneInput_141(remainData, remainSize);
        case 141:
            return LLVMFuzzerTestOneInput_142(remainData, remainSize);
        case 142:
            return LLVMFuzzerTestOneInput_143(remainData, remainSize);
        case 143:
            return LLVMFuzzerTestOneInput_144(remainData, remainSize);
        case 144:
            return LLVMFuzzerTestOneInput_145(remainData, remainSize);
        case 145:
            return LLVMFuzzerTestOneInput_146(remainData, remainSize);
        case 146:
            return LLVMFuzzerTestOneInput_147(remainData, remainSize);
        case 147:
            return LLVMFuzzerTestOneInput_148(remainData, remainSize);
        case 148:
            return LLVMFuzzerTestOneInput_149(remainData, remainSize);
        case 149:
            return LLVMFuzzerTestOneInput_150(remainData, remainSize);
        case 150:
            return LLVMFuzzerTestOneInput_151(remainData, remainSize);
        case 151:
            return LLVMFuzzerTestOneInput_152(remainData, remainSize);
        case 152:
            return LLVMFuzzerTestOneInput_153(remainData, remainSize);
        case 153:
            return LLVMFuzzerTestOneInput_154(remainData, remainSize);
        case 154:
            return LLVMFuzzerTestOneInput_155(remainData, remainSize);
        case 155:
            return LLVMFuzzerTestOneInput_156(remainData, remainSize);
        case 156:
            return LLVMFuzzerTestOneInput_157(remainData, remainSize);
        case 157:
            return LLVMFuzzerTestOneInput_158(remainData, remainSize);
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

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput(data, size);

    free(data);
    fclose(f);
    return 0;
}
