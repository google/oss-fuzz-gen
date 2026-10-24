// This is the entry of 568 fuzz drivers:
// 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 2
// 3, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 4
// 3, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 6
// 3, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 8
// 3, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102
// , 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118
// , 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134
// , 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150
// , 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166
// , 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182
// , 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198
// , 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214
// , 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230
// , 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246
// , 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262
// , 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278
// , 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294
// , 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310
// , 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326
// , 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342
// , 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358
// , 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374
// , 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390
// , 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406
// , 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422
// , 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438
// , 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454
// , 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470
// , 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486
// , 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502
// , 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518
// , 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534
// , 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550
// , 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566
// , 567, 568
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
int LLVMFuzzerTestOneInput_159(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_160(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_161(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_162(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_163(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_164(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_165(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_166(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_167(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_168(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_169(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_170(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_171(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_172(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_173(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_174(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_175(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_176(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_177(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_178(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_179(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_180(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_181(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_182(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_183(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_184(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_185(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_186(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_187(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_188(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_189(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_190(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_191(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_192(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_193(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_194(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_195(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_196(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_197(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_198(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_199(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_200(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_201(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_202(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_203(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_204(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_205(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_206(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_207(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_208(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_209(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_210(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_211(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_212(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_213(const uint8_t *Data, size_t Size);
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
int LLVMFuzzerTestOneInput_227(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_228(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_229(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_230(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_231(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_232(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_233(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_234(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_235(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_236(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_237(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_238(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_239(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_240(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_241(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_242(const uint8_t *Data, size_t Size);
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
int LLVMFuzzerTestOneInput_265(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_266(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_267(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_268(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_269(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_270(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_271(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_272(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_273(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_274(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_275(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_276(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_277(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_278(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_279(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_280(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_281(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_282(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_283(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_284(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_285(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_286(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_287(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_288(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_289(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_290(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_291(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_292(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_293(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_294(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_295(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_296(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_297(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_298(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_299(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_300(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_301(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_302(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_303(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_304(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_305(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_306(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_307(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_308(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_309(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_310(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_311(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_312(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_313(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_314(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_315(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_316(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_317(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_318(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_319(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_320(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_321(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_322(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_323(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_324(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_325(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_326(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_327(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_328(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_329(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_330(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_331(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_332(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_333(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_334(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_335(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_336(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_337(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_338(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_339(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_340(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_341(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_342(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_343(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_344(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_345(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_346(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_347(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_348(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_349(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_350(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_351(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_352(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_353(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_354(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_355(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_356(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_357(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_358(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_359(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_360(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_361(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_362(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_363(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_364(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_365(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_366(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_367(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_368(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_369(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_370(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_371(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_372(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_373(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_374(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_375(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_376(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_377(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_378(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_379(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_380(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_381(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_382(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_383(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_384(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_385(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_386(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_387(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_388(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_389(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_390(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_391(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_392(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_393(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_394(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_395(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_396(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_397(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_398(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_399(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_400(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_401(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_402(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_403(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_404(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_405(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_406(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_407(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_408(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_409(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_410(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_411(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_412(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_413(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_414(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_415(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_416(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_417(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_418(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_419(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_420(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_421(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_422(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_423(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_424(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_425(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_426(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_427(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_428(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_429(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_430(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_431(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_432(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_433(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_434(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_435(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_436(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_437(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_438(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_439(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_440(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_441(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_442(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_443(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_444(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_445(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_446(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_447(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_448(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_449(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_450(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_451(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_452(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_453(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_454(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_455(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_456(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_457(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_458(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_459(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_460(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_461(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_462(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_463(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_464(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_465(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_466(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_467(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_468(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_469(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_470(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_471(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_472(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_473(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_474(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_475(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_476(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_477(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_478(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_479(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_480(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_481(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_482(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_483(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_484(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_485(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_486(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_487(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_488(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_489(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_490(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_491(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_492(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_493(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_494(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_495(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_496(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_497(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_498(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_499(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_500(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_501(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_502(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_503(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_504(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_505(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_506(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_507(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_508(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_509(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_510(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_511(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_512(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_513(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_514(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_515(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_516(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_517(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_518(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_519(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_520(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_521(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_522(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_523(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_524(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_525(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_526(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_527(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_528(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_529(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_530(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_531(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_532(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_533(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_534(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_535(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_536(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_537(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_538(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_539(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_540(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_541(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_542(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_543(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_544(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_545(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_546(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_547(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_548(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_549(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_550(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_551(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_552(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_553(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_554(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_555(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_556(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_557(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_558(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_559(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_560(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_561(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_562(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_563(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_564(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_565(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_566(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_567(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_568(const uint8_t *Data, size_t Size);

// Entry function
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Driver selector
    if (Size < 2) {
        return 0;
    }
    const uint8_t *selector = Data;
    unsigned int driverIndex = 0;
    memcpy(&driverIndex, selector, 2);

    // Remain data and size
    const uint8_t *remainData = Data + 2;
    size_t remainSize = Size - 2;
    if (remainSize == 0) {
        return 0;
    }

    // Select driver
    switch (driverIndex % 568) {
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
        case 158:
            return LLVMFuzzerTestOneInput_159(remainData, remainSize);
        case 159:
            return LLVMFuzzerTestOneInput_160(remainData, remainSize);
        case 160:
            return LLVMFuzzerTestOneInput_161(remainData, remainSize);
        case 161:
            return LLVMFuzzerTestOneInput_162(remainData, remainSize);
        case 162:
            return LLVMFuzzerTestOneInput_163(remainData, remainSize);
        case 163:
            return LLVMFuzzerTestOneInput_164(remainData, remainSize);
        case 164:
            return LLVMFuzzerTestOneInput_165(remainData, remainSize);
        case 165:
            return LLVMFuzzerTestOneInput_166(remainData, remainSize);
        case 166:
            return LLVMFuzzerTestOneInput_167(remainData, remainSize);
        case 167:
            return LLVMFuzzerTestOneInput_168(remainData, remainSize);
        case 168:
            return LLVMFuzzerTestOneInput_169(remainData, remainSize);
        case 169:
            return LLVMFuzzerTestOneInput_170(remainData, remainSize);
        case 170:
            return LLVMFuzzerTestOneInput_171(remainData, remainSize);
        case 171:
            return LLVMFuzzerTestOneInput_172(remainData, remainSize);
        case 172:
            return LLVMFuzzerTestOneInput_173(remainData, remainSize);
        case 173:
            return LLVMFuzzerTestOneInput_174(remainData, remainSize);
        case 174:
            return LLVMFuzzerTestOneInput_175(remainData, remainSize);
        case 175:
            return LLVMFuzzerTestOneInput_176(remainData, remainSize);
        case 176:
            return LLVMFuzzerTestOneInput_177(remainData, remainSize);
        case 177:
            return LLVMFuzzerTestOneInput_178(remainData, remainSize);
        case 178:
            return LLVMFuzzerTestOneInput_179(remainData, remainSize);
        case 179:
            return LLVMFuzzerTestOneInput_180(remainData, remainSize);
        case 180:
            return LLVMFuzzerTestOneInput_181(remainData, remainSize);
        case 181:
            return LLVMFuzzerTestOneInput_182(remainData, remainSize);
        case 182:
            return LLVMFuzzerTestOneInput_183(remainData, remainSize);
        case 183:
            return LLVMFuzzerTestOneInput_184(remainData, remainSize);
        case 184:
            return LLVMFuzzerTestOneInput_185(remainData, remainSize);
        case 185:
            return LLVMFuzzerTestOneInput_186(remainData, remainSize);
        case 186:
            return LLVMFuzzerTestOneInput_187(remainData, remainSize);
        case 187:
            return LLVMFuzzerTestOneInput_188(remainData, remainSize);
        case 188:
            return LLVMFuzzerTestOneInput_189(remainData, remainSize);
        case 189:
            return LLVMFuzzerTestOneInput_190(remainData, remainSize);
        case 190:
            return LLVMFuzzerTestOneInput_191(remainData, remainSize);
        case 191:
            return LLVMFuzzerTestOneInput_192(remainData, remainSize);
        case 192:
            return LLVMFuzzerTestOneInput_193(remainData, remainSize);
        case 193:
            return LLVMFuzzerTestOneInput_194(remainData, remainSize);
        case 194:
            return LLVMFuzzerTestOneInput_195(remainData, remainSize);
        case 195:
            return LLVMFuzzerTestOneInput_196(remainData, remainSize);
        case 196:
            return LLVMFuzzerTestOneInput_197(remainData, remainSize);
        case 197:
            return LLVMFuzzerTestOneInput_198(remainData, remainSize);
        case 198:
            return LLVMFuzzerTestOneInput_199(remainData, remainSize);
        case 199:
            return LLVMFuzzerTestOneInput_200(remainData, remainSize);
        case 200:
            return LLVMFuzzerTestOneInput_201(remainData, remainSize);
        case 201:
            return LLVMFuzzerTestOneInput_202(remainData, remainSize);
        case 202:
            return LLVMFuzzerTestOneInput_203(remainData, remainSize);
        case 203:
            return LLVMFuzzerTestOneInput_204(remainData, remainSize);
        case 204:
            return LLVMFuzzerTestOneInput_205(remainData, remainSize);
        case 205:
            return LLVMFuzzerTestOneInput_206(remainData, remainSize);
        case 206:
            return LLVMFuzzerTestOneInput_207(remainData, remainSize);
        case 207:
            return LLVMFuzzerTestOneInput_208(remainData, remainSize);
        case 208:
            return LLVMFuzzerTestOneInput_209(remainData, remainSize);
        case 209:
            return LLVMFuzzerTestOneInput_210(remainData, remainSize);
        case 210:
            return LLVMFuzzerTestOneInput_211(remainData, remainSize);
        case 211:
            return LLVMFuzzerTestOneInput_212(remainData, remainSize);
        case 212:
            return LLVMFuzzerTestOneInput_213(remainData, remainSize);
        case 213:
            return LLVMFuzzerTestOneInput_214(remainData, remainSize);
        case 214:
            return LLVMFuzzerTestOneInput_215(remainData, remainSize);
        case 215:
            return LLVMFuzzerTestOneInput_216(remainData, remainSize);
        case 216:
            return LLVMFuzzerTestOneInput_217(remainData, remainSize);
        case 217:
            return LLVMFuzzerTestOneInput_218(remainData, remainSize);
        case 218:
            return LLVMFuzzerTestOneInput_219(remainData, remainSize);
        case 219:
            return LLVMFuzzerTestOneInput_220(remainData, remainSize);
        case 220:
            return LLVMFuzzerTestOneInput_221(remainData, remainSize);
        case 221:
            return LLVMFuzzerTestOneInput_222(remainData, remainSize);
        case 222:
            return LLVMFuzzerTestOneInput_223(remainData, remainSize);
        case 223:
            return LLVMFuzzerTestOneInput_224(remainData, remainSize);
        case 224:
            return LLVMFuzzerTestOneInput_225(remainData, remainSize);
        case 225:
            return LLVMFuzzerTestOneInput_226(remainData, remainSize);
        case 226:
            return LLVMFuzzerTestOneInput_227(remainData, remainSize);
        case 227:
            return LLVMFuzzerTestOneInput_228(remainData, remainSize);
        case 228:
            return LLVMFuzzerTestOneInput_229(remainData, remainSize);
        case 229:
            return LLVMFuzzerTestOneInput_230(remainData, remainSize);
        case 230:
            return LLVMFuzzerTestOneInput_231(remainData, remainSize);
        case 231:
            return LLVMFuzzerTestOneInput_232(remainData, remainSize);
        case 232:
            return LLVMFuzzerTestOneInput_233(remainData, remainSize);
        case 233:
            return LLVMFuzzerTestOneInput_234(remainData, remainSize);
        case 234:
            return LLVMFuzzerTestOneInput_235(remainData, remainSize);
        case 235:
            return LLVMFuzzerTestOneInput_236(remainData, remainSize);
        case 236:
            return LLVMFuzzerTestOneInput_237(remainData, remainSize);
        case 237:
            return LLVMFuzzerTestOneInput_238(remainData, remainSize);
        case 238:
            return LLVMFuzzerTestOneInput_239(remainData, remainSize);
        case 239:
            return LLVMFuzzerTestOneInput_240(remainData, remainSize);
        case 240:
            return LLVMFuzzerTestOneInput_241(remainData, remainSize);
        case 241:
            return LLVMFuzzerTestOneInput_242(remainData, remainSize);
        case 242:
            return LLVMFuzzerTestOneInput_243(remainData, remainSize);
        case 243:
            return LLVMFuzzerTestOneInput_244(remainData, remainSize);
        case 244:
            return LLVMFuzzerTestOneInput_245(remainData, remainSize);
        case 245:
            return LLVMFuzzerTestOneInput_246(remainData, remainSize);
        case 246:
            return LLVMFuzzerTestOneInput_247(remainData, remainSize);
        case 247:
            return LLVMFuzzerTestOneInput_248(remainData, remainSize);
        case 248:
            return LLVMFuzzerTestOneInput_249(remainData, remainSize);
        case 249:
            return LLVMFuzzerTestOneInput_250(remainData, remainSize);
        case 250:
            return LLVMFuzzerTestOneInput_251(remainData, remainSize);
        case 251:
            return LLVMFuzzerTestOneInput_252(remainData, remainSize);
        case 252:
            return LLVMFuzzerTestOneInput_253(remainData, remainSize);
        case 253:
            return LLVMFuzzerTestOneInput_254(remainData, remainSize);
        case 254:
            return LLVMFuzzerTestOneInput_255(remainData, remainSize);
        case 255:
            return LLVMFuzzerTestOneInput_256(remainData, remainSize);
        case 256:
            return LLVMFuzzerTestOneInput_257(remainData, remainSize);
        case 257:
            return LLVMFuzzerTestOneInput_258(remainData, remainSize);
        case 258:
            return LLVMFuzzerTestOneInput_259(remainData, remainSize);
        case 259:
            return LLVMFuzzerTestOneInput_260(remainData, remainSize);
        case 260:
            return LLVMFuzzerTestOneInput_261(remainData, remainSize);
        case 261:
            return LLVMFuzzerTestOneInput_262(remainData, remainSize);
        case 262:
            return LLVMFuzzerTestOneInput_263(remainData, remainSize);
        case 263:
            return LLVMFuzzerTestOneInput_264(remainData, remainSize);
        case 264:
            return LLVMFuzzerTestOneInput_265(remainData, remainSize);
        case 265:
            return LLVMFuzzerTestOneInput_266(remainData, remainSize);
        case 266:
            return LLVMFuzzerTestOneInput_267(remainData, remainSize);
        case 267:
            return LLVMFuzzerTestOneInput_268(remainData, remainSize);
        case 268:
            return LLVMFuzzerTestOneInput_269(remainData, remainSize);
        case 269:
            return LLVMFuzzerTestOneInput_270(remainData, remainSize);
        case 270:
            return LLVMFuzzerTestOneInput_271(remainData, remainSize);
        case 271:
            return LLVMFuzzerTestOneInput_272(remainData, remainSize);
        case 272:
            return LLVMFuzzerTestOneInput_273(remainData, remainSize);
        case 273:
            return LLVMFuzzerTestOneInput_274(remainData, remainSize);
        case 274:
            return LLVMFuzzerTestOneInput_275(remainData, remainSize);
        case 275:
            return LLVMFuzzerTestOneInput_276(remainData, remainSize);
        case 276:
            return LLVMFuzzerTestOneInput_277(remainData, remainSize);
        case 277:
            return LLVMFuzzerTestOneInput_278(remainData, remainSize);
        case 278:
            return LLVMFuzzerTestOneInput_279(remainData, remainSize);
        case 279:
            return LLVMFuzzerTestOneInput_280(remainData, remainSize);
        case 280:
            return LLVMFuzzerTestOneInput_281(remainData, remainSize);
        case 281:
            return LLVMFuzzerTestOneInput_282(remainData, remainSize);
        case 282:
            return LLVMFuzzerTestOneInput_283(remainData, remainSize);
        case 283:
            return LLVMFuzzerTestOneInput_284(remainData, remainSize);
        case 284:
            return LLVMFuzzerTestOneInput_285(remainData, remainSize);
        case 285:
            return LLVMFuzzerTestOneInput_286(remainData, remainSize);
        case 286:
            return LLVMFuzzerTestOneInput_287(remainData, remainSize);
        case 287:
            return LLVMFuzzerTestOneInput_288(remainData, remainSize);
        case 288:
            return LLVMFuzzerTestOneInput_289(remainData, remainSize);
        case 289:
            return LLVMFuzzerTestOneInput_290(remainData, remainSize);
        case 290:
            return LLVMFuzzerTestOneInput_291(remainData, remainSize);
        case 291:
            return LLVMFuzzerTestOneInput_292(remainData, remainSize);
        case 292:
            return LLVMFuzzerTestOneInput_293(remainData, remainSize);
        case 293:
            return LLVMFuzzerTestOneInput_294(remainData, remainSize);
        case 294:
            return LLVMFuzzerTestOneInput_295(remainData, remainSize);
        case 295:
            return LLVMFuzzerTestOneInput_296(remainData, remainSize);
        case 296:
            return LLVMFuzzerTestOneInput_297(remainData, remainSize);
        case 297:
            return LLVMFuzzerTestOneInput_298(remainData, remainSize);
        case 298:
            return LLVMFuzzerTestOneInput_299(remainData, remainSize);
        case 299:
            return LLVMFuzzerTestOneInput_300(remainData, remainSize);
        case 300:
            return LLVMFuzzerTestOneInput_301(remainData, remainSize);
        case 301:
            return LLVMFuzzerTestOneInput_302(remainData, remainSize);
        case 302:
            return LLVMFuzzerTestOneInput_303(remainData, remainSize);
        case 303:
            return LLVMFuzzerTestOneInput_304(remainData, remainSize);
        case 304:
            return LLVMFuzzerTestOneInput_305(remainData, remainSize);
        case 305:
            return LLVMFuzzerTestOneInput_306(remainData, remainSize);
        case 306:
            return LLVMFuzzerTestOneInput_307(remainData, remainSize);
        case 307:
            return LLVMFuzzerTestOneInput_308(remainData, remainSize);
        case 308:
            return LLVMFuzzerTestOneInput_309(remainData, remainSize);
        case 309:
            return LLVMFuzzerTestOneInput_310(remainData, remainSize);
        case 310:
            return LLVMFuzzerTestOneInput_311(remainData, remainSize);
        case 311:
            return LLVMFuzzerTestOneInput_312(remainData, remainSize);
        case 312:
            return LLVMFuzzerTestOneInput_313(remainData, remainSize);
        case 313:
            return LLVMFuzzerTestOneInput_314(remainData, remainSize);
        case 314:
            return LLVMFuzzerTestOneInput_315(remainData, remainSize);
        case 315:
            return LLVMFuzzerTestOneInput_316(remainData, remainSize);
        case 316:
            return LLVMFuzzerTestOneInput_317(remainData, remainSize);
        case 317:
            return LLVMFuzzerTestOneInput_318(remainData, remainSize);
        case 318:
            return LLVMFuzzerTestOneInput_319(remainData, remainSize);
        case 319:
            return LLVMFuzzerTestOneInput_320(remainData, remainSize);
        case 320:
            return LLVMFuzzerTestOneInput_321(remainData, remainSize);
        case 321:
            return LLVMFuzzerTestOneInput_322(remainData, remainSize);
        case 322:
            return LLVMFuzzerTestOneInput_323(remainData, remainSize);
        case 323:
            return LLVMFuzzerTestOneInput_324(remainData, remainSize);
        case 324:
            return LLVMFuzzerTestOneInput_325(remainData, remainSize);
        case 325:
            return LLVMFuzzerTestOneInput_326(remainData, remainSize);
        case 326:
            return LLVMFuzzerTestOneInput_327(remainData, remainSize);
        case 327:
            return LLVMFuzzerTestOneInput_328(remainData, remainSize);
        case 328:
            return LLVMFuzzerTestOneInput_329(remainData, remainSize);
        case 329:
            return LLVMFuzzerTestOneInput_330(remainData, remainSize);
        case 330:
            return LLVMFuzzerTestOneInput_331(remainData, remainSize);
        case 331:
            return LLVMFuzzerTestOneInput_332(remainData, remainSize);
        case 332:
            return LLVMFuzzerTestOneInput_333(remainData, remainSize);
        case 333:
            return LLVMFuzzerTestOneInput_334(remainData, remainSize);
        case 334:
            return LLVMFuzzerTestOneInput_335(remainData, remainSize);
        case 335:
            return LLVMFuzzerTestOneInput_336(remainData, remainSize);
        case 336:
            return LLVMFuzzerTestOneInput_337(remainData, remainSize);
        case 337:
            return LLVMFuzzerTestOneInput_338(remainData, remainSize);
        case 338:
            return LLVMFuzzerTestOneInput_339(remainData, remainSize);
        case 339:
            return LLVMFuzzerTestOneInput_340(remainData, remainSize);
        case 340:
            return LLVMFuzzerTestOneInput_341(remainData, remainSize);
        case 341:
            return LLVMFuzzerTestOneInput_342(remainData, remainSize);
        case 342:
            return LLVMFuzzerTestOneInput_343(remainData, remainSize);
        case 343:
            return LLVMFuzzerTestOneInput_344(remainData, remainSize);
        case 344:
            return LLVMFuzzerTestOneInput_345(remainData, remainSize);
        case 345:
            return LLVMFuzzerTestOneInput_346(remainData, remainSize);
        case 346:
            return LLVMFuzzerTestOneInput_347(remainData, remainSize);
        case 347:
            return LLVMFuzzerTestOneInput_348(remainData, remainSize);
        case 348:
            return LLVMFuzzerTestOneInput_349(remainData, remainSize);
        case 349:
            return LLVMFuzzerTestOneInput_350(remainData, remainSize);
        case 350:
            return LLVMFuzzerTestOneInput_351(remainData, remainSize);
        case 351:
            return LLVMFuzzerTestOneInput_352(remainData, remainSize);
        case 352:
            return LLVMFuzzerTestOneInput_353(remainData, remainSize);
        case 353:
            return LLVMFuzzerTestOneInput_354(remainData, remainSize);
        case 354:
            return LLVMFuzzerTestOneInput_355(remainData, remainSize);
        case 355:
            return LLVMFuzzerTestOneInput_356(remainData, remainSize);
        case 356:
            return LLVMFuzzerTestOneInput_357(remainData, remainSize);
        case 357:
            return LLVMFuzzerTestOneInput_358(remainData, remainSize);
        case 358:
            return LLVMFuzzerTestOneInput_359(remainData, remainSize);
        case 359:
            return LLVMFuzzerTestOneInput_360(remainData, remainSize);
        case 360:
            return LLVMFuzzerTestOneInput_361(remainData, remainSize);
        case 361:
            return LLVMFuzzerTestOneInput_362(remainData, remainSize);
        case 362:
            return LLVMFuzzerTestOneInput_363(remainData, remainSize);
        case 363:
            return LLVMFuzzerTestOneInput_364(remainData, remainSize);
        case 364:
            return LLVMFuzzerTestOneInput_365(remainData, remainSize);
        case 365:
            return LLVMFuzzerTestOneInput_366(remainData, remainSize);
        case 366:
            return LLVMFuzzerTestOneInput_367(remainData, remainSize);
        case 367:
            return LLVMFuzzerTestOneInput_368(remainData, remainSize);
        case 368:
            return LLVMFuzzerTestOneInput_369(remainData, remainSize);
        case 369:
            return LLVMFuzzerTestOneInput_370(remainData, remainSize);
        case 370:
            return LLVMFuzzerTestOneInput_371(remainData, remainSize);
        case 371:
            return LLVMFuzzerTestOneInput_372(remainData, remainSize);
        case 372:
            return LLVMFuzzerTestOneInput_373(remainData, remainSize);
        case 373:
            return LLVMFuzzerTestOneInput_374(remainData, remainSize);
        case 374:
            return LLVMFuzzerTestOneInput_375(remainData, remainSize);
        case 375:
            return LLVMFuzzerTestOneInput_376(remainData, remainSize);
        case 376:
            return LLVMFuzzerTestOneInput_377(remainData, remainSize);
        case 377:
            return LLVMFuzzerTestOneInput_378(remainData, remainSize);
        case 378:
            return LLVMFuzzerTestOneInput_379(remainData, remainSize);
        case 379:
            return LLVMFuzzerTestOneInput_380(remainData, remainSize);
        case 380:
            return LLVMFuzzerTestOneInput_381(remainData, remainSize);
        case 381:
            return LLVMFuzzerTestOneInput_382(remainData, remainSize);
        case 382:
            return LLVMFuzzerTestOneInput_383(remainData, remainSize);
        case 383:
            return LLVMFuzzerTestOneInput_384(remainData, remainSize);
        case 384:
            return LLVMFuzzerTestOneInput_385(remainData, remainSize);
        case 385:
            return LLVMFuzzerTestOneInput_386(remainData, remainSize);
        case 386:
            return LLVMFuzzerTestOneInput_387(remainData, remainSize);
        case 387:
            return LLVMFuzzerTestOneInput_388(remainData, remainSize);
        case 388:
            return LLVMFuzzerTestOneInput_389(remainData, remainSize);
        case 389:
            return LLVMFuzzerTestOneInput_390(remainData, remainSize);
        case 390:
            return LLVMFuzzerTestOneInput_391(remainData, remainSize);
        case 391:
            return LLVMFuzzerTestOneInput_392(remainData, remainSize);
        case 392:
            return LLVMFuzzerTestOneInput_393(remainData, remainSize);
        case 393:
            return LLVMFuzzerTestOneInput_394(remainData, remainSize);
        case 394:
            return LLVMFuzzerTestOneInput_395(remainData, remainSize);
        case 395:
            return LLVMFuzzerTestOneInput_396(remainData, remainSize);
        case 396:
            return LLVMFuzzerTestOneInput_397(remainData, remainSize);
        case 397:
            return LLVMFuzzerTestOneInput_398(remainData, remainSize);
        case 398:
            return LLVMFuzzerTestOneInput_399(remainData, remainSize);
        case 399:
            return LLVMFuzzerTestOneInput_400(remainData, remainSize);
        case 400:
            return LLVMFuzzerTestOneInput_401(remainData, remainSize);
        case 401:
            return LLVMFuzzerTestOneInput_402(remainData, remainSize);
        case 402:
            return LLVMFuzzerTestOneInput_403(remainData, remainSize);
        case 403:
            return LLVMFuzzerTestOneInput_404(remainData, remainSize);
        case 404:
            return LLVMFuzzerTestOneInput_405(remainData, remainSize);
        case 405:
            return LLVMFuzzerTestOneInput_406(remainData, remainSize);
        case 406:
            return LLVMFuzzerTestOneInput_407(remainData, remainSize);
        case 407:
            return LLVMFuzzerTestOneInput_408(remainData, remainSize);
        case 408:
            return LLVMFuzzerTestOneInput_409(remainData, remainSize);
        case 409:
            return LLVMFuzzerTestOneInput_410(remainData, remainSize);
        case 410:
            return LLVMFuzzerTestOneInput_411(remainData, remainSize);
        case 411:
            return LLVMFuzzerTestOneInput_412(remainData, remainSize);
        case 412:
            return LLVMFuzzerTestOneInput_413(remainData, remainSize);
        case 413:
            return LLVMFuzzerTestOneInput_414(remainData, remainSize);
        case 414:
            return LLVMFuzzerTestOneInput_415(remainData, remainSize);
        case 415:
            return LLVMFuzzerTestOneInput_416(remainData, remainSize);
        case 416:
            return LLVMFuzzerTestOneInput_417(remainData, remainSize);
        case 417:
            return LLVMFuzzerTestOneInput_418(remainData, remainSize);
        case 418:
            return LLVMFuzzerTestOneInput_419(remainData, remainSize);
        case 419:
            return LLVMFuzzerTestOneInput_420(remainData, remainSize);
        case 420:
            return LLVMFuzzerTestOneInput_421(remainData, remainSize);
        case 421:
            return LLVMFuzzerTestOneInput_422(remainData, remainSize);
        case 422:
            return LLVMFuzzerTestOneInput_423(remainData, remainSize);
        case 423:
            return LLVMFuzzerTestOneInput_424(remainData, remainSize);
        case 424:
            return LLVMFuzzerTestOneInput_425(remainData, remainSize);
        case 425:
            return LLVMFuzzerTestOneInput_426(remainData, remainSize);
        case 426:
            return LLVMFuzzerTestOneInput_427(remainData, remainSize);
        case 427:
            return LLVMFuzzerTestOneInput_428(remainData, remainSize);
        case 428:
            return LLVMFuzzerTestOneInput_429(remainData, remainSize);
        case 429:
            return LLVMFuzzerTestOneInput_430(remainData, remainSize);
        case 430:
            return LLVMFuzzerTestOneInput_431(remainData, remainSize);
        case 431:
            return LLVMFuzzerTestOneInput_432(remainData, remainSize);
        case 432:
            return LLVMFuzzerTestOneInput_433(remainData, remainSize);
        case 433:
            return LLVMFuzzerTestOneInput_434(remainData, remainSize);
        case 434:
            return LLVMFuzzerTestOneInput_435(remainData, remainSize);
        case 435:
            return LLVMFuzzerTestOneInput_436(remainData, remainSize);
        case 436:
            return LLVMFuzzerTestOneInput_437(remainData, remainSize);
        case 437:
            return LLVMFuzzerTestOneInput_438(remainData, remainSize);
        case 438:
            return LLVMFuzzerTestOneInput_439(remainData, remainSize);
        case 439:
            return LLVMFuzzerTestOneInput_440(remainData, remainSize);
        case 440:
            return LLVMFuzzerTestOneInput_441(remainData, remainSize);
        case 441:
            return LLVMFuzzerTestOneInput_442(remainData, remainSize);
        case 442:
            return LLVMFuzzerTestOneInput_443(remainData, remainSize);
        case 443:
            return LLVMFuzzerTestOneInput_444(remainData, remainSize);
        case 444:
            return LLVMFuzzerTestOneInput_445(remainData, remainSize);
        case 445:
            return LLVMFuzzerTestOneInput_446(remainData, remainSize);
        case 446:
            return LLVMFuzzerTestOneInput_447(remainData, remainSize);
        case 447:
            return LLVMFuzzerTestOneInput_448(remainData, remainSize);
        case 448:
            return LLVMFuzzerTestOneInput_449(remainData, remainSize);
        case 449:
            return LLVMFuzzerTestOneInput_450(remainData, remainSize);
        case 450:
            return LLVMFuzzerTestOneInput_451(remainData, remainSize);
        case 451:
            return LLVMFuzzerTestOneInput_452(remainData, remainSize);
        case 452:
            return LLVMFuzzerTestOneInput_453(remainData, remainSize);
        case 453:
            return LLVMFuzzerTestOneInput_454(remainData, remainSize);
        case 454:
            return LLVMFuzzerTestOneInput_455(remainData, remainSize);
        case 455:
            return LLVMFuzzerTestOneInput_456(remainData, remainSize);
        case 456:
            return LLVMFuzzerTestOneInput_457(remainData, remainSize);
        case 457:
            return LLVMFuzzerTestOneInput_458(remainData, remainSize);
        case 458:
            return LLVMFuzzerTestOneInput_459(remainData, remainSize);
        case 459:
            return LLVMFuzzerTestOneInput_460(remainData, remainSize);
        case 460:
            return LLVMFuzzerTestOneInput_461(remainData, remainSize);
        case 461:
            return LLVMFuzzerTestOneInput_462(remainData, remainSize);
        case 462:
            return LLVMFuzzerTestOneInput_463(remainData, remainSize);
        case 463:
            return LLVMFuzzerTestOneInput_464(remainData, remainSize);
        case 464:
            return LLVMFuzzerTestOneInput_465(remainData, remainSize);
        case 465:
            return LLVMFuzzerTestOneInput_466(remainData, remainSize);
        case 466:
            return LLVMFuzzerTestOneInput_467(remainData, remainSize);
        case 467:
            return LLVMFuzzerTestOneInput_468(remainData, remainSize);
        case 468:
            return LLVMFuzzerTestOneInput_469(remainData, remainSize);
        case 469:
            return LLVMFuzzerTestOneInput_470(remainData, remainSize);
        case 470:
            return LLVMFuzzerTestOneInput_471(remainData, remainSize);
        case 471:
            return LLVMFuzzerTestOneInput_472(remainData, remainSize);
        case 472:
            return LLVMFuzzerTestOneInput_473(remainData, remainSize);
        case 473:
            return LLVMFuzzerTestOneInput_474(remainData, remainSize);
        case 474:
            return LLVMFuzzerTestOneInput_475(remainData, remainSize);
        case 475:
            return LLVMFuzzerTestOneInput_476(remainData, remainSize);
        case 476:
            return LLVMFuzzerTestOneInput_477(remainData, remainSize);
        case 477:
            return LLVMFuzzerTestOneInput_478(remainData, remainSize);
        case 478:
            return LLVMFuzzerTestOneInput_479(remainData, remainSize);
        case 479:
            return LLVMFuzzerTestOneInput_480(remainData, remainSize);
        case 480:
            return LLVMFuzzerTestOneInput_481(remainData, remainSize);
        case 481:
            return LLVMFuzzerTestOneInput_482(remainData, remainSize);
        case 482:
            return LLVMFuzzerTestOneInput_483(remainData, remainSize);
        case 483:
            return LLVMFuzzerTestOneInput_484(remainData, remainSize);
        case 484:
            return LLVMFuzzerTestOneInput_485(remainData, remainSize);
        case 485:
            return LLVMFuzzerTestOneInput_486(remainData, remainSize);
        case 486:
            return LLVMFuzzerTestOneInput_487(remainData, remainSize);
        case 487:
            return LLVMFuzzerTestOneInput_488(remainData, remainSize);
        case 488:
            return LLVMFuzzerTestOneInput_489(remainData, remainSize);
        case 489:
            return LLVMFuzzerTestOneInput_490(remainData, remainSize);
        case 490:
            return LLVMFuzzerTestOneInput_491(remainData, remainSize);
        case 491:
            return LLVMFuzzerTestOneInput_492(remainData, remainSize);
        case 492:
            return LLVMFuzzerTestOneInput_493(remainData, remainSize);
        case 493:
            return LLVMFuzzerTestOneInput_494(remainData, remainSize);
        case 494:
            return LLVMFuzzerTestOneInput_495(remainData, remainSize);
        case 495:
            return LLVMFuzzerTestOneInput_496(remainData, remainSize);
        case 496:
            return LLVMFuzzerTestOneInput_497(remainData, remainSize);
        case 497:
            return LLVMFuzzerTestOneInput_498(remainData, remainSize);
        case 498:
            return LLVMFuzzerTestOneInput_499(remainData, remainSize);
        case 499:
            return LLVMFuzzerTestOneInput_500(remainData, remainSize);
        case 500:
            return LLVMFuzzerTestOneInput_501(remainData, remainSize);
        case 501:
            return LLVMFuzzerTestOneInput_502(remainData, remainSize);
        case 502:
            return LLVMFuzzerTestOneInput_503(remainData, remainSize);
        case 503:
            return LLVMFuzzerTestOneInput_504(remainData, remainSize);
        case 504:
            return LLVMFuzzerTestOneInput_505(remainData, remainSize);
        case 505:
            return LLVMFuzzerTestOneInput_506(remainData, remainSize);
        case 506:
            return LLVMFuzzerTestOneInput_507(remainData, remainSize);
        case 507:
            return LLVMFuzzerTestOneInput_508(remainData, remainSize);
        case 508:
            return LLVMFuzzerTestOneInput_509(remainData, remainSize);
        case 509:
            return LLVMFuzzerTestOneInput_510(remainData, remainSize);
        case 510:
            return LLVMFuzzerTestOneInput_511(remainData, remainSize);
        case 511:
            return LLVMFuzzerTestOneInput_512(remainData, remainSize);
        case 512:
            return LLVMFuzzerTestOneInput_513(remainData, remainSize);
        case 513:
            return LLVMFuzzerTestOneInput_514(remainData, remainSize);
        case 514:
            return LLVMFuzzerTestOneInput_515(remainData, remainSize);
        case 515:
            return LLVMFuzzerTestOneInput_516(remainData, remainSize);
        case 516:
            return LLVMFuzzerTestOneInput_517(remainData, remainSize);
        case 517:
            return LLVMFuzzerTestOneInput_518(remainData, remainSize);
        case 518:
            return LLVMFuzzerTestOneInput_519(remainData, remainSize);
        case 519:
            return LLVMFuzzerTestOneInput_520(remainData, remainSize);
        case 520:
            return LLVMFuzzerTestOneInput_521(remainData, remainSize);
        case 521:
            return LLVMFuzzerTestOneInput_522(remainData, remainSize);
        case 522:
            return LLVMFuzzerTestOneInput_523(remainData, remainSize);
        case 523:
            return LLVMFuzzerTestOneInput_524(remainData, remainSize);
        case 524:
            return LLVMFuzzerTestOneInput_525(remainData, remainSize);
        case 525:
            return LLVMFuzzerTestOneInput_526(remainData, remainSize);
        case 526:
            return LLVMFuzzerTestOneInput_527(remainData, remainSize);
        case 527:
            return LLVMFuzzerTestOneInput_528(remainData, remainSize);
        case 528:
            return LLVMFuzzerTestOneInput_529(remainData, remainSize);
        case 529:
            return LLVMFuzzerTestOneInput_530(remainData, remainSize);
        case 530:
            return LLVMFuzzerTestOneInput_531(remainData, remainSize);
        case 531:
            return LLVMFuzzerTestOneInput_532(remainData, remainSize);
        case 532:
            return LLVMFuzzerTestOneInput_533(remainData, remainSize);
        case 533:
            return LLVMFuzzerTestOneInput_534(remainData, remainSize);
        case 534:
            return LLVMFuzzerTestOneInput_535(remainData, remainSize);
        case 535:
            return LLVMFuzzerTestOneInput_536(remainData, remainSize);
        case 536:
            return LLVMFuzzerTestOneInput_537(remainData, remainSize);
        case 537:
            return LLVMFuzzerTestOneInput_538(remainData, remainSize);
        case 538:
            return LLVMFuzzerTestOneInput_539(remainData, remainSize);
        case 539:
            return LLVMFuzzerTestOneInput_540(remainData, remainSize);
        case 540:
            return LLVMFuzzerTestOneInput_541(remainData, remainSize);
        case 541:
            return LLVMFuzzerTestOneInput_542(remainData, remainSize);
        case 542:
            return LLVMFuzzerTestOneInput_543(remainData, remainSize);
        case 543:
            return LLVMFuzzerTestOneInput_544(remainData, remainSize);
        case 544:
            return LLVMFuzzerTestOneInput_545(remainData, remainSize);
        case 545:
            return LLVMFuzzerTestOneInput_546(remainData, remainSize);
        case 546:
            return LLVMFuzzerTestOneInput_547(remainData, remainSize);
        case 547:
            return LLVMFuzzerTestOneInput_548(remainData, remainSize);
        case 548:
            return LLVMFuzzerTestOneInput_549(remainData, remainSize);
        case 549:
            return LLVMFuzzerTestOneInput_550(remainData, remainSize);
        case 550:
            return LLVMFuzzerTestOneInput_551(remainData, remainSize);
        case 551:
            return LLVMFuzzerTestOneInput_552(remainData, remainSize);
        case 552:
            return LLVMFuzzerTestOneInput_553(remainData, remainSize);
        case 553:
            return LLVMFuzzerTestOneInput_554(remainData, remainSize);
        case 554:
            return LLVMFuzzerTestOneInput_555(remainData, remainSize);
        case 555:
            return LLVMFuzzerTestOneInput_556(remainData, remainSize);
        case 556:
            return LLVMFuzzerTestOneInput_557(remainData, remainSize);
        case 557:
            return LLVMFuzzerTestOneInput_558(remainData, remainSize);
        case 558:
            return LLVMFuzzerTestOneInput_559(remainData, remainSize);
        case 559:
            return LLVMFuzzerTestOneInput_560(remainData, remainSize);
        case 560:
            return LLVMFuzzerTestOneInput_561(remainData, remainSize);
        case 561:
            return LLVMFuzzerTestOneInput_562(remainData, remainSize);
        case 562:
            return LLVMFuzzerTestOneInput_563(remainData, remainSize);
        case 563:
            return LLVMFuzzerTestOneInput_564(remainData, remainSize);
        case 564:
            return LLVMFuzzerTestOneInput_565(remainData, remainSize);
        case 565:
            return LLVMFuzzerTestOneInput_566(remainData, remainSize);
        case 566:
            return LLVMFuzzerTestOneInput_567(remainData, remainSize);
        case 567:
            return LLVMFuzzerTestOneInput_568(remainData, remainSize);
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

