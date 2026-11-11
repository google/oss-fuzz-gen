// This is the entry of 1093 fuzz drivers:
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
// , 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582
// , 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598
// , 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609, 610, 611, 612, 613, 614
// , 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629, 630
// , 631, 632, 633, 634, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646
// , 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662
// , 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 675, 676, 677, 678
// , 679, 680, 681, 682, 683, 684, 685, 686, 687, 688, 689, 690, 691, 692, 693, 694
// , 695, 696, 697, 698, 699, 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710
// , 711, 712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726
// , 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742
// , 743, 744, 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758
// , 759, 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774
// , 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790
// , 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804, 805, 806
// , 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819, 820, 821, 822
// , 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838
// , 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854
// , 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 869, 870
// , 871, 872, 873, 874, 875, 876, 877, 878, 879, 880, 881, 882, 883, 884, 885, 886
// , 887, 888, 889, 890, 891, 892, 893, 894, 895, 896, 897, 898, 899, 900, 901, 902
// , 903, 904, 905, 906, 907, 908, 909, 910, 911, 912, 913, 914, 915, 916, 917, 918
// , 919, 920, 921, 922, 923, 924, 925, 926, 927, 928, 929, 930, 931, 932, 933, 934
// , 935, 936, 937, 938, 939, 940, 941, 942, 943, 944, 945, 946, 947, 948, 949, 950
// , 951, 952, 953, 954, 955, 956, 957, 958, 959, 960, 961, 962, 963, 964, 965, 966
// , 967, 968, 969, 970, 971, 972, 973, 974, 975, 976, 977, 978, 979, 980, 981, 982
// , 983, 984, 985, 986, 987, 988, 989, 990, 991, 992, 993, 994, 995, 996, 997, 998
// , 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1
// 012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 102
// 5, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038,
//  1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1
// 052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 106
// 5, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078,
//  1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1
// 092, 1093
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
int LLVMFuzzerTestOneInput_569(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_570(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_571(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_572(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_573(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_574(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_575(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_576(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_577(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_578(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_579(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_580(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_581(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_582(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_583(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_584(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_585(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_586(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_587(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_588(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_589(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_590(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_591(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_592(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_593(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_594(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_595(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_596(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_597(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_598(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_599(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_600(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_601(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_602(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_603(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_604(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_605(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_606(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_607(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_608(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_609(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_610(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_611(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_612(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_613(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_614(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_615(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_616(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_617(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_618(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_619(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_620(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_621(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_622(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_623(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_624(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_625(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_626(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_627(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_628(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_629(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_630(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_631(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_632(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_633(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_634(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_635(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_636(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_637(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_638(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_639(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_640(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_641(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_642(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_643(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_644(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_645(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_646(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_647(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_648(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_649(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_650(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_651(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_652(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_653(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_654(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_655(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_656(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_657(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_658(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_659(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_660(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_661(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_662(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_663(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_664(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_665(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_666(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_667(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_668(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_669(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_670(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_671(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_672(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_673(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_674(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_675(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_676(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_677(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_678(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_679(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_680(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_681(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_682(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_683(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_684(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_685(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_686(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_687(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_688(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_689(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_690(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_691(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_692(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_693(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_694(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_695(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_696(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_697(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_698(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_699(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_700(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_701(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_702(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_703(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_704(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_705(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_706(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_707(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_708(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_709(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_710(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_711(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_712(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_713(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_714(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_715(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_716(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_717(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_718(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_719(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_720(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_721(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_722(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_723(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_724(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_725(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_726(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_727(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_728(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_729(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_730(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_731(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_732(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_733(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_734(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_735(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_736(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_737(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_738(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_739(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_740(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_741(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_742(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_743(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_744(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_745(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_746(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_747(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_748(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_749(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_750(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_751(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_752(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_753(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_754(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_755(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_756(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_757(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_758(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_759(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_760(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_761(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_762(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_763(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_764(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_765(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_766(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_767(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_768(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_769(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_770(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_771(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_772(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_773(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_774(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_775(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_776(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_777(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_778(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_779(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_780(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_781(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_782(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_783(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_784(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_785(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_786(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_787(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_788(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_789(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_790(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_791(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_792(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_793(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_794(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_795(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_796(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_797(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_798(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_799(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_800(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_801(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_802(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_803(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_804(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_805(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_806(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_807(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_808(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_809(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_810(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_811(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_812(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_813(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_814(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_815(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_816(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_817(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_818(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_819(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_820(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_821(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_822(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_823(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_824(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_825(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_826(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_827(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_828(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_829(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_830(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_831(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_832(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_833(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_834(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_835(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_836(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_837(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_838(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_839(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_840(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_841(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_842(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_843(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_844(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_845(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_846(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_847(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_848(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_849(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_850(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_851(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_852(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_853(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_854(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_855(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_856(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_857(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_858(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_859(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_860(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_861(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_862(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_863(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_864(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_865(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_866(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_867(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_868(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_869(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_870(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_871(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_872(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_873(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_874(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_875(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_876(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_877(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_878(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_879(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_880(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_881(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_882(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_883(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_884(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_885(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_886(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_887(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_888(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_889(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_890(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_891(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_892(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_893(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_894(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_895(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_896(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_897(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_898(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_899(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_900(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_901(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_902(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_903(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_904(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_905(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_906(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_907(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_908(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_909(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_910(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_911(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_912(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_913(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_914(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_915(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_916(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_917(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_918(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_919(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_920(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_921(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_922(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_923(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_924(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_925(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_926(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_927(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_928(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_929(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_930(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_931(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_932(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_933(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_934(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_935(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_936(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_937(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_938(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_939(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_940(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_941(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_942(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_943(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_944(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_945(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_946(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_947(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_948(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_949(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_950(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_951(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_952(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_953(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_954(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_955(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_956(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_957(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_958(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_959(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_960(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_961(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_962(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_963(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_964(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_965(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_966(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_967(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_968(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_969(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_970(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_971(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_972(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_973(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_974(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_975(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_976(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_977(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_978(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_979(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_980(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_981(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_982(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_983(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_984(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_985(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_986(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_987(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_988(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_989(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_990(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_991(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_992(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_993(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_994(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_995(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_996(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_997(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_998(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_999(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1000(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1001(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1002(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1003(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1004(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1005(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1006(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1007(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1008(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1009(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1010(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1011(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1012(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1013(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1014(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1015(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1016(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1017(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1018(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1019(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1020(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1021(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1022(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1023(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1024(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1025(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1026(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1027(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1028(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1029(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1030(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1031(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1032(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1033(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1034(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1035(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1036(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1037(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1038(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1039(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1040(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1041(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1042(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1043(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1044(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1045(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1046(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1047(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1048(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1049(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1050(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1051(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1052(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1053(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1054(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1055(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1056(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1057(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1058(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1059(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1060(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1061(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1062(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1063(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1064(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1065(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1066(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1067(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1068(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1069(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1070(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1071(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1072(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1073(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1074(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1075(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1076(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1077(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1078(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1079(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1080(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1081(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1082(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1083(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1084(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1085(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1086(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1087(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1088(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1089(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1090(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1091(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1092(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_1093(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 1093) {
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
        case 568:
            return LLVMFuzzerTestOneInput_569(remainData, remainSize);
        case 569:
            return LLVMFuzzerTestOneInput_570(remainData, remainSize);
        case 570:
            return LLVMFuzzerTestOneInput_571(remainData, remainSize);
        case 571:
            return LLVMFuzzerTestOneInput_572(remainData, remainSize);
        case 572:
            return LLVMFuzzerTestOneInput_573(remainData, remainSize);
        case 573:
            return LLVMFuzzerTestOneInput_574(remainData, remainSize);
        case 574:
            return LLVMFuzzerTestOneInput_575(remainData, remainSize);
        case 575:
            return LLVMFuzzerTestOneInput_576(remainData, remainSize);
        case 576:
            return LLVMFuzzerTestOneInput_577(remainData, remainSize);
        case 577:
            return LLVMFuzzerTestOneInput_578(remainData, remainSize);
        case 578:
            return LLVMFuzzerTestOneInput_579(remainData, remainSize);
        case 579:
            return LLVMFuzzerTestOneInput_580(remainData, remainSize);
        case 580:
            return LLVMFuzzerTestOneInput_581(remainData, remainSize);
        case 581:
            return LLVMFuzzerTestOneInput_582(remainData, remainSize);
        case 582:
            return LLVMFuzzerTestOneInput_583(remainData, remainSize);
        case 583:
            return LLVMFuzzerTestOneInput_584(remainData, remainSize);
        case 584:
            return LLVMFuzzerTestOneInput_585(remainData, remainSize);
        case 585:
            return LLVMFuzzerTestOneInput_586(remainData, remainSize);
        case 586:
            return LLVMFuzzerTestOneInput_587(remainData, remainSize);
        case 587:
            return LLVMFuzzerTestOneInput_588(remainData, remainSize);
        case 588:
            return LLVMFuzzerTestOneInput_589(remainData, remainSize);
        case 589:
            return LLVMFuzzerTestOneInput_590(remainData, remainSize);
        case 590:
            return LLVMFuzzerTestOneInput_591(remainData, remainSize);
        case 591:
            return LLVMFuzzerTestOneInput_592(remainData, remainSize);
        case 592:
            return LLVMFuzzerTestOneInput_593(remainData, remainSize);
        case 593:
            return LLVMFuzzerTestOneInput_594(remainData, remainSize);
        case 594:
            return LLVMFuzzerTestOneInput_595(remainData, remainSize);
        case 595:
            return LLVMFuzzerTestOneInput_596(remainData, remainSize);
        case 596:
            return LLVMFuzzerTestOneInput_597(remainData, remainSize);
        case 597:
            return LLVMFuzzerTestOneInput_598(remainData, remainSize);
        case 598:
            return LLVMFuzzerTestOneInput_599(remainData, remainSize);
        case 599:
            return LLVMFuzzerTestOneInput_600(remainData, remainSize);
        case 600:
            return LLVMFuzzerTestOneInput_601(remainData, remainSize);
        case 601:
            return LLVMFuzzerTestOneInput_602(remainData, remainSize);
        case 602:
            return LLVMFuzzerTestOneInput_603(remainData, remainSize);
        case 603:
            return LLVMFuzzerTestOneInput_604(remainData, remainSize);
        case 604:
            return LLVMFuzzerTestOneInput_605(remainData, remainSize);
        case 605:
            return LLVMFuzzerTestOneInput_606(remainData, remainSize);
        case 606:
            return LLVMFuzzerTestOneInput_607(remainData, remainSize);
        case 607:
            return LLVMFuzzerTestOneInput_608(remainData, remainSize);
        case 608:
            return LLVMFuzzerTestOneInput_609(remainData, remainSize);
        case 609:
            return LLVMFuzzerTestOneInput_610(remainData, remainSize);
        case 610:
            return LLVMFuzzerTestOneInput_611(remainData, remainSize);
        case 611:
            return LLVMFuzzerTestOneInput_612(remainData, remainSize);
        case 612:
            return LLVMFuzzerTestOneInput_613(remainData, remainSize);
        case 613:
            return LLVMFuzzerTestOneInput_614(remainData, remainSize);
        case 614:
            return LLVMFuzzerTestOneInput_615(remainData, remainSize);
        case 615:
            return LLVMFuzzerTestOneInput_616(remainData, remainSize);
        case 616:
            return LLVMFuzzerTestOneInput_617(remainData, remainSize);
        case 617:
            return LLVMFuzzerTestOneInput_618(remainData, remainSize);
        case 618:
            return LLVMFuzzerTestOneInput_619(remainData, remainSize);
        case 619:
            return LLVMFuzzerTestOneInput_620(remainData, remainSize);
        case 620:
            return LLVMFuzzerTestOneInput_621(remainData, remainSize);
        case 621:
            return LLVMFuzzerTestOneInput_622(remainData, remainSize);
        case 622:
            return LLVMFuzzerTestOneInput_623(remainData, remainSize);
        case 623:
            return LLVMFuzzerTestOneInput_624(remainData, remainSize);
        case 624:
            return LLVMFuzzerTestOneInput_625(remainData, remainSize);
        case 625:
            return LLVMFuzzerTestOneInput_626(remainData, remainSize);
        case 626:
            return LLVMFuzzerTestOneInput_627(remainData, remainSize);
        case 627:
            return LLVMFuzzerTestOneInput_628(remainData, remainSize);
        case 628:
            return LLVMFuzzerTestOneInput_629(remainData, remainSize);
        case 629:
            return LLVMFuzzerTestOneInput_630(remainData, remainSize);
        case 630:
            return LLVMFuzzerTestOneInput_631(remainData, remainSize);
        case 631:
            return LLVMFuzzerTestOneInput_632(remainData, remainSize);
        case 632:
            return LLVMFuzzerTestOneInput_633(remainData, remainSize);
        case 633:
            return LLVMFuzzerTestOneInput_634(remainData, remainSize);
        case 634:
            return LLVMFuzzerTestOneInput_635(remainData, remainSize);
        case 635:
            return LLVMFuzzerTestOneInput_636(remainData, remainSize);
        case 636:
            return LLVMFuzzerTestOneInput_637(remainData, remainSize);
        case 637:
            return LLVMFuzzerTestOneInput_638(remainData, remainSize);
        case 638:
            return LLVMFuzzerTestOneInput_639(remainData, remainSize);
        case 639:
            return LLVMFuzzerTestOneInput_640(remainData, remainSize);
        case 640:
            return LLVMFuzzerTestOneInput_641(remainData, remainSize);
        case 641:
            return LLVMFuzzerTestOneInput_642(remainData, remainSize);
        case 642:
            return LLVMFuzzerTestOneInput_643(remainData, remainSize);
        case 643:
            return LLVMFuzzerTestOneInput_644(remainData, remainSize);
        case 644:
            return LLVMFuzzerTestOneInput_645(remainData, remainSize);
        case 645:
            return LLVMFuzzerTestOneInput_646(remainData, remainSize);
        case 646:
            return LLVMFuzzerTestOneInput_647(remainData, remainSize);
        case 647:
            return LLVMFuzzerTestOneInput_648(remainData, remainSize);
        case 648:
            return LLVMFuzzerTestOneInput_649(remainData, remainSize);
        case 649:
            return LLVMFuzzerTestOneInput_650(remainData, remainSize);
        case 650:
            return LLVMFuzzerTestOneInput_651(remainData, remainSize);
        case 651:
            return LLVMFuzzerTestOneInput_652(remainData, remainSize);
        case 652:
            return LLVMFuzzerTestOneInput_653(remainData, remainSize);
        case 653:
            return LLVMFuzzerTestOneInput_654(remainData, remainSize);
        case 654:
            return LLVMFuzzerTestOneInput_655(remainData, remainSize);
        case 655:
            return LLVMFuzzerTestOneInput_656(remainData, remainSize);
        case 656:
            return LLVMFuzzerTestOneInput_657(remainData, remainSize);
        case 657:
            return LLVMFuzzerTestOneInput_658(remainData, remainSize);
        case 658:
            return LLVMFuzzerTestOneInput_659(remainData, remainSize);
        case 659:
            return LLVMFuzzerTestOneInput_660(remainData, remainSize);
        case 660:
            return LLVMFuzzerTestOneInput_661(remainData, remainSize);
        case 661:
            return LLVMFuzzerTestOneInput_662(remainData, remainSize);
        case 662:
            return LLVMFuzzerTestOneInput_663(remainData, remainSize);
        case 663:
            return LLVMFuzzerTestOneInput_664(remainData, remainSize);
        case 664:
            return LLVMFuzzerTestOneInput_665(remainData, remainSize);
        case 665:
            return LLVMFuzzerTestOneInput_666(remainData, remainSize);
        case 666:
            return LLVMFuzzerTestOneInput_667(remainData, remainSize);
        case 667:
            return LLVMFuzzerTestOneInput_668(remainData, remainSize);
        case 668:
            return LLVMFuzzerTestOneInput_669(remainData, remainSize);
        case 669:
            return LLVMFuzzerTestOneInput_670(remainData, remainSize);
        case 670:
            return LLVMFuzzerTestOneInput_671(remainData, remainSize);
        case 671:
            return LLVMFuzzerTestOneInput_672(remainData, remainSize);
        case 672:
            return LLVMFuzzerTestOneInput_673(remainData, remainSize);
        case 673:
            return LLVMFuzzerTestOneInput_674(remainData, remainSize);
        case 674:
            return LLVMFuzzerTestOneInput_675(remainData, remainSize);
        case 675:
            return LLVMFuzzerTestOneInput_676(remainData, remainSize);
        case 676:
            return LLVMFuzzerTestOneInput_677(remainData, remainSize);
        case 677:
            return LLVMFuzzerTestOneInput_678(remainData, remainSize);
        case 678:
            return LLVMFuzzerTestOneInput_679(remainData, remainSize);
        case 679:
            return LLVMFuzzerTestOneInput_680(remainData, remainSize);
        case 680:
            return LLVMFuzzerTestOneInput_681(remainData, remainSize);
        case 681:
            return LLVMFuzzerTestOneInput_682(remainData, remainSize);
        case 682:
            return LLVMFuzzerTestOneInput_683(remainData, remainSize);
        case 683:
            return LLVMFuzzerTestOneInput_684(remainData, remainSize);
        case 684:
            return LLVMFuzzerTestOneInput_685(remainData, remainSize);
        case 685:
            return LLVMFuzzerTestOneInput_686(remainData, remainSize);
        case 686:
            return LLVMFuzzerTestOneInput_687(remainData, remainSize);
        case 687:
            return LLVMFuzzerTestOneInput_688(remainData, remainSize);
        case 688:
            return LLVMFuzzerTestOneInput_689(remainData, remainSize);
        case 689:
            return LLVMFuzzerTestOneInput_690(remainData, remainSize);
        case 690:
            return LLVMFuzzerTestOneInput_691(remainData, remainSize);
        case 691:
            return LLVMFuzzerTestOneInput_692(remainData, remainSize);
        case 692:
            return LLVMFuzzerTestOneInput_693(remainData, remainSize);
        case 693:
            return LLVMFuzzerTestOneInput_694(remainData, remainSize);
        case 694:
            return LLVMFuzzerTestOneInput_695(remainData, remainSize);
        case 695:
            return LLVMFuzzerTestOneInput_696(remainData, remainSize);
        case 696:
            return LLVMFuzzerTestOneInput_697(remainData, remainSize);
        case 697:
            return LLVMFuzzerTestOneInput_698(remainData, remainSize);
        case 698:
            return LLVMFuzzerTestOneInput_699(remainData, remainSize);
        case 699:
            return LLVMFuzzerTestOneInput_700(remainData, remainSize);
        case 700:
            return LLVMFuzzerTestOneInput_701(remainData, remainSize);
        case 701:
            return LLVMFuzzerTestOneInput_702(remainData, remainSize);
        case 702:
            return LLVMFuzzerTestOneInput_703(remainData, remainSize);
        case 703:
            return LLVMFuzzerTestOneInput_704(remainData, remainSize);
        case 704:
            return LLVMFuzzerTestOneInput_705(remainData, remainSize);
        case 705:
            return LLVMFuzzerTestOneInput_706(remainData, remainSize);
        case 706:
            return LLVMFuzzerTestOneInput_707(remainData, remainSize);
        case 707:
            return LLVMFuzzerTestOneInput_708(remainData, remainSize);
        case 708:
            return LLVMFuzzerTestOneInput_709(remainData, remainSize);
        case 709:
            return LLVMFuzzerTestOneInput_710(remainData, remainSize);
        case 710:
            return LLVMFuzzerTestOneInput_711(remainData, remainSize);
        case 711:
            return LLVMFuzzerTestOneInput_712(remainData, remainSize);
        case 712:
            return LLVMFuzzerTestOneInput_713(remainData, remainSize);
        case 713:
            return LLVMFuzzerTestOneInput_714(remainData, remainSize);
        case 714:
            return LLVMFuzzerTestOneInput_715(remainData, remainSize);
        case 715:
            return LLVMFuzzerTestOneInput_716(remainData, remainSize);
        case 716:
            return LLVMFuzzerTestOneInput_717(remainData, remainSize);
        case 717:
            return LLVMFuzzerTestOneInput_718(remainData, remainSize);
        case 718:
            return LLVMFuzzerTestOneInput_719(remainData, remainSize);
        case 719:
            return LLVMFuzzerTestOneInput_720(remainData, remainSize);
        case 720:
            return LLVMFuzzerTestOneInput_721(remainData, remainSize);
        case 721:
            return LLVMFuzzerTestOneInput_722(remainData, remainSize);
        case 722:
            return LLVMFuzzerTestOneInput_723(remainData, remainSize);
        case 723:
            return LLVMFuzzerTestOneInput_724(remainData, remainSize);
        case 724:
            return LLVMFuzzerTestOneInput_725(remainData, remainSize);
        case 725:
            return LLVMFuzzerTestOneInput_726(remainData, remainSize);
        case 726:
            return LLVMFuzzerTestOneInput_727(remainData, remainSize);
        case 727:
            return LLVMFuzzerTestOneInput_728(remainData, remainSize);
        case 728:
            return LLVMFuzzerTestOneInput_729(remainData, remainSize);
        case 729:
            return LLVMFuzzerTestOneInput_730(remainData, remainSize);
        case 730:
            return LLVMFuzzerTestOneInput_731(remainData, remainSize);
        case 731:
            return LLVMFuzzerTestOneInput_732(remainData, remainSize);
        case 732:
            return LLVMFuzzerTestOneInput_733(remainData, remainSize);
        case 733:
            return LLVMFuzzerTestOneInput_734(remainData, remainSize);
        case 734:
            return LLVMFuzzerTestOneInput_735(remainData, remainSize);
        case 735:
            return LLVMFuzzerTestOneInput_736(remainData, remainSize);
        case 736:
            return LLVMFuzzerTestOneInput_737(remainData, remainSize);
        case 737:
            return LLVMFuzzerTestOneInput_738(remainData, remainSize);
        case 738:
            return LLVMFuzzerTestOneInput_739(remainData, remainSize);
        case 739:
            return LLVMFuzzerTestOneInput_740(remainData, remainSize);
        case 740:
            return LLVMFuzzerTestOneInput_741(remainData, remainSize);
        case 741:
            return LLVMFuzzerTestOneInput_742(remainData, remainSize);
        case 742:
            return LLVMFuzzerTestOneInput_743(remainData, remainSize);
        case 743:
            return LLVMFuzzerTestOneInput_744(remainData, remainSize);
        case 744:
            return LLVMFuzzerTestOneInput_745(remainData, remainSize);
        case 745:
            return LLVMFuzzerTestOneInput_746(remainData, remainSize);
        case 746:
            return LLVMFuzzerTestOneInput_747(remainData, remainSize);
        case 747:
            return LLVMFuzzerTestOneInput_748(remainData, remainSize);
        case 748:
            return LLVMFuzzerTestOneInput_749(remainData, remainSize);
        case 749:
            return LLVMFuzzerTestOneInput_750(remainData, remainSize);
        case 750:
            return LLVMFuzzerTestOneInput_751(remainData, remainSize);
        case 751:
            return LLVMFuzzerTestOneInput_752(remainData, remainSize);
        case 752:
            return LLVMFuzzerTestOneInput_753(remainData, remainSize);
        case 753:
            return LLVMFuzzerTestOneInput_754(remainData, remainSize);
        case 754:
            return LLVMFuzzerTestOneInput_755(remainData, remainSize);
        case 755:
            return LLVMFuzzerTestOneInput_756(remainData, remainSize);
        case 756:
            return LLVMFuzzerTestOneInput_757(remainData, remainSize);
        case 757:
            return LLVMFuzzerTestOneInput_758(remainData, remainSize);
        case 758:
            return LLVMFuzzerTestOneInput_759(remainData, remainSize);
        case 759:
            return LLVMFuzzerTestOneInput_760(remainData, remainSize);
        case 760:
            return LLVMFuzzerTestOneInput_761(remainData, remainSize);
        case 761:
            return LLVMFuzzerTestOneInput_762(remainData, remainSize);
        case 762:
            return LLVMFuzzerTestOneInput_763(remainData, remainSize);
        case 763:
            return LLVMFuzzerTestOneInput_764(remainData, remainSize);
        case 764:
            return LLVMFuzzerTestOneInput_765(remainData, remainSize);
        case 765:
            return LLVMFuzzerTestOneInput_766(remainData, remainSize);
        case 766:
            return LLVMFuzzerTestOneInput_767(remainData, remainSize);
        case 767:
            return LLVMFuzzerTestOneInput_768(remainData, remainSize);
        case 768:
            return LLVMFuzzerTestOneInput_769(remainData, remainSize);
        case 769:
            return LLVMFuzzerTestOneInput_770(remainData, remainSize);
        case 770:
            return LLVMFuzzerTestOneInput_771(remainData, remainSize);
        case 771:
            return LLVMFuzzerTestOneInput_772(remainData, remainSize);
        case 772:
            return LLVMFuzzerTestOneInput_773(remainData, remainSize);
        case 773:
            return LLVMFuzzerTestOneInput_774(remainData, remainSize);
        case 774:
            return LLVMFuzzerTestOneInput_775(remainData, remainSize);
        case 775:
            return LLVMFuzzerTestOneInput_776(remainData, remainSize);
        case 776:
            return LLVMFuzzerTestOneInput_777(remainData, remainSize);
        case 777:
            return LLVMFuzzerTestOneInput_778(remainData, remainSize);
        case 778:
            return LLVMFuzzerTestOneInput_779(remainData, remainSize);
        case 779:
            return LLVMFuzzerTestOneInput_780(remainData, remainSize);
        case 780:
            return LLVMFuzzerTestOneInput_781(remainData, remainSize);
        case 781:
            return LLVMFuzzerTestOneInput_782(remainData, remainSize);
        case 782:
            return LLVMFuzzerTestOneInput_783(remainData, remainSize);
        case 783:
            return LLVMFuzzerTestOneInput_784(remainData, remainSize);
        case 784:
            return LLVMFuzzerTestOneInput_785(remainData, remainSize);
        case 785:
            return LLVMFuzzerTestOneInput_786(remainData, remainSize);
        case 786:
            return LLVMFuzzerTestOneInput_787(remainData, remainSize);
        case 787:
            return LLVMFuzzerTestOneInput_788(remainData, remainSize);
        case 788:
            return LLVMFuzzerTestOneInput_789(remainData, remainSize);
        case 789:
            return LLVMFuzzerTestOneInput_790(remainData, remainSize);
        case 790:
            return LLVMFuzzerTestOneInput_791(remainData, remainSize);
        case 791:
            return LLVMFuzzerTestOneInput_792(remainData, remainSize);
        case 792:
            return LLVMFuzzerTestOneInput_793(remainData, remainSize);
        case 793:
            return LLVMFuzzerTestOneInput_794(remainData, remainSize);
        case 794:
            return LLVMFuzzerTestOneInput_795(remainData, remainSize);
        case 795:
            return LLVMFuzzerTestOneInput_796(remainData, remainSize);
        case 796:
            return LLVMFuzzerTestOneInput_797(remainData, remainSize);
        case 797:
            return LLVMFuzzerTestOneInput_798(remainData, remainSize);
        case 798:
            return LLVMFuzzerTestOneInput_799(remainData, remainSize);
        case 799:
            return LLVMFuzzerTestOneInput_800(remainData, remainSize);
        case 800:
            return LLVMFuzzerTestOneInput_801(remainData, remainSize);
        case 801:
            return LLVMFuzzerTestOneInput_802(remainData, remainSize);
        case 802:
            return LLVMFuzzerTestOneInput_803(remainData, remainSize);
        case 803:
            return LLVMFuzzerTestOneInput_804(remainData, remainSize);
        case 804:
            return LLVMFuzzerTestOneInput_805(remainData, remainSize);
        case 805:
            return LLVMFuzzerTestOneInput_806(remainData, remainSize);
        case 806:
            return LLVMFuzzerTestOneInput_807(remainData, remainSize);
        case 807:
            return LLVMFuzzerTestOneInput_808(remainData, remainSize);
        case 808:
            return LLVMFuzzerTestOneInput_809(remainData, remainSize);
        case 809:
            return LLVMFuzzerTestOneInput_810(remainData, remainSize);
        case 810:
            return LLVMFuzzerTestOneInput_811(remainData, remainSize);
        case 811:
            return LLVMFuzzerTestOneInput_812(remainData, remainSize);
        case 812:
            return LLVMFuzzerTestOneInput_813(remainData, remainSize);
        case 813:
            return LLVMFuzzerTestOneInput_814(remainData, remainSize);
        case 814:
            return LLVMFuzzerTestOneInput_815(remainData, remainSize);
        case 815:
            return LLVMFuzzerTestOneInput_816(remainData, remainSize);
        case 816:
            return LLVMFuzzerTestOneInput_817(remainData, remainSize);
        case 817:
            return LLVMFuzzerTestOneInput_818(remainData, remainSize);
        case 818:
            return LLVMFuzzerTestOneInput_819(remainData, remainSize);
        case 819:
            return LLVMFuzzerTestOneInput_820(remainData, remainSize);
        case 820:
            return LLVMFuzzerTestOneInput_821(remainData, remainSize);
        case 821:
            return LLVMFuzzerTestOneInput_822(remainData, remainSize);
        case 822:
            return LLVMFuzzerTestOneInput_823(remainData, remainSize);
        case 823:
            return LLVMFuzzerTestOneInput_824(remainData, remainSize);
        case 824:
            return LLVMFuzzerTestOneInput_825(remainData, remainSize);
        case 825:
            return LLVMFuzzerTestOneInput_826(remainData, remainSize);
        case 826:
            return LLVMFuzzerTestOneInput_827(remainData, remainSize);
        case 827:
            return LLVMFuzzerTestOneInput_828(remainData, remainSize);
        case 828:
            return LLVMFuzzerTestOneInput_829(remainData, remainSize);
        case 829:
            return LLVMFuzzerTestOneInput_830(remainData, remainSize);
        case 830:
            return LLVMFuzzerTestOneInput_831(remainData, remainSize);
        case 831:
            return LLVMFuzzerTestOneInput_832(remainData, remainSize);
        case 832:
            return LLVMFuzzerTestOneInput_833(remainData, remainSize);
        case 833:
            return LLVMFuzzerTestOneInput_834(remainData, remainSize);
        case 834:
            return LLVMFuzzerTestOneInput_835(remainData, remainSize);
        case 835:
            return LLVMFuzzerTestOneInput_836(remainData, remainSize);
        case 836:
            return LLVMFuzzerTestOneInput_837(remainData, remainSize);
        case 837:
            return LLVMFuzzerTestOneInput_838(remainData, remainSize);
        case 838:
            return LLVMFuzzerTestOneInput_839(remainData, remainSize);
        case 839:
            return LLVMFuzzerTestOneInput_840(remainData, remainSize);
        case 840:
            return LLVMFuzzerTestOneInput_841(remainData, remainSize);
        case 841:
            return LLVMFuzzerTestOneInput_842(remainData, remainSize);
        case 842:
            return LLVMFuzzerTestOneInput_843(remainData, remainSize);
        case 843:
            return LLVMFuzzerTestOneInput_844(remainData, remainSize);
        case 844:
            return LLVMFuzzerTestOneInput_845(remainData, remainSize);
        case 845:
            return LLVMFuzzerTestOneInput_846(remainData, remainSize);
        case 846:
            return LLVMFuzzerTestOneInput_847(remainData, remainSize);
        case 847:
            return LLVMFuzzerTestOneInput_848(remainData, remainSize);
        case 848:
            return LLVMFuzzerTestOneInput_849(remainData, remainSize);
        case 849:
            return LLVMFuzzerTestOneInput_850(remainData, remainSize);
        case 850:
            return LLVMFuzzerTestOneInput_851(remainData, remainSize);
        case 851:
            return LLVMFuzzerTestOneInput_852(remainData, remainSize);
        case 852:
            return LLVMFuzzerTestOneInput_853(remainData, remainSize);
        case 853:
            return LLVMFuzzerTestOneInput_854(remainData, remainSize);
        case 854:
            return LLVMFuzzerTestOneInput_855(remainData, remainSize);
        case 855:
            return LLVMFuzzerTestOneInput_856(remainData, remainSize);
        case 856:
            return LLVMFuzzerTestOneInput_857(remainData, remainSize);
        case 857:
            return LLVMFuzzerTestOneInput_858(remainData, remainSize);
        case 858:
            return LLVMFuzzerTestOneInput_859(remainData, remainSize);
        case 859:
            return LLVMFuzzerTestOneInput_860(remainData, remainSize);
        case 860:
            return LLVMFuzzerTestOneInput_861(remainData, remainSize);
        case 861:
            return LLVMFuzzerTestOneInput_862(remainData, remainSize);
        case 862:
            return LLVMFuzzerTestOneInput_863(remainData, remainSize);
        case 863:
            return LLVMFuzzerTestOneInput_864(remainData, remainSize);
        case 864:
            return LLVMFuzzerTestOneInput_865(remainData, remainSize);
        case 865:
            return LLVMFuzzerTestOneInput_866(remainData, remainSize);
        case 866:
            return LLVMFuzzerTestOneInput_867(remainData, remainSize);
        case 867:
            return LLVMFuzzerTestOneInput_868(remainData, remainSize);
        case 868:
            return LLVMFuzzerTestOneInput_869(remainData, remainSize);
        case 869:
            return LLVMFuzzerTestOneInput_870(remainData, remainSize);
        case 870:
            return LLVMFuzzerTestOneInput_871(remainData, remainSize);
        case 871:
            return LLVMFuzzerTestOneInput_872(remainData, remainSize);
        case 872:
            return LLVMFuzzerTestOneInput_873(remainData, remainSize);
        case 873:
            return LLVMFuzzerTestOneInput_874(remainData, remainSize);
        case 874:
            return LLVMFuzzerTestOneInput_875(remainData, remainSize);
        case 875:
            return LLVMFuzzerTestOneInput_876(remainData, remainSize);
        case 876:
            return LLVMFuzzerTestOneInput_877(remainData, remainSize);
        case 877:
            return LLVMFuzzerTestOneInput_878(remainData, remainSize);
        case 878:
            return LLVMFuzzerTestOneInput_879(remainData, remainSize);
        case 879:
            return LLVMFuzzerTestOneInput_880(remainData, remainSize);
        case 880:
            return LLVMFuzzerTestOneInput_881(remainData, remainSize);
        case 881:
            return LLVMFuzzerTestOneInput_882(remainData, remainSize);
        case 882:
            return LLVMFuzzerTestOneInput_883(remainData, remainSize);
        case 883:
            return LLVMFuzzerTestOneInput_884(remainData, remainSize);
        case 884:
            return LLVMFuzzerTestOneInput_885(remainData, remainSize);
        case 885:
            return LLVMFuzzerTestOneInput_886(remainData, remainSize);
        case 886:
            return LLVMFuzzerTestOneInput_887(remainData, remainSize);
        case 887:
            return LLVMFuzzerTestOneInput_888(remainData, remainSize);
        case 888:
            return LLVMFuzzerTestOneInput_889(remainData, remainSize);
        case 889:
            return LLVMFuzzerTestOneInput_890(remainData, remainSize);
        case 890:
            return LLVMFuzzerTestOneInput_891(remainData, remainSize);
        case 891:
            return LLVMFuzzerTestOneInput_892(remainData, remainSize);
        case 892:
            return LLVMFuzzerTestOneInput_893(remainData, remainSize);
        case 893:
            return LLVMFuzzerTestOneInput_894(remainData, remainSize);
        case 894:
            return LLVMFuzzerTestOneInput_895(remainData, remainSize);
        case 895:
            return LLVMFuzzerTestOneInput_896(remainData, remainSize);
        case 896:
            return LLVMFuzzerTestOneInput_897(remainData, remainSize);
        case 897:
            return LLVMFuzzerTestOneInput_898(remainData, remainSize);
        case 898:
            return LLVMFuzzerTestOneInput_899(remainData, remainSize);
        case 899:
            return LLVMFuzzerTestOneInput_900(remainData, remainSize);
        case 900:
            return LLVMFuzzerTestOneInput_901(remainData, remainSize);
        case 901:
            return LLVMFuzzerTestOneInput_902(remainData, remainSize);
        case 902:
            return LLVMFuzzerTestOneInput_903(remainData, remainSize);
        case 903:
            return LLVMFuzzerTestOneInput_904(remainData, remainSize);
        case 904:
            return LLVMFuzzerTestOneInput_905(remainData, remainSize);
        case 905:
            return LLVMFuzzerTestOneInput_906(remainData, remainSize);
        case 906:
            return LLVMFuzzerTestOneInput_907(remainData, remainSize);
        case 907:
            return LLVMFuzzerTestOneInput_908(remainData, remainSize);
        case 908:
            return LLVMFuzzerTestOneInput_909(remainData, remainSize);
        case 909:
            return LLVMFuzzerTestOneInput_910(remainData, remainSize);
        case 910:
            return LLVMFuzzerTestOneInput_911(remainData, remainSize);
        case 911:
            return LLVMFuzzerTestOneInput_912(remainData, remainSize);
        case 912:
            return LLVMFuzzerTestOneInput_913(remainData, remainSize);
        case 913:
            return LLVMFuzzerTestOneInput_914(remainData, remainSize);
        case 914:
            return LLVMFuzzerTestOneInput_915(remainData, remainSize);
        case 915:
            return LLVMFuzzerTestOneInput_916(remainData, remainSize);
        case 916:
            return LLVMFuzzerTestOneInput_917(remainData, remainSize);
        case 917:
            return LLVMFuzzerTestOneInput_918(remainData, remainSize);
        case 918:
            return LLVMFuzzerTestOneInput_919(remainData, remainSize);
        case 919:
            return LLVMFuzzerTestOneInput_920(remainData, remainSize);
        case 920:
            return LLVMFuzzerTestOneInput_921(remainData, remainSize);
        case 921:
            return LLVMFuzzerTestOneInput_922(remainData, remainSize);
        case 922:
            return LLVMFuzzerTestOneInput_923(remainData, remainSize);
        case 923:
            return LLVMFuzzerTestOneInput_924(remainData, remainSize);
        case 924:
            return LLVMFuzzerTestOneInput_925(remainData, remainSize);
        case 925:
            return LLVMFuzzerTestOneInput_926(remainData, remainSize);
        case 926:
            return LLVMFuzzerTestOneInput_927(remainData, remainSize);
        case 927:
            return LLVMFuzzerTestOneInput_928(remainData, remainSize);
        case 928:
            return LLVMFuzzerTestOneInput_929(remainData, remainSize);
        case 929:
            return LLVMFuzzerTestOneInput_930(remainData, remainSize);
        case 930:
            return LLVMFuzzerTestOneInput_931(remainData, remainSize);
        case 931:
            return LLVMFuzzerTestOneInput_932(remainData, remainSize);
        case 932:
            return LLVMFuzzerTestOneInput_933(remainData, remainSize);
        case 933:
            return LLVMFuzzerTestOneInput_934(remainData, remainSize);
        case 934:
            return LLVMFuzzerTestOneInput_935(remainData, remainSize);
        case 935:
            return LLVMFuzzerTestOneInput_936(remainData, remainSize);
        case 936:
            return LLVMFuzzerTestOneInput_937(remainData, remainSize);
        case 937:
            return LLVMFuzzerTestOneInput_938(remainData, remainSize);
        case 938:
            return LLVMFuzzerTestOneInput_939(remainData, remainSize);
        case 939:
            return LLVMFuzzerTestOneInput_940(remainData, remainSize);
        case 940:
            return LLVMFuzzerTestOneInput_941(remainData, remainSize);
        case 941:
            return LLVMFuzzerTestOneInput_942(remainData, remainSize);
        case 942:
            return LLVMFuzzerTestOneInput_943(remainData, remainSize);
        case 943:
            return LLVMFuzzerTestOneInput_944(remainData, remainSize);
        case 944:
            return LLVMFuzzerTestOneInput_945(remainData, remainSize);
        case 945:
            return LLVMFuzzerTestOneInput_946(remainData, remainSize);
        case 946:
            return LLVMFuzzerTestOneInput_947(remainData, remainSize);
        case 947:
            return LLVMFuzzerTestOneInput_948(remainData, remainSize);
        case 948:
            return LLVMFuzzerTestOneInput_949(remainData, remainSize);
        case 949:
            return LLVMFuzzerTestOneInput_950(remainData, remainSize);
        case 950:
            return LLVMFuzzerTestOneInput_951(remainData, remainSize);
        case 951:
            return LLVMFuzzerTestOneInput_952(remainData, remainSize);
        case 952:
            return LLVMFuzzerTestOneInput_953(remainData, remainSize);
        case 953:
            return LLVMFuzzerTestOneInput_954(remainData, remainSize);
        case 954:
            return LLVMFuzzerTestOneInput_955(remainData, remainSize);
        case 955:
            return LLVMFuzzerTestOneInput_956(remainData, remainSize);
        case 956:
            return LLVMFuzzerTestOneInput_957(remainData, remainSize);
        case 957:
            return LLVMFuzzerTestOneInput_958(remainData, remainSize);
        case 958:
            return LLVMFuzzerTestOneInput_959(remainData, remainSize);
        case 959:
            return LLVMFuzzerTestOneInput_960(remainData, remainSize);
        case 960:
            return LLVMFuzzerTestOneInput_961(remainData, remainSize);
        case 961:
            return LLVMFuzzerTestOneInput_962(remainData, remainSize);
        case 962:
            return LLVMFuzzerTestOneInput_963(remainData, remainSize);
        case 963:
            return LLVMFuzzerTestOneInput_964(remainData, remainSize);
        case 964:
            return LLVMFuzzerTestOneInput_965(remainData, remainSize);
        case 965:
            return LLVMFuzzerTestOneInput_966(remainData, remainSize);
        case 966:
            return LLVMFuzzerTestOneInput_967(remainData, remainSize);
        case 967:
            return LLVMFuzzerTestOneInput_968(remainData, remainSize);
        case 968:
            return LLVMFuzzerTestOneInput_969(remainData, remainSize);
        case 969:
            return LLVMFuzzerTestOneInput_970(remainData, remainSize);
        case 970:
            return LLVMFuzzerTestOneInput_971(remainData, remainSize);
        case 971:
            return LLVMFuzzerTestOneInput_972(remainData, remainSize);
        case 972:
            return LLVMFuzzerTestOneInput_973(remainData, remainSize);
        case 973:
            return LLVMFuzzerTestOneInput_974(remainData, remainSize);
        case 974:
            return LLVMFuzzerTestOneInput_975(remainData, remainSize);
        case 975:
            return LLVMFuzzerTestOneInput_976(remainData, remainSize);
        case 976:
            return LLVMFuzzerTestOneInput_977(remainData, remainSize);
        case 977:
            return LLVMFuzzerTestOneInput_978(remainData, remainSize);
        case 978:
            return LLVMFuzzerTestOneInput_979(remainData, remainSize);
        case 979:
            return LLVMFuzzerTestOneInput_980(remainData, remainSize);
        case 980:
            return LLVMFuzzerTestOneInput_981(remainData, remainSize);
        case 981:
            return LLVMFuzzerTestOneInput_982(remainData, remainSize);
        case 982:
            return LLVMFuzzerTestOneInput_983(remainData, remainSize);
        case 983:
            return LLVMFuzzerTestOneInput_984(remainData, remainSize);
        case 984:
            return LLVMFuzzerTestOneInput_985(remainData, remainSize);
        case 985:
            return LLVMFuzzerTestOneInput_986(remainData, remainSize);
        case 986:
            return LLVMFuzzerTestOneInput_987(remainData, remainSize);
        case 987:
            return LLVMFuzzerTestOneInput_988(remainData, remainSize);
        case 988:
            return LLVMFuzzerTestOneInput_989(remainData, remainSize);
        case 989:
            return LLVMFuzzerTestOneInput_990(remainData, remainSize);
        case 990:
            return LLVMFuzzerTestOneInput_991(remainData, remainSize);
        case 991:
            return LLVMFuzzerTestOneInput_992(remainData, remainSize);
        case 992:
            return LLVMFuzzerTestOneInput_993(remainData, remainSize);
        case 993:
            return LLVMFuzzerTestOneInput_994(remainData, remainSize);
        case 994:
            return LLVMFuzzerTestOneInput_995(remainData, remainSize);
        case 995:
            return LLVMFuzzerTestOneInput_996(remainData, remainSize);
        case 996:
            return LLVMFuzzerTestOneInput_997(remainData, remainSize);
        case 997:
            return LLVMFuzzerTestOneInput_998(remainData, remainSize);
        case 998:
            return LLVMFuzzerTestOneInput_999(remainData, remainSize);
        case 999:
            return LLVMFuzzerTestOneInput_1000(remainData, remainSize);
        case 1000:
            return LLVMFuzzerTestOneInput_1001(remainData, remainSize);
        case 1001:
            return LLVMFuzzerTestOneInput_1002(remainData, remainSize);
        case 1002:
            return LLVMFuzzerTestOneInput_1003(remainData, remainSize);
        case 1003:
            return LLVMFuzzerTestOneInput_1004(remainData, remainSize);
        case 1004:
            return LLVMFuzzerTestOneInput_1005(remainData, remainSize);
        case 1005:
            return LLVMFuzzerTestOneInput_1006(remainData, remainSize);
        case 1006:
            return LLVMFuzzerTestOneInput_1007(remainData, remainSize);
        case 1007:
            return LLVMFuzzerTestOneInput_1008(remainData, remainSize);
        case 1008:
            return LLVMFuzzerTestOneInput_1009(remainData, remainSize);
        case 1009:
            return LLVMFuzzerTestOneInput_1010(remainData, remainSize);
        case 1010:
            return LLVMFuzzerTestOneInput_1011(remainData, remainSize);
        case 1011:
            return LLVMFuzzerTestOneInput_1012(remainData, remainSize);
        case 1012:
            return LLVMFuzzerTestOneInput_1013(remainData, remainSize);
        case 1013:
            return LLVMFuzzerTestOneInput_1014(remainData, remainSize);
        case 1014:
            return LLVMFuzzerTestOneInput_1015(remainData, remainSize);
        case 1015:
            return LLVMFuzzerTestOneInput_1016(remainData, remainSize);
        case 1016:
            return LLVMFuzzerTestOneInput_1017(remainData, remainSize);
        case 1017:
            return LLVMFuzzerTestOneInput_1018(remainData, remainSize);
        case 1018:
            return LLVMFuzzerTestOneInput_1019(remainData, remainSize);
        case 1019:
            return LLVMFuzzerTestOneInput_1020(remainData, remainSize);
        case 1020:
            return LLVMFuzzerTestOneInput_1021(remainData, remainSize);
        case 1021:
            return LLVMFuzzerTestOneInput_1022(remainData, remainSize);
        case 1022:
            return LLVMFuzzerTestOneInput_1023(remainData, remainSize);
        case 1023:
            return LLVMFuzzerTestOneInput_1024(remainData, remainSize);
        case 1024:
            return LLVMFuzzerTestOneInput_1025(remainData, remainSize);
        case 1025:
            return LLVMFuzzerTestOneInput_1026(remainData, remainSize);
        case 1026:
            return LLVMFuzzerTestOneInput_1027(remainData, remainSize);
        case 1027:
            return LLVMFuzzerTestOneInput_1028(remainData, remainSize);
        case 1028:
            return LLVMFuzzerTestOneInput_1029(remainData, remainSize);
        case 1029:
            return LLVMFuzzerTestOneInput_1030(remainData, remainSize);
        case 1030:
            return LLVMFuzzerTestOneInput_1031(remainData, remainSize);
        case 1031:
            return LLVMFuzzerTestOneInput_1032(remainData, remainSize);
        case 1032:
            return LLVMFuzzerTestOneInput_1033(remainData, remainSize);
        case 1033:
            return LLVMFuzzerTestOneInput_1034(remainData, remainSize);
        case 1034:
            return LLVMFuzzerTestOneInput_1035(remainData, remainSize);
        case 1035:
            return LLVMFuzzerTestOneInput_1036(remainData, remainSize);
        case 1036:
            return LLVMFuzzerTestOneInput_1037(remainData, remainSize);
        case 1037:
            return LLVMFuzzerTestOneInput_1038(remainData, remainSize);
        case 1038:
            return LLVMFuzzerTestOneInput_1039(remainData, remainSize);
        case 1039:
            return LLVMFuzzerTestOneInput_1040(remainData, remainSize);
        case 1040:
            return LLVMFuzzerTestOneInput_1041(remainData, remainSize);
        case 1041:
            return LLVMFuzzerTestOneInput_1042(remainData, remainSize);
        case 1042:
            return LLVMFuzzerTestOneInput_1043(remainData, remainSize);
        case 1043:
            return LLVMFuzzerTestOneInput_1044(remainData, remainSize);
        case 1044:
            return LLVMFuzzerTestOneInput_1045(remainData, remainSize);
        case 1045:
            return LLVMFuzzerTestOneInput_1046(remainData, remainSize);
        case 1046:
            return LLVMFuzzerTestOneInput_1047(remainData, remainSize);
        case 1047:
            return LLVMFuzzerTestOneInput_1048(remainData, remainSize);
        case 1048:
            return LLVMFuzzerTestOneInput_1049(remainData, remainSize);
        case 1049:
            return LLVMFuzzerTestOneInput_1050(remainData, remainSize);
        case 1050:
            return LLVMFuzzerTestOneInput_1051(remainData, remainSize);
        case 1051:
            return LLVMFuzzerTestOneInput_1052(remainData, remainSize);
        case 1052:
            return LLVMFuzzerTestOneInput_1053(remainData, remainSize);
        case 1053:
            return LLVMFuzzerTestOneInput_1054(remainData, remainSize);
        case 1054:
            return LLVMFuzzerTestOneInput_1055(remainData, remainSize);
        case 1055:
            return LLVMFuzzerTestOneInput_1056(remainData, remainSize);
        case 1056:
            return LLVMFuzzerTestOneInput_1057(remainData, remainSize);
        case 1057:
            return LLVMFuzzerTestOneInput_1058(remainData, remainSize);
        case 1058:
            return LLVMFuzzerTestOneInput_1059(remainData, remainSize);
        case 1059:
            return LLVMFuzzerTestOneInput_1060(remainData, remainSize);
        case 1060:
            return LLVMFuzzerTestOneInput_1061(remainData, remainSize);
        case 1061:
            return LLVMFuzzerTestOneInput_1062(remainData, remainSize);
        case 1062:
            return LLVMFuzzerTestOneInput_1063(remainData, remainSize);
        case 1063:
            return LLVMFuzzerTestOneInput_1064(remainData, remainSize);
        case 1064:
            return LLVMFuzzerTestOneInput_1065(remainData, remainSize);
        case 1065:
            return LLVMFuzzerTestOneInput_1066(remainData, remainSize);
        case 1066:
            return LLVMFuzzerTestOneInput_1067(remainData, remainSize);
        case 1067:
            return LLVMFuzzerTestOneInput_1068(remainData, remainSize);
        case 1068:
            return LLVMFuzzerTestOneInput_1069(remainData, remainSize);
        case 1069:
            return LLVMFuzzerTestOneInput_1070(remainData, remainSize);
        case 1070:
            return LLVMFuzzerTestOneInput_1071(remainData, remainSize);
        case 1071:
            return LLVMFuzzerTestOneInput_1072(remainData, remainSize);
        case 1072:
            return LLVMFuzzerTestOneInput_1073(remainData, remainSize);
        case 1073:
            return LLVMFuzzerTestOneInput_1074(remainData, remainSize);
        case 1074:
            return LLVMFuzzerTestOneInput_1075(remainData, remainSize);
        case 1075:
            return LLVMFuzzerTestOneInput_1076(remainData, remainSize);
        case 1076:
            return LLVMFuzzerTestOneInput_1077(remainData, remainSize);
        case 1077:
            return LLVMFuzzerTestOneInput_1078(remainData, remainSize);
        case 1078:
            return LLVMFuzzerTestOneInput_1079(remainData, remainSize);
        case 1079:
            return LLVMFuzzerTestOneInput_1080(remainData, remainSize);
        case 1080:
            return LLVMFuzzerTestOneInput_1081(remainData, remainSize);
        case 1081:
            return LLVMFuzzerTestOneInput_1082(remainData, remainSize);
        case 1082:
            return LLVMFuzzerTestOneInput_1083(remainData, remainSize);
        case 1083:
            return LLVMFuzzerTestOneInput_1084(remainData, remainSize);
        case 1084:
            return LLVMFuzzerTestOneInput_1085(remainData, remainSize);
        case 1085:
            return LLVMFuzzerTestOneInput_1086(remainData, remainSize);
        case 1086:
            return LLVMFuzzerTestOneInput_1087(remainData, remainSize);
        case 1087:
            return LLVMFuzzerTestOneInput_1088(remainData, remainSize);
        case 1088:
            return LLVMFuzzerTestOneInput_1089(remainData, remainSize);
        case 1089:
            return LLVMFuzzerTestOneInput_1090(remainData, remainSize);
        case 1090:
            return LLVMFuzzerTestOneInput_1091(remainData, remainSize);
        case 1091:
            return LLVMFuzzerTestOneInput_1092(remainData, remainSize);
        case 1092:
            return LLVMFuzzerTestOneInput_1093(remainData, remainSize);
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
