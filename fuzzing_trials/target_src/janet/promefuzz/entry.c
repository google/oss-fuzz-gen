// This is the entry of 227 fuzz drivers:
// 4, 6, 8, 9, 11, 13, 14, 18, 26, 29, 32, 34, 38, 39, 41, 48, 62, 65, 75, 78, 83, 
// 84, 93, 104, 111, 118, 133, 137, 141, 142, 144, 146, 149, 150, 155, 163, 164, 16
// 5, 170, 172, 177, 178, 179, 188, 200, 207, 209, 212, 215, 217, 218, 221, 223, 22
// 4, 226, 229, 232, 233, 235, 236, 242, 250, 257, 259, 260, 264, 265, 273, 276, 27
// 8, 292, 296, 300, 302, 305, 314, 317, 322, 327, 328, 330, 338, 346, 351, 353, 35
// 7, 359, 363, 368, 371, 372, 374, 376, 378, 379, 381, 383, 388, 390, 393, 394, 40
// 2, 403, 404, 405, 412, 417, 420, 425, 426, 433, 439, 443, 445, 450, 451, 452, 45
// 5, 461, 465, 475, 476, 480, 481, 483, 495, 499, 501, 503, 506, 508, 511, 513, 51
// 9, 523, 526, 527, 529, 533, 534, 537, 538, 539, 544, 547, 551, 561, 571, 576, 57
// 7, 578, 581, 584, 587, 595, 596, 601, 603, 604, 605, 606, 607, 608, 613, 614, 61
// 5, 617, 619, 620, 622, 624, 626, 628, 635, 640, 641, 649, 653, 660, 665, 666, 66
// 7, 672, 676, 679, 681, 683, 689, 694, 695, 701, 702, 704, 705, 706, 709, 713, 72
// 2, 725, 727, 728, 729, 730, 734, 737, 740, 741, 743, 752, 756, 758, 759, 762, 76
// 5, 766, 767, 771, 772, 774, 779, 780, 783, 786, 787, 796, 798, 800
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <memory.h>

// Declarations of all fuzz drivers `LLVMFuzzerTestOneInput` functions
int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_38(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_83(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_93(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_104(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_111(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_118(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_133(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_137(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_142(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_144(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_146(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_149(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_150(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_155(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_163(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_164(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_165(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_170(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_172(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_177(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_178(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_179(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_188(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_200(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_207(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_209(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_212(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_215(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_217(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_218(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_221(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_223(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_224(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_226(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_229(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_232(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_233(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_235(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_236(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_242(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_250(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_257(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_259(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_260(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_264(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_265(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_273(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_276(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_278(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_292(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_296(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_300(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_302(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_305(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_314(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_317(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_322(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_327(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_328(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_330(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_338(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_346(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_351(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_353(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_357(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_359(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_363(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_368(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_371(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_372(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_374(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_376(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_378(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_379(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_381(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_383(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_388(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_390(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_393(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_394(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_402(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_403(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_404(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_405(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_412(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_417(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_420(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_425(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_426(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_433(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_439(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_443(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_445(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_450(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_451(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_452(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_455(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_461(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_465(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_475(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_476(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_480(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_481(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_483(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_495(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_499(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_501(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_503(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_506(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_508(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_511(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_513(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_519(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_523(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_526(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_527(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_529(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_533(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_534(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_537(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_538(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_539(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_544(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_547(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_551(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_561(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_571(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_576(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_577(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_578(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_581(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_584(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_587(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_595(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_596(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_601(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_603(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_604(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_605(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_606(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_607(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_608(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_613(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_614(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_615(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_617(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_619(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_620(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_622(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_624(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_626(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_628(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_635(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_640(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_641(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_649(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_653(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_660(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_665(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_666(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_667(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_672(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_676(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_679(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_681(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_683(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_689(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_694(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_695(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_701(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_702(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_704(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_705(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_706(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_709(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_713(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_722(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_725(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_727(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_728(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_729(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_730(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_734(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_737(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_740(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_741(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_743(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_752(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_756(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_758(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_759(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_762(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_765(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_766(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_767(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_771(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_772(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_774(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_779(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_780(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_783(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_786(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_787(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_796(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_798(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput_800(const uint8_t *Data, size_t Size);

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
    switch (driverIndex % 227) {
        case 0:
            return LLVMFuzzerTestOneInput_4(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_6(remainData, remainSize);
        case 2:
            return LLVMFuzzerTestOneInput_8(remainData, remainSize);
        case 3:
            return LLVMFuzzerTestOneInput_9(remainData, remainSize);
        case 4:
            return LLVMFuzzerTestOneInput_11(remainData, remainSize);
        case 5:
            return LLVMFuzzerTestOneInput_13(remainData, remainSize);
        case 6:
            return LLVMFuzzerTestOneInput_14(remainData, remainSize);
        case 7:
            return LLVMFuzzerTestOneInput_18(remainData, remainSize);
        case 8:
            return LLVMFuzzerTestOneInput_26(remainData, remainSize);
        case 9:
            return LLVMFuzzerTestOneInput_29(remainData, remainSize);
        case 10:
            return LLVMFuzzerTestOneInput_32(remainData, remainSize);
        case 11:
            return LLVMFuzzerTestOneInput_34(remainData, remainSize);
        case 12:
            return LLVMFuzzerTestOneInput_38(remainData, remainSize);
        case 13:
            return LLVMFuzzerTestOneInput_39(remainData, remainSize);
        case 14:
            return LLVMFuzzerTestOneInput_41(remainData, remainSize);
        case 15:
            return LLVMFuzzerTestOneInput_48(remainData, remainSize);
        case 16:
            return LLVMFuzzerTestOneInput_62(remainData, remainSize);
        case 17:
            return LLVMFuzzerTestOneInput_65(remainData, remainSize);
        case 18:
            return LLVMFuzzerTestOneInput_75(remainData, remainSize);
        case 19:
            return LLVMFuzzerTestOneInput_78(remainData, remainSize);
        case 20:
            return LLVMFuzzerTestOneInput_83(remainData, remainSize);
        case 21:
            return LLVMFuzzerTestOneInput_84(remainData, remainSize);
        case 22:
            return LLVMFuzzerTestOneInput_93(remainData, remainSize);
        case 23:
            return LLVMFuzzerTestOneInput_104(remainData, remainSize);
        case 24:
            return LLVMFuzzerTestOneInput_111(remainData, remainSize);
        case 25:
            return LLVMFuzzerTestOneInput_118(remainData, remainSize);
        case 26:
            return LLVMFuzzerTestOneInput_133(remainData, remainSize);
        case 27:
            return LLVMFuzzerTestOneInput_137(remainData, remainSize);
        case 28:
            return LLVMFuzzerTestOneInput_141(remainData, remainSize);
        case 29:
            return LLVMFuzzerTestOneInput_142(remainData, remainSize);
        case 30:
            return LLVMFuzzerTestOneInput_144(remainData, remainSize);
        case 31:
            return LLVMFuzzerTestOneInput_146(remainData, remainSize);
        case 32:
            return LLVMFuzzerTestOneInput_149(remainData, remainSize);
        case 33:
            return LLVMFuzzerTestOneInput_150(remainData, remainSize);
        case 34:
            return LLVMFuzzerTestOneInput_155(remainData, remainSize);
        case 35:
            return LLVMFuzzerTestOneInput_163(remainData, remainSize);
        case 36:
            return LLVMFuzzerTestOneInput_164(remainData, remainSize);
        case 37:
            return LLVMFuzzerTestOneInput_165(remainData, remainSize);
        case 38:
            return LLVMFuzzerTestOneInput_170(remainData, remainSize);
        case 39:
            return LLVMFuzzerTestOneInput_172(remainData, remainSize);
        case 40:
            return LLVMFuzzerTestOneInput_177(remainData, remainSize);
        case 41:
            return LLVMFuzzerTestOneInput_178(remainData, remainSize);
        case 42:
            return LLVMFuzzerTestOneInput_179(remainData, remainSize);
        case 43:
            return LLVMFuzzerTestOneInput_188(remainData, remainSize);
        case 44:
            return LLVMFuzzerTestOneInput_200(remainData, remainSize);
        case 45:
            return LLVMFuzzerTestOneInput_207(remainData, remainSize);
        case 46:
            return LLVMFuzzerTestOneInput_209(remainData, remainSize);
        case 47:
            return LLVMFuzzerTestOneInput_212(remainData, remainSize);
        case 48:
            return LLVMFuzzerTestOneInput_215(remainData, remainSize);
        case 49:
            return LLVMFuzzerTestOneInput_217(remainData, remainSize);
        case 50:
            return LLVMFuzzerTestOneInput_218(remainData, remainSize);
        case 51:
            return LLVMFuzzerTestOneInput_221(remainData, remainSize);
        case 52:
            return LLVMFuzzerTestOneInput_223(remainData, remainSize);
        case 53:
            return LLVMFuzzerTestOneInput_224(remainData, remainSize);
        case 54:
            return LLVMFuzzerTestOneInput_226(remainData, remainSize);
        case 55:
            return LLVMFuzzerTestOneInput_229(remainData, remainSize);
        case 56:
            return LLVMFuzzerTestOneInput_232(remainData, remainSize);
        case 57:
            return LLVMFuzzerTestOneInput_233(remainData, remainSize);
        case 58:
            return LLVMFuzzerTestOneInput_235(remainData, remainSize);
        case 59:
            return LLVMFuzzerTestOneInput_236(remainData, remainSize);
        case 60:
            return LLVMFuzzerTestOneInput_242(remainData, remainSize);
        case 61:
            return LLVMFuzzerTestOneInput_250(remainData, remainSize);
        case 62:
            return LLVMFuzzerTestOneInput_257(remainData, remainSize);
        case 63:
            return LLVMFuzzerTestOneInput_259(remainData, remainSize);
        case 64:
            return LLVMFuzzerTestOneInput_260(remainData, remainSize);
        case 65:
            return LLVMFuzzerTestOneInput_264(remainData, remainSize);
        case 66:
            return LLVMFuzzerTestOneInput_265(remainData, remainSize);
        case 67:
            return LLVMFuzzerTestOneInput_273(remainData, remainSize);
        case 68:
            return LLVMFuzzerTestOneInput_276(remainData, remainSize);
        case 69:
            return LLVMFuzzerTestOneInput_278(remainData, remainSize);
        case 70:
            return LLVMFuzzerTestOneInput_292(remainData, remainSize);
        case 71:
            return LLVMFuzzerTestOneInput_296(remainData, remainSize);
        case 72:
            return LLVMFuzzerTestOneInput_300(remainData, remainSize);
        case 73:
            return LLVMFuzzerTestOneInput_302(remainData, remainSize);
        case 74:
            return LLVMFuzzerTestOneInput_305(remainData, remainSize);
        case 75:
            return LLVMFuzzerTestOneInput_314(remainData, remainSize);
        case 76:
            return LLVMFuzzerTestOneInput_317(remainData, remainSize);
        case 77:
            return LLVMFuzzerTestOneInput_322(remainData, remainSize);
        case 78:
            return LLVMFuzzerTestOneInput_327(remainData, remainSize);
        case 79:
            return LLVMFuzzerTestOneInput_328(remainData, remainSize);
        case 80:
            return LLVMFuzzerTestOneInput_330(remainData, remainSize);
        case 81:
            return LLVMFuzzerTestOneInput_338(remainData, remainSize);
        case 82:
            return LLVMFuzzerTestOneInput_346(remainData, remainSize);
        case 83:
            return LLVMFuzzerTestOneInput_351(remainData, remainSize);
        case 84:
            return LLVMFuzzerTestOneInput_353(remainData, remainSize);
        case 85:
            return LLVMFuzzerTestOneInput_357(remainData, remainSize);
        case 86:
            return LLVMFuzzerTestOneInput_359(remainData, remainSize);
        case 87:
            return LLVMFuzzerTestOneInput_363(remainData, remainSize);
        case 88:
            return LLVMFuzzerTestOneInput_368(remainData, remainSize);
        case 89:
            return LLVMFuzzerTestOneInput_371(remainData, remainSize);
        case 90:
            return LLVMFuzzerTestOneInput_372(remainData, remainSize);
        case 91:
            return LLVMFuzzerTestOneInput_374(remainData, remainSize);
        case 92:
            return LLVMFuzzerTestOneInput_376(remainData, remainSize);
        case 93:
            return LLVMFuzzerTestOneInput_378(remainData, remainSize);
        case 94:
            return LLVMFuzzerTestOneInput_379(remainData, remainSize);
        case 95:
            return LLVMFuzzerTestOneInput_381(remainData, remainSize);
        case 96:
            return LLVMFuzzerTestOneInput_383(remainData, remainSize);
        case 97:
            return LLVMFuzzerTestOneInput_388(remainData, remainSize);
        case 98:
            return LLVMFuzzerTestOneInput_390(remainData, remainSize);
        case 99:
            return LLVMFuzzerTestOneInput_393(remainData, remainSize);
        case 100:
            return LLVMFuzzerTestOneInput_394(remainData, remainSize);
        case 101:
            return LLVMFuzzerTestOneInput_402(remainData, remainSize);
        case 102:
            return LLVMFuzzerTestOneInput_403(remainData, remainSize);
        case 103:
            return LLVMFuzzerTestOneInput_404(remainData, remainSize);
        case 104:
            return LLVMFuzzerTestOneInput_405(remainData, remainSize);
        case 105:
            return LLVMFuzzerTestOneInput_412(remainData, remainSize);
        case 106:
            return LLVMFuzzerTestOneInput_417(remainData, remainSize);
        case 107:
            return LLVMFuzzerTestOneInput_420(remainData, remainSize);
        case 108:
            return LLVMFuzzerTestOneInput_425(remainData, remainSize);
        case 109:
            return LLVMFuzzerTestOneInput_426(remainData, remainSize);
        case 110:
            return LLVMFuzzerTestOneInput_433(remainData, remainSize);
        case 111:
            return LLVMFuzzerTestOneInput_439(remainData, remainSize);
        case 112:
            return LLVMFuzzerTestOneInput_443(remainData, remainSize);
        case 113:
            return LLVMFuzzerTestOneInput_445(remainData, remainSize);
        case 114:
            return LLVMFuzzerTestOneInput_450(remainData, remainSize);
        case 115:
            return LLVMFuzzerTestOneInput_451(remainData, remainSize);
        case 116:
            return LLVMFuzzerTestOneInput_452(remainData, remainSize);
        case 117:
            return LLVMFuzzerTestOneInput_455(remainData, remainSize);
        case 118:
            return LLVMFuzzerTestOneInput_461(remainData, remainSize);
        case 119:
            return LLVMFuzzerTestOneInput_465(remainData, remainSize);
        case 120:
            return LLVMFuzzerTestOneInput_475(remainData, remainSize);
        case 121:
            return LLVMFuzzerTestOneInput_476(remainData, remainSize);
        case 122:
            return LLVMFuzzerTestOneInput_480(remainData, remainSize);
        case 123:
            return LLVMFuzzerTestOneInput_481(remainData, remainSize);
        case 124:
            return LLVMFuzzerTestOneInput_483(remainData, remainSize);
        case 125:
            return LLVMFuzzerTestOneInput_495(remainData, remainSize);
        case 126:
            return LLVMFuzzerTestOneInput_499(remainData, remainSize);
        case 127:
            return LLVMFuzzerTestOneInput_501(remainData, remainSize);
        case 128:
            return LLVMFuzzerTestOneInput_503(remainData, remainSize);
        case 129:
            return LLVMFuzzerTestOneInput_506(remainData, remainSize);
        case 130:
            return LLVMFuzzerTestOneInput_508(remainData, remainSize);
        case 131:
            return LLVMFuzzerTestOneInput_511(remainData, remainSize);
        case 132:
            return LLVMFuzzerTestOneInput_513(remainData, remainSize);
        case 133:
            return LLVMFuzzerTestOneInput_519(remainData, remainSize);
        case 134:
            return LLVMFuzzerTestOneInput_523(remainData, remainSize);
        case 135:
            return LLVMFuzzerTestOneInput_526(remainData, remainSize);
        case 136:
            return LLVMFuzzerTestOneInput_527(remainData, remainSize);
        case 137:
            return LLVMFuzzerTestOneInput_529(remainData, remainSize);
        case 138:
            return LLVMFuzzerTestOneInput_533(remainData, remainSize);
        case 139:
            return LLVMFuzzerTestOneInput_534(remainData, remainSize);
        case 140:
            return LLVMFuzzerTestOneInput_537(remainData, remainSize);
        case 141:
            return LLVMFuzzerTestOneInput_538(remainData, remainSize);
        case 142:
            return LLVMFuzzerTestOneInput_539(remainData, remainSize);
        case 143:
            return LLVMFuzzerTestOneInput_544(remainData, remainSize);
        case 144:
            return LLVMFuzzerTestOneInput_547(remainData, remainSize);
        case 145:
            return LLVMFuzzerTestOneInput_551(remainData, remainSize);
        case 146:
            return LLVMFuzzerTestOneInput_561(remainData, remainSize);
        case 147:
            return LLVMFuzzerTestOneInput_571(remainData, remainSize);
        case 148:
            return LLVMFuzzerTestOneInput_576(remainData, remainSize);
        case 149:
            return LLVMFuzzerTestOneInput_577(remainData, remainSize);
        case 150:
            return LLVMFuzzerTestOneInput_578(remainData, remainSize);
        case 151:
            return LLVMFuzzerTestOneInput_581(remainData, remainSize);
        case 152:
            return LLVMFuzzerTestOneInput_584(remainData, remainSize);
        case 153:
            return LLVMFuzzerTestOneInput_587(remainData, remainSize);
        case 154:
            return LLVMFuzzerTestOneInput_595(remainData, remainSize);
        case 155:
            return LLVMFuzzerTestOneInput_596(remainData, remainSize);
        case 156:
            return LLVMFuzzerTestOneInput_601(remainData, remainSize);
        case 157:
            return LLVMFuzzerTestOneInput_603(remainData, remainSize);
        case 158:
            return LLVMFuzzerTestOneInput_604(remainData, remainSize);
        case 159:
            return LLVMFuzzerTestOneInput_605(remainData, remainSize);
        case 160:
            return LLVMFuzzerTestOneInput_606(remainData, remainSize);
        case 161:
            return LLVMFuzzerTestOneInput_607(remainData, remainSize);
        case 162:
            return LLVMFuzzerTestOneInput_608(remainData, remainSize);
        case 163:
            return LLVMFuzzerTestOneInput_613(remainData, remainSize);
        case 164:
            return LLVMFuzzerTestOneInput_614(remainData, remainSize);
        case 165:
            return LLVMFuzzerTestOneInput_615(remainData, remainSize);
        case 166:
            return LLVMFuzzerTestOneInput_617(remainData, remainSize);
        case 167:
            return LLVMFuzzerTestOneInput_619(remainData, remainSize);
        case 168:
            return LLVMFuzzerTestOneInput_620(remainData, remainSize);
        case 169:
            return LLVMFuzzerTestOneInput_622(remainData, remainSize);
        case 170:
            return LLVMFuzzerTestOneInput_624(remainData, remainSize);
        case 171:
            return LLVMFuzzerTestOneInput_626(remainData, remainSize);
        case 172:
            return LLVMFuzzerTestOneInput_628(remainData, remainSize);
        case 173:
            return LLVMFuzzerTestOneInput_635(remainData, remainSize);
        case 174:
            return LLVMFuzzerTestOneInput_640(remainData, remainSize);
        case 175:
            return LLVMFuzzerTestOneInput_641(remainData, remainSize);
        case 176:
            return LLVMFuzzerTestOneInput_649(remainData, remainSize);
        case 177:
            return LLVMFuzzerTestOneInput_653(remainData, remainSize);
        case 178:
            return LLVMFuzzerTestOneInput_660(remainData, remainSize);
        case 179:
            return LLVMFuzzerTestOneInput_665(remainData, remainSize);
        case 180:
            return LLVMFuzzerTestOneInput_666(remainData, remainSize);
        case 181:
            return LLVMFuzzerTestOneInput_667(remainData, remainSize);
        case 182:
            return LLVMFuzzerTestOneInput_672(remainData, remainSize);
        case 183:
            return LLVMFuzzerTestOneInput_676(remainData, remainSize);
        case 184:
            return LLVMFuzzerTestOneInput_679(remainData, remainSize);
        case 185:
            return LLVMFuzzerTestOneInput_681(remainData, remainSize);
        case 186:
            return LLVMFuzzerTestOneInput_683(remainData, remainSize);
        case 187:
            return LLVMFuzzerTestOneInput_689(remainData, remainSize);
        case 188:
            return LLVMFuzzerTestOneInput_694(remainData, remainSize);
        case 189:
            return LLVMFuzzerTestOneInput_695(remainData, remainSize);
        case 190:
            return LLVMFuzzerTestOneInput_701(remainData, remainSize);
        case 191:
            return LLVMFuzzerTestOneInput_702(remainData, remainSize);
        case 192:
            return LLVMFuzzerTestOneInput_704(remainData, remainSize);
        case 193:
            return LLVMFuzzerTestOneInput_705(remainData, remainSize);
        case 194:
            return LLVMFuzzerTestOneInput_706(remainData, remainSize);
        case 195:
            return LLVMFuzzerTestOneInput_709(remainData, remainSize);
        case 196:
            return LLVMFuzzerTestOneInput_713(remainData, remainSize);
        case 197:
            return LLVMFuzzerTestOneInput_722(remainData, remainSize);
        case 198:
            return LLVMFuzzerTestOneInput_725(remainData, remainSize);
        case 199:
            return LLVMFuzzerTestOneInput_727(remainData, remainSize);
        case 200:
            return LLVMFuzzerTestOneInput_728(remainData, remainSize);
        case 201:
            return LLVMFuzzerTestOneInput_729(remainData, remainSize);
        case 202:
            return LLVMFuzzerTestOneInput_730(remainData, remainSize);
        case 203:
            return LLVMFuzzerTestOneInput_734(remainData, remainSize);
        case 204:
            return LLVMFuzzerTestOneInput_737(remainData, remainSize);
        case 205:
            return LLVMFuzzerTestOneInput_740(remainData, remainSize);
        case 206:
            return LLVMFuzzerTestOneInput_741(remainData, remainSize);
        case 207:
            return LLVMFuzzerTestOneInput_743(remainData, remainSize);
        case 208:
            return LLVMFuzzerTestOneInput_752(remainData, remainSize);
        case 209:
            return LLVMFuzzerTestOneInput_756(remainData, remainSize);
        case 210:
            return LLVMFuzzerTestOneInput_758(remainData, remainSize);
        case 211:
            return LLVMFuzzerTestOneInput_759(remainData, remainSize);
        case 212:
            return LLVMFuzzerTestOneInput_762(remainData, remainSize);
        case 213:
            return LLVMFuzzerTestOneInput_765(remainData, remainSize);
        case 214:
            return LLVMFuzzerTestOneInput_766(remainData, remainSize);
        case 215:
            return LLVMFuzzerTestOneInput_767(remainData, remainSize);
        case 216:
            return LLVMFuzzerTestOneInput_771(remainData, remainSize);
        case 217:
            return LLVMFuzzerTestOneInput_772(remainData, remainSize);
        case 218:
            return LLVMFuzzerTestOneInput_774(remainData, remainSize);
        case 219:
            return LLVMFuzzerTestOneInput_779(remainData, remainSize);
        case 220:
            return LLVMFuzzerTestOneInput_780(remainData, remainSize);
        case 221:
            return LLVMFuzzerTestOneInput_783(remainData, remainSize);
        case 222:
            return LLVMFuzzerTestOneInput_786(remainData, remainSize);
        case 223:
            return LLVMFuzzerTestOneInput_787(remainData, remainSize);
        case 224:
            return LLVMFuzzerTestOneInput_796(remainData, remainSize);
        case 225:
            return LLVMFuzzerTestOneInput_798(remainData, remainSize);
        case 226:
            return LLVMFuzzerTestOneInput_800(remainData, remainSize);
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

