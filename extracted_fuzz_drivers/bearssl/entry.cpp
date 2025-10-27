#include "driver.h"
#include "mutatorpool.h"
#include "numbers.h"
#include "repository_tbl.h"
#include <cryptofuzz/options.h>
#include <cstddef>
#include <cstdint>
#include <fuzzing/datasource/id.hpp>
#include <memory>
#include <set>
#include <string>
#include <vector>

#if defined(CRYPTOFUZZ_LIBTOMMATH) && defined(CRYPTOFUZZ_NSS)
#error "libtommath and NSS cannot be used together due to symbol collisions"
#endif

#if defined(CRYPTOFUZZ_TREZOR_FIRMWARE) && defined(CRYPTOFUZZ_RELIC)
#error "trezor-firmware and relic cannot be used together due to symbol collisions"
#endif

#if !defined(CRYPTOFUZZ_NO_OPENSSL)
#include <modules/openssl/module.h>
#ifdef SHA1
#undef SHA1
#endif
#ifdef SHA224
#undef SHA224
#endif
#ifdef SHA256
#undef SHA256
#endif
#ifdef SHA384
#undef SHA384
#endif
#ifdef SHA512
#undef SHA512
#endif
#endif

#if defined(CRYPTOFUZZ_BITCOIN)
#include <modules/bitcoin/module.h>
#endif

#if defined(CRYPTOFUZZ_REFERENCE)
#include <modules/reference/module.h>
#endif

#if defined(CRYPTOFUZZ_CPPCRYPTO)
#include <modules/cppcrypto/module.h>
#endif

#if defined(CRYPTOFUZZ_MBEDTLS)
#include <modules/mbedtls/module.h>
#endif

#if defined(CRYPTOFUZZ_BOOST)
#include <modules/boost/module.h>
#endif

#if defined(CRYPTOFUZZ_MONERO)
#include <modules/monero/module.h>
#endif

#if defined(CRYPTOFUZZ_VERACRYPT)
#include <modules/veracrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBSODIUM)
#include <modules/libsodium/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBTOMCRYPT)
#include <modules/libtomcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_CRYPTOPP)
#include <modules/cryptopp/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBGCRYPT)
#include <modules/libgcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_EVERCRYPT)
#include <modules/evercrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_GOLANG)
#include <modules/golang/module.h>
#endif

#if defined(CRYPTOFUZZ_RING)
#include <modules/ring/module.h>
#endif

#if defined(CRYPTOFUZZ_NSS)
#include <modules/nss/module.h>
#endif

#if defined(CRYPTOFUZZ_BOTAN)
#include <modules/botan/module.h>
#endif

#if defined(CRYPTOFUZZ_NETTLE)
#include <modules/nettle/module.h>
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT)
#include <modules/wolfcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBGMP)
#include <modules/libgmp/module.h>
#endif

#if defined(CRYPTOFUZZ_BN_JS)
#include <modules/bn.js/module.h>
#endif

#if defined(CRYPTOFUZZ_CRYPTO_JS)
#include <modules/crypto-js/module.h>
#endif

#if defined(CRYPTOFUZZ_BIGNUMBER_JS)
#include <modules/bignumber.js/module.h>
#endif

#if defined(CRYPTOFUZZ_MPDECIMAL)
#include <modules/mpdecimal/module.h>
#endif

#if defined(CRYPTOFUZZ_LINUX)
#include <modules/linux/module.h>
#endif

#if defined(CRYPTOFUZZ_SYMCRYPT)
#include <modules/symcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBTOMMATH)
#include <modules/libtommath/module.h>
#endif

#if defined(CRYPTOFUZZ_SJCL)
#include <modules/sjcl/module.h>
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
#include <modules/wolfcrypt-openssl/module.h>
#endif

#if defined(CRYPTOFUZZ_MONOCYPHER)
#include <modules/monocypher/module.h>
#endif

#if defined(CRYPTOFUZZ_SECP256K1)
#include <modules/secp256k1/module.h>
#endif

#if defined(CRYPTOFUZZ_RUST_LIBSECP256K1)
#include <modules/rust-libsecp256k1/module.h>
#endif

#if defined(CRYPTOFUZZ_TREZOR_FIRMWARE)
#include <modules/trezor/module.h>
#endif

#if defined(CRYPTOFUZZ_ELLIPTIC)
#include <modules/elliptic/module.h>
#endif

#if defined(CRYPTOFUZZ_DECRED)
#include <modules/decred/module.h>
#endif

#if defined(CRYPTOFUZZ_BEARSSL)
#include <modules/bearssl/module.h>
#endif

#if defined(CRYPTOFUZZ_MICRO_ECC)
#include <modules/micro-ecc/module.h>
#endif

#if defined(CRYPTOFUZZ_CIFRA)
#include <modules/cifra/module.h>
#endif

#if defined(CRYPTOFUZZ_RELIC)
#include <modules/relic/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBECC)
#include <modules/libecc/module.h>
#endif

#if defined(CRYPTOFUZZ_CHIA_BLS)
#include <modules/chia_bls/module.h>
#endif

#if defined(CRYPTOFUZZ_K256)
#include <modules/k256/module.h>
#endif

#if defined(CRYPTOFUZZ_SCHNORRKEL)
#include <modules/schnorrkel/module.h>
#endif

#if defined(CRYPTOFUZZ_NOBLE_SECP256K1)
#include <modules/noble-secp256k1/module.h>
#endif

#if defined(CRYPTOFUZZ_NOBLE_CURVES)
#include <modules/noble-curves/module.h>
#endif

#if defined(CRYPTOFUZZ_BLST)
#include <modules/blst/module.h>
#endif

#if defined(CRYPTOFUZZ_MCL)
#include <modules/mcl/module.h>
#endif

#if defined(CRYPTOFUZZ_PY_ECC)
#include <modules/py_ecc/module.h>
#endif

#if defined(CRYPTOFUZZ_KILIC_BLS12_381)
#include <modules/kilic-bls12-381/module.h>
#endif

#if defined(CRYPTOFUZZ_NOBLE_ED25519)
#include <modules/noble-ed25519/module.h>
#endif

#if defined(CRYPTOFUZZ_NOBLE_BLS12_381)
#include <modules/noble-bls12-381/module.h>
#endif

#if defined(CRYPTOFUZZ_SCHNORR_FUN)
#include <modules/schnorr_fun/module.h>
#endif

#if defined(CRYPTOFUZZ_QUICKJS)
#include <modules/quickjs/module.h>
#endif

#if defined(CRYPTOFUZZ_UINT128_T)
#include <modules/uint128_t/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBFF)
#include <modules/libff/module.h>
#endif

#if defined(CRYPTOFUZZ_GNARK_BN254)
#include <modules/gnark-bn254/module.h>
#endif

#if defined(CRYPTOFUZZ_GOOGLE_BN256)
#include <modules/google-bn256/module.h>
#endif

#if defined(CRYPTOFUZZ_CLOUDFLARE_BN256)
#include <modules/cloudflare-bn256/module.h>
#endif

#if defined(CRYPTOFUZZ_NOBLE_HASHES)
#include <modules/noble-hashes/module.h>
#endif

#if defined(CRYPTOFUZZ_SKALE_SOLIDITY)
#include <modules/skalesolidity/module.h>
#endif

#if defined(CRYPTOFUZZ_GOOGLE_INTEGERS)
#include <modules/google-integers/module.h>
#endif

#if defined(CRYPTOFUZZ_NIMCRYPTO)
#include <modules/nimcrypto/module.h>
#endif

#if defined(CRYPTOFUZZ_RUSTCRYPTO)
#include <modules/rustcrypto/module.h>
#endif

#if defined(CRYPTOFUZZ_NUM_BIGINT)
#include <modules/num-bigint/module.h>
#endif

#if defined(CRYPTOFUZZ_INTX)
#include <modules/intx/module.h>
#endif

#if defined(CRYPTOFUZZ_DECRED_UINT256)
#include <modules/decred-uint256/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBDIVIDE)
#include <modules/libdivide/module.h>
#endif

#if defined(CRYPTOFUZZ_RUST_UINT)
#include <modules/rust-uint/module.h>
#endif

#if defined(CRYPTOFUZZ_BC)
#include <modules/bc/module.h>
#endif

#if defined(CRYPTOFUZZ_JAVA)
#include <modules/java/module.h>
#endif

#if defined(CRYPTOFUZZ_SOLIDITY_MATH)
#include <modules/soliditymath/module.h>
#endif

#if defined(CRYPTOFUZZ_V8)
#include <modules/v8/module.h>
#endif

#if defined(CRYPTOFUZZ_V8_EMBEDDED)
#include <modules/v8-embedded/module.h>
#endif

#if defined(CRYPTOFUZZ_CIRCL)
#include <modules/circl/module.h>
#endif

#if defined(CRYPTOFUZZ_SPL_MATH)
#include <modules/spl_math/module.h>
#endif

#if defined(CRYPTOFUZZ_ZIG)
#include <modules/zig/module.h>
#endif

#if defined(CRYPTOFUZZ_PRYSMATICLABS_HASHTREE)
#include <modules/prysmaticlabs-hashtree/module.h>
#endif

#if defined(CRYPTOFUZZ_STARKWARE)
#include <modules/starkware/module.h>
#endif

#if defined(CRYPTOFUZZ_PORNIN_BINGCD)
#include <modules/pornin-bingcd/module.h>
#endif

#if defined(CRYPTOFUZZ_STINT)
#include <modules/stint/module.h>
#endif

#if defined(CRYPTOFUZZ_KRYPTOLOGY)
#include <modules/kryptology/module.h>
#endif

#if defined(CRYPTOFUZZ_NIM_BIGINTS)
#include <modules/nim-bigints/module.h>
#endif

#if defined(CRYPTOFUZZ_HOLIMAN_UINT256)
#include <modules/holiman-uint256/module.h>
#endif

#if defined(CRYPTOFUZZ_CPU)
#include <modules/cpu/module.h>
#endif

#if defined(CRYPTOFUZZ_GETH)
#include <modules/geth/module.h>
#endif

#if defined(CRYPTOFUZZ_JSBN)
#include <modules/jsbn/module.h>
#endif

#if defined(CRYPTOFUZZ_WIDE_INTEGER)
#include <modules/wide-integer/module.h>
#endif

#if defined(CRYPTOFUZZ_TINY_KECCAK)
#include <modules/tiny-keccak/module.h>
#endif

#if defined(CRYPTOFUZZ_ARKWORKS_ALGEBRA)
#include <modules/arkworks-algebra/module.h>
#endif

#if defined(CRYPTOFUZZ_FF)
#include <modules/ff/module.h>
#endif

#if defined(CRYPTOFUZZ_ALEO)
#include <modules/aleo/module.h>
#endif

#if defined(CRYPTOFUZZ_SHAMATAR)
#include <modules/shamatar/module.h>
#endif

#if defined(CRYPTOFUZZ_MICROSOFT_CALCULATOR)
#include <modules/microsoft-calculator/module.h>
#endif

#if defined(CRYPTOFUZZ_POLYGON_ZKEVM_PROVER)
#include <modules/polygon-zkevm-prover/module.h>
#endif

#if defined(CRYPTOFUZZ_GOLDILOCKS)
#include <modules/goldilocks/module.h>
#endif

#if defined(CRYPTOFUZZ_D)
#include <modules/d/module.h>
#endif

#if defined(CRYPTOFUZZ_PAIRING_CE)
#include <modules/pairing_ce/module.h>
#endif

#if defined(CRYPTOFUZZ_PASTA_CURVES)
#include <modules/pasta_curves/module.h>
#endif

#if defined(CRYPTOFUZZ_BOUNCYCASTLE)
#include <modules/bouncycastle/module.h>
#endif

#if defined(CRYPTOFUZZ_FAHEEL_BIGINT)
#include <modules/faheel-bigint/module.h>
#endif

#if defined(CRYPTOFUZZ_SUBSTRATE_BN)
#include <modules/substrate-bn/module.h>
#endif

#if defined(CRYPTOFUZZ_AURORA_ENGINE_MODEXP)
#include <modules/aurora-engine-modexp/module.h>
#endif

#if defined(CRYPTOFUZZ_CONSTANTINE)
#include <modules/constantine/module.h>
#endif

std::shared_ptr<cryptofuzz::Driver> driver = nullptr;

const cryptofuzz::Options *cryptofuzz_options = nullptr;

static void setOptions(int argc, char **argv) {
  std::vector<std::string> extraArguments;

  const std::string cmdline(
#include "extra_options.h"
  );
  boost::split(extraArguments, cmdline, boost::is_any_of(" "));

  const cryptofuzz::Options options(argc, argv, extraArguments);

  driver = std::make_shared<cryptofuzz::Driver>(options);
  cryptofuzz_options = driver->GetOptionsPtr();
}

static void addNumbers(void) {
  std::set<std::string> curveNumbers;

  for (size_t i = 0; i < (sizeof(ECC_CurveLUT) / sizeof(ECC_CurveLUT[0])); i++) {
    if (!cryptofuzz_options->curves.Empty()) {
      if (!cryptofuzz_options->curves.Have(ECC_CurveLUT[i].id)) {
        continue;
      }
    }
    if (ECC_CurveLUT[i].prime)
      curveNumbers.insert(*ECC_CurveLUT[i].prime);
    if (ECC_CurveLUT[i].a)
      curveNumbers.insert(*ECC_CurveLUT[i].a);
    if (ECC_CurveLUT[i].b)
      curveNumbers.insert(*ECC_CurveLUT[i].b);
    if (ECC_CurveLUT[i].x)
      curveNumbers.insert(*ECC_CurveLUT[i].x);
    if (ECC_CurveLUT[i].y)
      curveNumbers.insert(*ECC_CurveLUT[i].y);
    if (ECC_CurveLUT[i].order_min_1)
      curveNumbers.insert(*ECC_CurveLUT[i].order_min_1);
    if (ECC_CurveLUT[i].order)
      curveNumbers.insert(*ECC_CurveLUT[i].order);
    if (ECC_CurveLUT[i].cube_root_of_unity)
      curveNumbers.insert(*ECC_CurveLUT[i].cube_root_of_unity);
  }

  for (const auto &s : curveNumbers) {
    cryptofuzz::numbers.push_back(s);
  }
}

static void addDHParameters(void) {
#if 0
    Pool_DSA_PQG.Set(
            {.p = "1",
            .q = "2",
            .g = "3"});
#endif
  Pool_DSA_PQG.Set({.p = "150231251465501053065289730830479539031267100291054217656119618775188714462742252299995155757488154161365770046117427638242442140226792437461696203428042747814919633220489019161055283800701437723694062141157721435870605677289344980419875189236552985653350450140879697446183075783979747578514684880689288047799", .q = "1294481460557625951125096174768278956450379329019", .g = "123176323926370145306905001771640082099315258804911565991781248774641279332286091530406470110108628420952674474326303976152638457646984169382680970876359186878615754700522570368203249170942652654272930135088255007459054551060675803532305465059607033300717516344741377807058295415130769662943475898885953255340"});
  Pool_DSA_PQG.Set({.p = "106509719202367738942907301715621764539176496646576730633405674043673327856034496732123285709035111374434625191651676418221653833534278937120432644397709949603105722781668399360019469472968954460534436252768055503483520304713097271043340825087067201677304620852378413654560436979990703753937487367926506348269", .q = "1118288236462792761843833248187413414208173350127", .g = "72435671226965183258018862642795284302154495588562538482929411018310293659579761499337602974793436767341017333127333555852102593771624671345177391442816067820254123593555250556535136260966363205479876316378634773122750273117965996152020834617159357433557924693138598393331986343698108999770366446752278926383"});
  Pool_DSA_PQG.Set({.p = "138004309818347094291132867053619499223956524961247192036762792751710974956820647583519309378416103935248269857717426029960774699149947213109440086871278734506662709841063082677937025903550210186986005638869595390211739861476658649538254442080037424128091536935132784096865076724077340725421734957662003955733", .q = "1182250927352833565111471235946595886633807053753", .g = "50981117407618898907676270875500924244946234557748656321451486290931484477672699528123700670310821778249759666738775273571334004072876741139654244496478237072456811279416350268794526824840182161332334555442145925212778889513472053306551473115435240639581353186943034554008455203164569371804149410594860147535"});
  Pool_DSA_PQG.Set({.p = "109946688229802800321045008502525855019018343635199811459637834412277718704275426696546931048200193867073853699694661301100987130977969037055869145785556128499893546459160327648034486774397840709962126663410720743324891206859744100608443126416778329748285936795477961285242132107013514469104031276590639145529", .q = "1097017798574652758688027153013343959247758036379", .g = "90853802403425362444834708006843703424758064889418913931212173026894777531419682953836039048180446572898657640543499059154888760571238291120015914403667178235563530884249409802138323217540531374295893371508604222324367014390024227163670654837119886355437741902577247163114711575830541075372536310906966739501"});
  Pool_DSA_PQG.Set({.p = "124209509072024958275166637845461843473168024436234587545357618943183152164739154230608140142817940602971118647920318657635219309456829210930848667888289103140463427808821865872498412912378809701133733363511757593195923487399372820407763609428150569455525396831100333605708326427075191467209382555105711963299", .q = "1156817815916336365281547542987775955291851935871", .g = "43439798865518148079170184647168882910799658250950112656992473391369195267567114318131636772383729066568167011041675228166469202932063704475384188208092171311430491566372323746821632363680716780126497417783638448391870877258448510742322506027897962466869528155419123258766935809190262469523993336422700725318"});
  Pool_DSA_PQG.Set({.p = "126331233628980840165184565942245385096513091144740711497864308287507943295406615416955002027235910171772121228535928494648768972393171048104219309808822924104348781037865255204637472392028547550836119757782109037132097469719594436136398329796267499263632942017207769135383159876183961765810415630873971115233", .q = "1203327632657956941015344776779451299508739578129", .g = "97452668285819865055659311415043913678401634848512133077315151404416203000244082651639944515890002752552299640827969897097594332745578954618134141809516813588353374434067098749478884011839257971032639225273289142277635977389715811787650901754149760120488823365859750048315630946360036462942314143557183124982"});
  Pool_DSA_PQG.Set({.p = "139250883301823483908883928083839064003745916441650255007772870154941172395087178752876101091005767662213271334443940570474680019084601422955747232370282598419697274421195681275556947624938410397537906338955131228297990585299263933664717169274974367925488384465967202651868677400555284280096337099191959071787", .q = "1325100766121833447183259101226453517842221286507", .g = "58646846595225538779696035374886298089421912241195003782810584053398797793591727045576166116215795078184706343867027617123952824238923027973165246674943121228498251801328224621075003565013070726915672626019475087221545030092892828436386114258346864840836351933570664379118571919793182205573116727058719375661"});
  Pool_DSA_PQG.Set({.p = "144701324401598336550884152343368172277609864124511490596617105828057159991373774941016821760687266369338519486490004072145971111466542758853015017509128499051606282143736677640332301617479652949405201725583682831439755381248675286661684002938741047451713467379330091941738855468955951557713143970579349864457", .q = "1439434426242082501974975807657668984105633014787", .g = "113600692930456433400748782777975166451962648651602592974909826945350314246206069661699011991844511030599644698164383474978927329888470480371116765437437655015511396253863826561268272020107619231686538845226921909438712847791416806266736495398219697258274310643814113505622803337678429494610934192497815903365"});
  Pool_DSA_PQG.Set({.p = "135341197697226724892903083596165054694790625986023071616356886245846043038405567011291087532200081879605164155216745486229649520257309932549000914144450824446643782112243492160717188886767122817207763789165868343163481202614492491575215866530116235028761963662218876392260598504340050277595263388586602546747", .q = "1169054189952016903829256751948870806314450386513", .g = "30572099485446824777611559392355316740353774202040161762373834574766256266332511696873593659519522274210266790041815776129917472702566335252550578138435000898308011273223392155586550839178056561166656269827651537030610266906854193629082719056305327623289093720593961976531902349641250618073959820008293423729"});
  Pool_DSA_PQG.Set({.p = "127351864753493277268739385478165721559729466727175877720818107624823856755558221219347691856288532870918552584721097877527832510124917679520208660409823797024889655990544958921667883652156168599993183854739635683709671125815430824244885672208722762544165061369990843770047348269058869140280321943549216357991", .q = "1156961398255600519725597002666342085415806424529", .g = "106257931303095074533103986366433211062343163442228036675016417802383259373755687507866521855899403669620543075167608985212468902139533924762542871308909385486893394211775148650040778024210387468981928471252790681933685353324695021902141191542978389064246508147865484230435458524929665990269930783999629249441"});
  Pool_DSA_PQG.Set({.p = "131039458455155250090174200145321228172977476476885551980435528702610913389079590939737522784805216856991866456707299626829238352232572218199747475524103264307799994317996352504194705753236329996801042545987006513074758983109144174154780904219653269610458162384667077307435251147347179290650561637905921672683", .q = "1170715624353437458381293805110022939445185488259", .g = "126742934784779681813194779376736668434375433467445616299439666618831396063812870504003367398372147678231830460960085383230032539099660760734275638091575317361409298198873148524067936524126541952740212599133188511748079844136886266936035053990867071777029697349092865480561238401432352105670316197944641993372"});
  Pool_DSA_PQG.Set({.p = "113501887847313654923482478343337570064130386651110593957519724786021990228602191373446721521338119059972385547173111082437621139282278796862795599570090388898648541512966469137375762705045818898892127936907280478802811793893711980582500291057764626146803929832480402191770765381629264026303953585630138960173", .q = "1210118463151965859368281774842614821435692691527", .g = "7368690161464245595369357421049794571202878323927473530430901957824912081535284584536397796919942606122666864397318876947854645101607578840959967924770322750454906727500380020624862129397409509250521115423635650551518713996861995296315890736439522758915319733553857973686465993050136329199277364851750662840"});
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  setOptions(*argc, *argv);
  addNumbers();
  addDHParameters();

#if !defined(CRYPTOFUZZ_NO_OPENSSL)
  driver->LoadModule(std::make_shared<cryptofuzz::module::OpenSSL>());
#endif

#if defined(CRYPTOFUZZ_BITCOIN)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Bitcoin>());
#endif

#if defined(CRYPTOFUZZ_REFERENCE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Reference>());
#endif

#if defined(CRYPTOFUZZ_CPPCRYPTO)
  driver->LoadModule(std::make_shared<cryptofuzz::module::CPPCrypto>());
#endif

#if defined(CRYPTOFUZZ_MBEDTLS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::mbedTLS>());
#endif

#if defined(CRYPTOFUZZ_BOOST)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Boost>());
#endif

#if defined(CRYPTOFUZZ_MONERO)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Monero>());
#endif

#if defined(CRYPTOFUZZ_VERACRYPT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Veracrypt>());
#endif

#if defined(CRYPTOFUZZ_LIBSODIUM)
  driver->LoadModule(std::make_shared<cryptofuzz::module::libsodium>());
#endif

#if defined(CRYPTOFUZZ_LIBTOMCRYPT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::libtomcrypt>());
#endif

#if defined(CRYPTOFUZZ_CRYPTOPP)
  driver->LoadModule(std::make_shared<cryptofuzz::module::CryptoPP>());
#endif

#if defined(CRYPTOFUZZ_LIBGCRYPT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::libgcrypt>());
#endif

#if defined(CRYPTOFUZZ_EVERCRYPT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::EverCrypt>());
#endif

#if defined(CRYPTOFUZZ_GOLANG)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Golang>());
#endif

#if defined(CRYPTOFUZZ_RING)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Ring>());
#endif

#if defined(CRYPTOFUZZ_NSS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::NSS>());
#endif

#if defined(CRYPTOFUZZ_BOTAN)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Botan>());
#endif

#if defined(CRYPTOFUZZ_NETTLE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Nettle>());
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::wolfCrypt>());
#endif

#if defined(CRYPTOFUZZ_LIBGMP)
  driver->LoadModule(std::make_shared<cryptofuzz::module::libgmp>());
#endif

#if defined(CRYPTOFUZZ_BN_JS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::bn_js>());
#endif

#if defined(CRYPTOFUZZ_CRYPTO_JS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::crypto_js>());
#endif

#if defined(CRYPTOFUZZ_BIGNUMBER_JS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::bignumber_js>());
#endif

#if defined(CRYPTOFUZZ_MPDECIMAL)
  driver->LoadModule(std::make_shared<cryptofuzz::module::mpdecimal>());
#endif

#if defined(CRYPTOFUZZ_LINUX)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Linux>());
#endif

#if defined(CRYPTOFUZZ_SYMCRYPT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::SymCrypt>());
#endif

#if defined(CRYPTOFUZZ_LIBTOMMATH)
  driver->LoadModule(std::make_shared<cryptofuzz::module::libtommath>());
#endif

#if defined(CRYPTOFUZZ_SJCL)
  driver->LoadModule(std::make_shared<cryptofuzz::module::sjcl>());
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
  driver->LoadModule(std::make_shared<cryptofuzz::module::wolfCrypt_OpenSSL>());
#endif

#if defined(CRYPTOFUZZ_MONOCYPHER)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Monocypher>());
#endif

#if defined(CRYPTOFUZZ_SECP256K1)
  driver->LoadModule(std::make_shared<cryptofuzz::module::secp256k1>());
#endif

#if defined(CRYPTOFUZZ_RUST_LIBSECP256K1)
  driver->LoadModule(std::make_shared<cryptofuzz::module::rust_libsecp256k1>());
#endif

#if defined(CRYPTOFUZZ_TREZOR_FIRMWARE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::trezor_firmware>());
#endif

#if defined(CRYPTOFUZZ_ELLIPTIC)
  driver->LoadModule(std::make_shared<cryptofuzz::module::elliptic>());
#endif

#if defined(CRYPTOFUZZ_DECRED)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Decred>());
#endif

#if defined(CRYPTOFUZZ_BEARSSL)
  driver->LoadModule(std::make_shared<cryptofuzz::module::BearSSL>());
#endif

#if defined(CRYPTOFUZZ_MICRO_ECC)
  driver->LoadModule(std::make_shared<cryptofuzz::module::micro_ecc>());
#endif

#if defined(CRYPTOFUZZ_CIFRA)
  driver->LoadModule(std::make_shared<cryptofuzz::module::cifra>());
#endif

#if defined(CRYPTOFUZZ_RELIC)
  driver->LoadModule(std::make_shared<cryptofuzz::module::relic>());
#endif

#if defined(CRYPTOFUZZ_LIBECC)
  driver->LoadModule(std::make_shared<cryptofuzz::module::libecc>());
#endif

#if defined(CRYPTOFUZZ_CHIA_BLS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::chia_bls>());
#endif

#if defined(CRYPTOFUZZ_K256)
  driver->LoadModule(std::make_shared<cryptofuzz::module::k256>());
#endif

#if defined(CRYPTOFUZZ_SCHNORRKEL)
  driver->LoadModule(std::make_shared<cryptofuzz::module::schnorrkel>());
#endif

#if defined(CRYPTOFUZZ_NOBLE_SECP256K1)
  driver->LoadModule(std::make_shared<cryptofuzz::module::noble_secp256k1>());
#endif

#if defined(CRYPTOFUZZ_NOBLE_CURVES)
  driver->LoadModule(std::make_shared<cryptofuzz::module::noble_curves>());
#endif

#if defined(CRYPTOFUZZ_BLST)
  driver->LoadModule(std::make_shared<cryptofuzz::module::blst>());
#endif

#if defined(CRYPTOFUZZ_MCL)
  driver->LoadModule(std::make_shared<cryptofuzz::module::mcl>());
#endif

#if defined(CRYPTOFUZZ_PY_ECC)
  driver->LoadModule(std::make_shared<cryptofuzz::module::py_ecc>());
#endif

#if defined(CRYPTOFUZZ_KILIC_BLS12_381)
  driver->LoadModule(std::make_shared<cryptofuzz::module::kilic_bls12_381>());
#endif

#if defined(CRYPTOFUZZ_NOBLE_ED25519)
  driver->LoadModule(std::make_shared<cryptofuzz::module::noble_ed25519>());
#endif

#if defined(CRYPTOFUZZ_NOBLE_BLS12_381)
  driver->LoadModule(std::make_shared<cryptofuzz::module::noble_bls12_381>());
#endif

#if defined(CRYPTOFUZZ_SCHNORR_FUN)
  driver->LoadModule(std::make_shared<cryptofuzz::module::schnorr_fun>());
#endif

#if defined(CRYPTOFUZZ_QUICKJS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::quickjs>());
#endif

#if defined(CRYPTOFUZZ_UINT128_T)
  driver->LoadModule(std::make_shared<cryptofuzz::module::uint128_t>());
#endif

#if defined(CRYPTOFUZZ_LIBFF)
  driver->LoadModule(std::make_shared<cryptofuzz::module::_libff>());
#endif

#if defined(CRYPTOFUZZ_GNARK_BN254)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Gnark_bn254>());
#endif

#if defined(CRYPTOFUZZ_GOOGLE_BN256)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Google_bn256>());
#endif

#if defined(CRYPTOFUZZ_CLOUDFLARE_BN256)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Cloudflare_bn256>());
#endif

#if defined(CRYPTOFUZZ_NOBLE_HASHES)
  driver->LoadModule(std::make_shared<cryptofuzz::module::noble_hashes>());
#endif

#if defined(CRYPTOFUZZ_SKALE_SOLIDITY)
  driver->LoadModule(std::make_shared<cryptofuzz::module::SkaleSolidity>());
#endif

#if defined(CRYPTOFUZZ_GOOGLE_INTEGERS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Google_Integers>());
#endif

#if defined(CRYPTOFUZZ_NIMCRYPTO)
  driver->LoadModule(std::make_shared<cryptofuzz::module::nimcrypto>());
#endif

#if defined(CRYPTOFUZZ_RUSTCRYPTO)
  driver->LoadModule(std::make_shared<cryptofuzz::module::rustcrypto>());
#endif

#if defined(CRYPTOFUZZ_NUM_BIGINT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::num_bigint>());
#endif

#if defined(CRYPTOFUZZ_INTX)
  driver->LoadModule(std::make_shared<cryptofuzz::module::intx>());
#endif

#if defined(CRYPTOFUZZ_DECRED_UINT256)
  driver->LoadModule(std::make_shared<cryptofuzz::module::decred_uint256>());
#endif

#if defined(CRYPTOFUZZ_LIBDIVIDE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::libdivide>());
#endif

#if defined(CRYPTOFUZZ_RUST_UINT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::rust_uint>());
#endif

#if defined(CRYPTOFUZZ_BC)
  driver->LoadModule(std::make_shared<cryptofuzz::module::bc>());
#endif

#if defined(CRYPTOFUZZ_JAVA)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Java>());
#endif

#if defined(CRYPTOFUZZ_SOLIDITY_MATH)
  driver->LoadModule(std::make_shared<cryptofuzz::module::SolidityMath>());
#endif

#if defined(CRYPTOFUZZ_V8)
  driver->LoadModule(std::make_shared<cryptofuzz::module::V8>());
#endif

#if defined(CRYPTOFUZZ_CIRCL)
  driver->LoadModule(std::make_shared<cryptofuzz::module::circl>());
#endif

#if defined(CRYPTOFUZZ_SPL_MATH)
  driver->LoadModule(std::make_shared<cryptofuzz::module::spl_math>());
#endif

#if defined(CRYPTOFUZZ_ZIG)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Zig>());
#endif

#if defined(CRYPTOFUZZ_PRYSMATICLABS_HASHTREE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::prysmaticlabs_hashtree>());
#endif

#if defined(CRYPTOFUZZ_STARKWARE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Starkware>());
#endif

#if defined(CRYPTOFUZZ_PORNIN_BINGCD)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Pornin_BinGCD>());
#endif

#if defined(CRYPTOFUZZ_STINT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::stint>());
#endif

#if defined(CRYPTOFUZZ_KRYPTOLOGY)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Kryptology>());
#endif

#if defined(CRYPTOFUZZ_NIM_BIGINTS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::nim_bigints>());
#endif

#if defined(CRYPTOFUZZ_HOLIMAN_UINT256)
  driver->LoadModule(std::make_shared<cryptofuzz::module::holiman_uint256>());
#endif

#if defined(CRYPTOFUZZ_CPU)
  driver->LoadModule(std::make_shared<cryptofuzz::module::CPU>());
#endif

#if defined(CRYPTOFUZZ_GETH)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Geth>());
#endif

#if defined(CRYPTOFUZZ_JSBN)
  driver->LoadModule(std::make_shared<cryptofuzz::module::jsbn>());
#endif

#if defined(CRYPTOFUZZ_WIDE_INTEGER)
  driver->LoadModule(std::make_shared<cryptofuzz::module::wide_integer>());
#endif

#if defined(CRYPTOFUZZ_TINY_KECCAK)
  driver->LoadModule(std::make_shared<cryptofuzz::module::tiny_keccak>());
#endif

#if defined(CRYPTOFUZZ_ARKWORKS_ALGEBRA)
  driver->LoadModule(std::make_shared<cryptofuzz::module::arkworks_algebra>());
#endif

#if defined(CRYPTOFUZZ_FF)
  driver->LoadModule(std::make_shared<cryptofuzz::module::ff>());
#endif

#if defined(CRYPTOFUZZ_ALEO)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Aleo>());
#endif

#if defined(CRYPTOFUZZ_SHAMATAR)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Shamatar>());
#endif

#if defined(CRYPTOFUZZ_MICROSOFT_CALCULATOR)
  driver->LoadModule(std::make_shared<cryptofuzz::module::MicrosoftCalculator>());
#endif

#if defined(CRYPTOFUZZ_POLYGON_ZKEVM_PROVER)
  driver->LoadModule(std::make_shared<cryptofuzz::module::polygon_zkevm_prover>());
#endif

#if defined(CRYPTOFUZZ_GOLDILOCKS)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Goldilocks>());
#endif

#if defined(CRYPTOFUZZ_D)
  driver->LoadModule(std::make_shared<cryptofuzz::module::D>());
#endif

#if defined(CRYPTOFUZZ_PAIRING_CE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::pairing_ce>());
#endif

#if defined(CRYPTOFUZZ_PASTA_CURVES)
  driver->LoadModule(std::make_shared<cryptofuzz::module::pasta_curves>());
#endif

#if defined(CRYPTOFUZZ_BOUNCYCASTLE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::BouncyCastle>());
#endif

#if defined(CRYPTOFUZZ_FAHEEL_BIGINT)
  driver->LoadModule(std::make_shared<cryptofuzz::module::faheel_BigInt>());
#endif

#if defined(CRYPTOFUZZ_SUBSTRATE_BN)
  driver->LoadModule(std::make_shared<cryptofuzz::module::substrate_bn>());
#endif

#if defined(CRYPTOFUZZ_AURORA_ENGINE_MODEXP)
  driver->LoadModule(std::make_shared<cryptofuzz::module::aurora_engine_modexp>());
#endif

#if defined(CRYPTOFUZZ_V8_EMBEDDED)
  driver->LoadModule(std::make_shared<cryptofuzz::module::V8_embedded>());
#endif

#if defined(CRYPTOFUZZ_CONSTANTINE)
  driver->LoadModule(std::make_shared<cryptofuzz::module::Constantine>());
#endif

  /* TODO check if options.forceModule (if set) refers to a module that is
   * actually loaded, warn otherwise.
   */
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  driver->Run(data, size);

  return 0;
}
