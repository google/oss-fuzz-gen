#include "rutil/DataStream.hxx"
#include "rutil/Logger.hxx"

#include "resip/stack/Auth.hxx"
#include "resip/stack/CSeqCategory.hxx"
#include "resip/stack/CallId.hxx"
#include "resip/stack/CpimContents.hxx"
#include "resip/stack/DateCategory.hxx"
#include "resip/stack/DialogInfoContents.hxx"
#include "resip/stack/DtmfPayloadContents.hxx"
#include "resip/stack/ExpiresCategory.hxx"
#include "resip/stack/GenericPidfContents.hxx"
#include "resip/stack/GenericUri.hxx"
#include "resip/stack/IntegerCategory.hxx"
#include "resip/stack/InvalidContents.hxx"
#include "resip/stack/MessageWaitingContents.hxx"
#include "resip/stack/Mime.hxx"
#include "resip/stack/MultipartMixedContents.hxx"
#include "resip/stack/NameAddr.hxx"
#include "resip/stack/OctetContents.hxx"
#include "resip/stack/Pidf.hxx"
#include "resip/stack/Pkcs7Contents.hxx"
#include "resip/stack/Pkcs8Contents.hxx"
#include "resip/stack/PlainContents.hxx"
#include "resip/stack/PrivacyCategory.hxx"
#include "resip/stack/RAckCategory.hxx"
#include "resip/stack/RequestLine.hxx"
#include "resip/stack/Rlmi.hxx"
#include "resip/stack/SdpContents.hxx"
#include "resip/stack/SipFrag.hxx"
#include "resip/stack/StatusLine.hxx"
#include "resip/stack/StringCategory.hxx"
#include "resip/stack/Token.hxx"
#include "resip/stack/TokenOrQuotedStringCategory.hxx"
#include "resip/stack/UInt32Category.hxx"
#include "resip/stack/Uri.hxx"
#include "resip/stack/Via.hxx"
#include "resip/stack/WarningCategory.hxx"
#include "resip/stack/X509Contents.hxx"

#include "TestSupport.hxx"

static void fuzzAuth(const resip::HeaderFieldValue &hfv) {
  resip::Auth payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzCSeqCategory(const resip::HeaderFieldValue &hfv) {
  resip::CSeqCategory payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzCpimContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("message", "cpim");
  resip::CpimContents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzCallId(const resip::HeaderFieldValue &hfv) {
  resip::CallId payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzDtmfPayloadContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "dtmf-relay");
  resip::DtmfPayloadContents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzDateCategory(const resip::HeaderFieldValue &hfv) {
  resip::DateCategory payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzDialogInfoContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "sdp");
  resip::DialogInfoContents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzExpiresCategory(const resip::HeaderFieldValue &hfv) {
  resip::ExpiresCategory payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzGenericPidfContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "pidf+xml");
  resip::GenericPidfContents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzGenericUri(const resip::HeaderFieldValue &hfv) {
  resip::GenericURI payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzIntegerCategory(const resip::HeaderFieldValue &hfv) {
  resip::IntegerCategory payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzInvalidContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("Invalid", "Invalid");
  resip::InvalidContents payload(hfv, type, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzMessageWaitingContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "simple-message-summary");
  resip::MessageWaitingContents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzMime(const resip::HeaderFieldValue &hfv) {
  resip::Mime payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzMultipartMixedContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("multipart", "mixed");
  resip::MultipartMixedContents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzNameAddr(const resip::Data &buffer) {
  try {
    resip::NameAddr illegal(buffer);
  } catch (const resip::ParseException &) {
  }
}

static void fuzzOctetContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "octet-stream");
  resip::OctetContents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzPidf(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "pidf+xml");
  resip::Pidf payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzPkcs7Contents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "pkcs7-mime");
  resip::Pkcs7Contents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzPkcs8Contents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "pkcs8");
  resip::Pkcs8Contents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzPlainContents(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("text", "plain");
  resip::PlainContents payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzPrivacyCategory(const resip::HeaderFieldValue &hfv) {
  resip::PrivacyCategory payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzRAckCategory(const resip::HeaderFieldValue &hfv) {
  resip::RAckCategory payload(hfv, resip::Headers::UNKNOWN);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzRequestLine(const resip::HeaderFieldValue &hfv) {
  resip::RequestLine payload(hfv);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzRlmi(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "rlmi+xml");
  resip::Rlmi payload(hfv, type);
  try {
    payload.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzSdp(const resip::HeaderFieldValue &hfv) {
  static const resip::Mime type("application", "sdp");
  resip::SdpContents sdp(hfv, type);
  try {
    sdp.checkParsed();
  } catch (const resip::ParseException &) {
  }
}

static void fuzzSip(const resip::Data &buffer) {
  try {
    std::unique_ptr<resip::SipMessage> msg(resip::TestSupport::makeMessage(buffer));
  } catch (const resip::ParseException &) {
  }
}

/*

TODO: add fuzzing for those classes

resip/stack/SipFrag.cxx:SipFrag::parse(ParseBuffer& pb)
resip/stack/StatusLine.cxx:StatusLine::parse(ParseBuffer& pb)
resip/stack/StringCategory.cxx:StringCategory::parse(ParseBuffer& pb)
resip/stack/Token.cxx:Token::parse(ParseBuffer& pb)
resip/stack/TokenOrQuotedStringCategory.cxx:TokenOrQuotedStringCategory::parse(ParseBuffer& pb)
resip/stack/UInt32Category.cxx:UInt32Category::parse(ParseBuffer& pb)
resip/stack/Via.cxx:Via::parse(ParseBuffer& pb)
resip/stack/WarningCategory.cxx:WarningCategory::parse(ParseBuffer& pb)
resip/stack/X509Contents.cxx:X509Contents::parse(ParseBuffer& pb)

*/

static void fuzzUri(const resip::HeaderFieldValue &hfv) {
  resip::Uri uri(hfv, resip::Headers::UNKNOWN);
  try {
    uri.embedded();
  } catch (const resip::ParseException &) {
  }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  resip::Log::initialize(resip::Log::Cout, resip::Log::None, *argv[0]);
  return 0;
}

// Entrypoint for Clang's libfuzzer
extern "C" int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {

  const resip::Data buffer(resip::Data::Share, reinterpret_cast<const char *>(data), size);
  const resip::HeaderFieldValue hfv(reinterpret_cast<const char *>(data), size);

  fuzzAuth(hfv);
  fuzzCSeqCategory(hfv);
  fuzzCallId(hfv);
  fuzzCpimContents(hfv);
  fuzzDtmfPayloadContents(hfv);
  fuzzDateCategory(hfv);
  fuzzExpiresCategory(hfv);
  fuzzGenericUri(hfv);
  fuzzIntegerCategory(hfv);
  fuzzInvalidContents(hfv);
  fuzzMessageWaitingContents(hfv);
  fuzzMime(hfv);
  fuzzMultipartMixedContents(hfv);
  fuzzNameAddr(buffer);
  fuzzOctetContents(hfv);

  fuzzPkcs7Contents(hfv);
  fuzzPkcs8Contents(hfv);
  fuzzPlainContents(hfv);
  fuzzPrivacyCategory(hfv);
  fuzzRAckCategory(hfv);
  fuzzRequestLine(hfv);
  fuzzRlmi(hfv);
  fuzzSdp(hfv);
  fuzzSip(buffer);
  fuzzUri(hfv);

  // leaks or hogs memory
  // fuzzDialogInfoContents(hfv);
  // fuzzGenericPidfContents(hfv);
  // fuzzPidf(hfv); return 0;

  return 0;
}

/* ====================================================================
 * The Vovida Software License, Version 1.0
 *
 * Copyright (c) 2000 Vovida Networks, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The names "VOCAL", "Vovida Open Communication Application Library",
 *    and "Vovida Open Communication Application Library (VOCAL)" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact vocal@vovida.org.
 *
 * 4. Products derived from this software may not be called "VOCAL", nor
 *    may "VOCAL" appear in their name, without prior written
 *    permission of Vovida Networks, Inc.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
 * NON-INFRINGEMENT ARE DISCLAIMED.  IN NO EVENT SHALL VOVIDA
 * NETWORKS, INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT DAMAGES
 * IN EXCESS OF $1,000, NOR FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * ====================================================================
 *
 * This software consists of voluntary contributions made by Vovida
 * Networks, Inc. and many individuals on behalf of Vovida Networks,
 * Inc.  For more information on Vovida Networks, Inc., please see
 * <http://www.vovida.org/>.
 *
 */
