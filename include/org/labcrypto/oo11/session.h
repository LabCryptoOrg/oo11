/*  The MIT License (MIT)
 *
 *  Copyright (c) 2015 LabCrypto Org.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#ifndef _ORG_LABCRYPTO_OO11__SESSION_H_
#define _ORG_LABCRYPTO_OO11__SESSION_H_

#ifdef _MSC_VER
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

#include <stdio.h>

#include <vector>
#include <stdexcept>

#include <org/labcrypto/oo11/pkcs11/cryptoki.h>


namespace org {
namespace labcrypto {
namespace oo11 {
  enum SessionType {
    SESSION_TYPE__ANONYMOUS,
    SESSION_TYPE__USER,
    SESSION_TYPE__SO
  };
  class Slot;
  class Object;
  class RSAPrivateKey;
  class RSAPublicKey;
  class Session {
    friend class Slot;
    friend class Object;
  public:
    Session() 
      : closed_(false) {
    }
  public:
    void
    Logout();
  public:
    inline 
    Slot* 
    GetSlot() {
      return slot_;
    }
  public:
    std::vector<Object*>
    GetEverything();
    std::vector<RSAPublicKey*> 
    EnumerateRSAPublicKeys();
    std::vector<RSAPrivateKey*> 
    EnumerateRSAPrivateKeys();
    RSAPublicKey*
    GetRSAPublicKey (
      std::string label
    );
    RSAPrivateKey*
    GetRSAPrivateKey (
      std::string label
    );
  private:
    bool closed_;
    Slot *slot_;
    SessionType type_;
    CK_SESSION_HANDLE handle_;
  };
} // END NAMESPACE oo11
} // END NAMESPACE labcrypto
} // END NAMESPACE org

#endif