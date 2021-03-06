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

#include <org/labcrypto/oo11/session.h>


namespace org {
namespace labcrypto {
namespace oo11 {
  std::vector<Object*>
  GetEverything() {
    // TODO
  }
  std::vector<RSAPublicKey*> 
  EnumerateRSAPublicRSAKeys() {
    // TODO
  }
  std::vector<RSAPrivateKey*> 
  EnumerateRSAPrivateRSAKeys() {
    // TODO
  }
  RSAPublicKey*
  GetRSAPublicKey (
    std::string label
  ) {
    // TODO
  }
  RSAPrivateKey*
  GetRSAPrivateKey (
    std::string label
  ) {
    // TODO
  }
  void
  Session::Logout () {
    CK_RV result = C_Logout(handle_);
    if (result) {
      char errorMessage[256];
      sprintf(errorMessage, "Error in logging out, error code: 0x%lx\n", result);
      throw std::runtime_error(errorMessage);
    }
    closed_ = true;
  }
} // END NAMESPACE oo11
} // END NAMESPACE labcrypto
} // END NAMESPACE org