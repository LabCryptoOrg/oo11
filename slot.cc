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

#include <org/labcrypto/oo11/slot.h>
#include <org/labcrypto/oo11/session.h>


namespace org {
namespace labcrypto {
namespace oo11 {
  Session*
  Slot::MakeAnonymousSession () {
    CK_OBJECT_HANDLE sessionHandle;
    CK_RV result = 
      C_OpenSession (
        slotId_, 
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        NULL,
        NULL,
        &sessionHandle
      );
    if (result) {
      char errorMessage[256];
      sprintf(errorMessage, "Error in making session, error code: 0x%lx\n", result);
      throw std::runtime_error(errorMessage);
    }
    Session *session = new Session;
    session->handle_ = sessionHandle;
    session->slot_ = this;
    session->type_ = SESSION_TYPE__ANONYMOUS;
    return session;
  }
  Session*
  Slot::MakeUserSession (
    std::string userPassword
  ) {
    CK_OBJECT_HANDLE sessionHandle;
    CK_RV result = 
      C_OpenSession (
        slotId_, 
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        NULL,
        NULL,
        &sessionHandle
      );
    if (result) {
      char errorMessage[256];
      sprintf(errorMessage, "Error in making user session, error code: 0x%lx\n", result);
      throw std::runtime_error(errorMessage);
    }
    result = 
      C_Login (
        sessionHandle, 
        CKU_USER,
        (CK_CHAR_PTR)userPassword.c_str(),
        userPassword.size()
      );
    if (result) {
      char errorMessage[256];
      sprintf(errorMessage, "Error in logging in as user, error code: 0x%lx\n", result);
      C_CloseSession(sessionHandle);
      throw std::runtime_error(errorMessage);
    }
    Session *session = new Session;
    session->handle_ = sessionHandle;
    session->slot_ = this;
    session->type_ = SESSION_TYPE__USER;
    return session;
  }
  Session*
  Slot::MakeSOSession (
    std::string soPassword
  ) {
    CK_OBJECT_HANDLE sessionHandle;
    CK_RV result = 
      C_OpenSession (
        slotId_, 
        CKF_RW_SESSION | CKF_SERIAL_SESSION,
        NULL,
        NULL,
        &sessionHandle
      );
    if (result) {
      char errorMessage[256];
      sprintf(errorMessage, "Error in making SO session, error code: 0x%lx\n", result);
      throw std::runtime_error(errorMessage);
    }
    result = 
      C_Login (
        sessionHandle, 
        CKU_SO,
        (CK_CHAR_PTR)soPassword.c_str(),
        soPassword.size()
      );
    if (result) {
      char errorMessage[256];
      sprintf(errorMessage, "Error in logging in as SO, error code: 0x%lx\n", result);
      C_CloseSession(sessionHandle);
      throw std::runtime_error(errorMessage);
    }
    Session *session = new Session;
    session->handle_ = sessionHandle;
    session->slot_ = this;
    session->type_ = SESSION_TYPE__USER;
    return session;
  }
} // END NAMESPACE oo11
} // END NAMESPACE labcrypto
} // END NAMESPACE org