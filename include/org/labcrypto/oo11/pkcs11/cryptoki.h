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

#ifdef WIN32_
/* cryptoki.h include file for PKCS #11. */
/* $Revision: 1.1.1.1 $ */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or 
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the 
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* This is a sample file containing the top level include directives
 * for building Win32 Cryptoki libraries and applications.
 */

#ifndef ___CRYPTOKI_H_INC___
#define ___CRYPTOKI_H_INC___

#if defined(WIN16) || (defined(_WINDOWS) && !defined(_WIN32))
  #define CK_ENTRY           _export _far _pascal
  #define CK_POINTER         far *
  #pragma pack(1)
#elif defined(VXD)
  #define CK_ENTRY           
  #define CK_POINTER         *
  #pragma pack(push, 1)
#elif defined(WIN32) || defined(_WINDOWS)
  #define CK_ENTRY           __declspec( dllexport )
  #define CK_POINTER         *
  #pragma pack(push, cryptoki, 1)
#else
  #define CK_ENTRY           
  #define CK_POINTER         *
#endif

/* Specifies that the function is a DLL entry point. */
#define CK_IMPORT_SPEC __declspec(dllimport)

/* Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do
 * not define it in applications.
 */
#ifdef CRYPTOKI_EXPORTS
/* Specified that the function is an exported DLL entry point. */
#define CK_EXPORT_SPEC __declspec(dllexport) 
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC 
#endif

/* Ensures the calling convention for Win32 builds */
#define CK_CALL_SPEC __cdecl

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name

/*
#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name
*/

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name

/*
#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name
*/

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)
 
/*
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)
*/

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)

/*
#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (CK_CALL_SPEC CK_PTR name)
*/

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <libpki/drivers/pkcs11/rsa/pkcs11t.h>
#include <libpki/drivers/pkcs11/rsa/pkcs11_func.h>

#if defined(WIN16) || (defined(_WINDOWS) && !defined(_WIN32))
  #pragma pack()
#elif defined(VXD)
  #pragma pack(pop)
#elif defined(WIN32) || defined(_WINDOWS)
  #pragma pack(pop, cryptoki)
#endif


#endif /* ___CRYPTOKI_H_INC___ */

#else
/* cryptoki.h include file for PKCS #11. */
/*
 * Copyright (C) 2009  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC AND NETWORK ASSOCIATES DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* $Revision: 1.3 $ */

/*
 * Portions Copyright RSA Security Inc.
 *
 * License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or 
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the 
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* This is a sample file containing the top level include directives
 * for building Unix Cryptoki libraries and applications.
 */

#ifndef ___CRYPTOKI_H_INC___
#define ___CRYPTOKI_H_INC___

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)

/* NULL is in unistd.h */
#include <unistd.h>
#define NULL_PTR NULL

#undef CK_PKCS11_FUNCTION_INFO

#include "pkcs11.h"

#endif /* ___CRYPTOKI_H_INC___ */

#endif