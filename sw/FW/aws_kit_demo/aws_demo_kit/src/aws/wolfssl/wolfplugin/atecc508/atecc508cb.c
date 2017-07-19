/**
 *
 * \file
 *
 * \brief Interface between CryptoAuthLib and WolfSSL.
 *
 * Copyright (c) 2015 Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 */

#include <wolfssl/internal.h>
#include "atecc508cb.h"
#include "tls/atcatls.h"
#include "tls/atcatls_cfg.h"
#include "atcacert/atcacert_client.h"
#include "cert_def_1_signer.h"
#include "cert_def_2_device.h"

#define M1_ECC

#ifdef M1_RSA
static uint8_t signerCert[593] = { 0x30, 0x82, 0x2, 0x4d, 0x30, 0x82, 0x1, 0xb6, 0x2, 0x9, 0x0, 0xf7, 0xd0, 0x4d, 0xb3, 0x82, 0xf6, 0xa3, 0x27, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xb, 0x5, 0x0, 0x30, 0x6b, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0x8, 0xc, 0xa, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x14, 0x30, 0x12, 0x6, 0x3, 0x55, 0x4, 0x7, 0xc, 0xb, 0x53, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x43, 0x6c, 0x61, 0x72, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0xa, 0x4d, 0x65, 0x64, 0x69, 0x75, 0x6d, 0x20, 0x4f, 0x6e, 0x65, 0x31, 0xd, 0x30, 0xb, 0x6, 0x3, 0x55, 0x4, 0xb, 0xc, 0x4, 0x4d, 0x51, 0x54, 0x54, 0x31, 0xd, 0x30, 0xb, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x4, 0x4d, 0x51, 0x54, 0x54, 0x30, 0x1e, 0x17, 0xd, 0x31, 0x37, 0x30, 0x35, 0x31, 0x30, 0x32, 0x32, 0x31, 0x34, 0x34, 0x39, 0x5a, 0x17, 0xd, 0x31, 0x38, 0x30, 0x35, 0x31, 0x30, 0x32, 0x32, 0x31, 0x34, 0x34, 0x39, 0x5a, 0x30, 0x6b, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0x8, 0xc, 0xa, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x14, 0x30, 0x12, 0x6, 0x3, 0x55, 0x4, 0x7, 0xc, 0xb, 0x53, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x43, 0x6c, 0x61, 0x72, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0xa, 0x4d, 0x65, 0x64, 0x69, 0x75, 0x6d, 0x20, 0x4f, 0x6e, 0x65, 0x31, 0xd, 0x30, 0xb, 0x6, 0x3, 0x55, 0x4, 0xb, 0xc, 0x4, 0x4d, 0x51, 0x54, 0x54, 0x31, 0xd, 0x30, 0xb, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x4, 0x4d, 0x51, 0x54, 0x54, 0x30, 0x81, 0x9f, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0, 0x3, 0x81, 0x8d, 0x0, 0x30, 0x81, 0x89, 0x2, 0x81, 0x81, 0x0, 0xac, 0xb8, 0xbf, 0x6c, 0x14, 0x86, 0x80, 0xbd, 0xbf, 0x3b, 0x49, 0xde, 0xfb, 0x9b, 0x94, 0xc1, 0xe4, 0x7c, 0xe6, 0xf8, 0x7f, 0x3, 0x96, 0x7d, 0x28, 0xd7, 0x2c, 0x70, 0xef, 0x6, 0x3a, 0xcc, 0x7, 0x78, 0x5f, 0x24, 0x80, 0x1e, 0xbb, 0x94, 0xf8, 0xd9, 0x6f, 0xe2, 0x0, 0xc9, 0x60, 0x7e, 0x4c, 0x7c, 0xc0, 0xdd, 0x2c, 0x73, 0x44, 0xcf, 0x6, 0xbf, 0x52, 0x12, 0x7e, 0x5b, 0x59, 0x69, 0xbe, 0x39, 0xe9, 0xc, 0xd6, 0x53, 0xdc, 0x3c, 0xe1, 0xc2, 0x2b, 0x38, 0x29, 0x52, 0xae, 0xd3, 0xc5, 0x59, 0x2e, 0x3b, 0x3, 0x96, 0x70, 0xd4, 0x39, 0x39, 0x68, 0xb2, 0xec, 0xf4, 0xfd, 0xe8, 0x75, 0x22, 0xbf, 0x31, 0xc2, 0x51, 0xcc, 0xcc, 0x3d, 0x72, 0xe1, 0xc8, 0x8b, 0x26, 0xec, 0x43, 0xe0, 0x5b, 0xea, 0x8c, 0x80, 0x43, 0xfb, 0xe, 0x90, 0x1, 0xa, 0xe2, 0xff, 0xd1, 0x83, 0x61, 0x2, 0x3, 0x1, 0x0, 0x1, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0xb, 0x5, 0x0, 0x3, 0x81, 0x81, 0x0, 0x17, 0x30, 0xa6, 0xfb, 0x5, 0x39, 0x4, 0x6d, 0x73, 0x44, 0xef, 0x47, 0x1, 0x18, 0x29, 0x36, 0xba, 0x5e, 0x3c, 0x10, 0x2e, 0x67, 0xea, 0xe7, 0xcd, 0x25, 0x45, 0xe2, 0x7f, 0x6f, 0xe2, 0xe2, 0x5a, 0xcc, 0xa0, 0x94, 0xae, 0x3b, 0x90, 0xfb, 0xe8, 0xeb, 0xc2, 0xaa, 0xa2, 0x19, 0x55, 0xd, 0x9e, 0x3a, 0xc8, 0x96, 0xf, 0x91, 0x24, 0xbe, 0xde, 0xe8, 0x11, 0x41, 0xa, 0x60, 0xad, 0xc4, 0xf6, 0xd9, 0x74, 0x4e, 0x1a, 0xb9, 0x47, 0x7a, 0x19, 0x9a, 0x43, 0xb4, 0xb2, 0xb5, 0xa5, 0x8c, 0xc9, 0xf1, 0x71, 0x77, 0xa2, 0x37, 0x3d, 0x51, 0x8a, 0xec, 0xb9, 0x12, 0x2a, 0x66, 0x27, 0xf8, 0x30, 0x11, 0x7d, 0x37, 0x4c, 0xb5, 0xae, 0x34, 0x96, 0x93, 0x9f, 0x78, 0x99, 0x2b, 0x5d, 0xec, 0xae, 0x47, 0xe6, 0xf2, 0xbb, 0xc6, 0x45, 0x43, 0xe0, 0xe1, 0x6, 0x3a, 0xf6, 0x2b, 0xb8, 0x3e };
static uint8_t deviceCert[773] = { 0x30, 0x82, 0x3, 0x1, 0x30, 0x82, 0x2, 0x6a, 0x2, 0x8, 0x5, 0xff, 0x42, 0x9c, 0x5e, 0x82, 0x20, 0x0, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x5, 0x5, 0x0, 0x30, 0x6b, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0x8, 0xc, 0xa, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x14, 0x30, 0x12, 0x6, 0x3, 0x55, 0x4, 0x7, 0xc, 0xb, 0x53, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x43, 0x6c, 0x61, 0x72, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0xa, 0x4d, 0x65, 0x64, 0x69, 0x75, 0x6d, 0x20, 0x4f, 0x6e, 0x65, 0x31, 0xd, 0x30, 0xb, 0x6, 0x3, 0x55, 0x4, 0xb, 0xc, 0x4, 0x4d, 0x51, 0x54, 0x54, 0x31, 0xd, 0x30, 0xb, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x4, 0x4d, 0x51, 0x54, 0x54, 0x30, 0x1e, 0x17, 0xd, 0x31, 0x37, 0x30, 0x37, 0x31, 0x32, 0x31, 0x38, 0x31, 0x39, 0x32, 0x37, 0x5a, 0x17, 0xd, 0x31, 0x38, 0x30, 0x37, 0x31, 0x32, 0x31, 0x38, 0x31, 0x39, 0x32, 0x37, 0x5a, 0x30, 0x81, 0x9b, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0x8, 0xc, 0xa, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0xa, 0x4d, 0x65, 0x64, 0x69, 0x75, 0x6d, 0x20, 0x4f, 0x6e, 0x65, 0x31, 0x1b, 0x30, 0x19, 0x6, 0x3, 0x55, 0x4, 0xb, 0xc, 0x12, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x31, 0x45, 0x30, 0x43, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x3c, 0x5a, 0x4e, 0x41, 0x53, 0x37, 0x5a, 0x43, 0x45, 0x53, 0x42, 0x35, 0x53, 0x42, 0x45, 0x34, 0x35, 0x46, 0x36, 0x5a, 0x4b, 0x45, 0x41, 0x42, 0x51, 0x47, 0x56, 0x54, 0x47, 0x4d, 0x4e, 0x42, 0x52, 0x47, 0x45, 0x59, 0x54, 0x47, 0x4d, 0x42, 0x59, 0x47, 0x51, 0x59, 0x54, 0x41, 0x4d, 0x42, 0x51, 0x2f, 0x7a, 0x6c, 0x36, 0x54, 0x68, 0x30, 0x47, 0x50, 0x79, 0x43, 0x6b, 0x30, 0x82, 0x1, 0x22, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1, 0x5, 0x0, 0x3, 0x82, 0x1, 0xf, 0x0, 0x30, 0x82, 0x1, 0xa, 0x2, 0x82, 0x1, 0x1, 0x0, 0xb5, 0x81, 0x34, 0xd9, 0x4b, 0x5d, 0x74, 0x7b, 0x4b, 0x27, 0x1b, 0x86, 0x1f, 0x64, 0xf8, 0x36, 0xd0, 0x92, 0x39, 0x99, 0x33, 0x4e, 0xb, 0x83, 0x1a, 0xcb, 0xaf, 0xb4, 0xc3, 0x82, 0xb3, 0x46, 0xba, 0x19, 0xeb, 0x73, 0x4, 0xc3, 0xc2, 0xee, 0x7d, 0x96, 0x7a, 0xd1, 0xe2, 0x54, 0xbe, 0xd7, 0xe9, 0x69, 0x48, 0x64, 0x5e, 0xea, 0x60, 0x89, 0x49, 0xbd, 0x48, 0x3e, 0x9d, 0xa7, 0xab, 0x52, 0x6d, 0x8a, 0x66, 0x44, 0x8a, 0x5c, 0x2c, 0xf6, 0xe5, 0x2c, 0xad, 0xac, 0xc6, 0xef, 0x16, 0x8f, 0x5f, 0x56, 0xed, 0x13, 0x65, 0x26, 0x68, 0x12, 0xe7, 0x81, 0xfd, 0x9a, 0x62, 0xe2, 0x9e, 0xa4, 0xb2, 0xa7, 0x42, 0xd2, 0x8e, 0xf8, 0xec, 0x1a, 0x6d, 0xe3, 0xa9, 0x99, 0xad, 0x98, 0x33, 0x8d, 0xef, 0x19, 0x48, 0x22, 0x9f, 0x84, 0xb5, 0x41, 0xfc, 0xbc, 0x7f, 0x7e, 0x65, 0x64, 0xdd, 0x9, 0xe0, 0x55, 0xcb, 0xc7, 0x4d, 0xe1, 0xb1, 0x7, 0x7d, 0x86, 0xc7, 0x8b, 0x6a, 0xef, 0x4f, 0xac, 0xb1, 0x77, 0x35, 0x97, 0x43, 0x91, 0x27, 0x6c, 0x2e, 0x26, 0xae, 0x2d, 0x80, 0x71, 0x27, 0x1c, 0x44, 0x1c, 0xf8, 0xda, 0xac, 0x69, 0x98, 0xc2, 0x57, 0x99, 0x98, 0xf0, 0x7f, 0x5d, 0xc8, 0xb3, 0x7e, 0x57, 0xa3, 0x90, 0xef, 0xfe, 0x87, 0x65, 0xcd, 0xf4, 0xf2, 0x6, 0x11, 0xf3, 0x23, 0xca, 0x9f, 0x70, 0xa5, 0xb2, 0x51, 0x75, 0x2, 0xb1, 0xd3, 0x60, 0x14, 0xb0, 0x3f, 0xe4, 0x7f, 0x59, 0x51, 0x40, 0xfc, 0x23, 0xab, 0xc1, 0x43, 0xf0, 0x6d, 0x4b, 0x44, 0x4d, 0xf0, 0x8d, 0xb1, 0xcf, 0x8, 0xbd, 0x14, 0x68, 0x4e, 0xbf, 0x9, 0xfa, 0x78, 0x62, 0x4e, 0x6f, 0x61, 0xc3, 0xf8, 0x42, 0x45, 0x63, 0x56, 0x99, 0xb7, 0xa7, 0xb0, 0x45, 0x63, 0x8d, 0xa, 0xdb, 0x76, 0x74, 0x61, 0x9b, 0x2, 0x3, 0x1, 0x0, 0x1, 0x30, 0xd, 0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x5, 0x5, 0x0, 0x3, 0x81, 0x81, 0x0, 0x3f, 0x2a, 0x2c, 0x57, 0x88, 0xbf, 0x13, 0x67, 0x6d, 0x78, 0x20, 0x35, 0x4, 0x36, 0x5e, 0xa3, 0x2d, 0xac, 0x1a, 0xa1, 0xa0, 0x11, 0x36, 0x1f, 0xc, 0x88, 0x70, 0x8c, 0x16, 0xd4, 0x7b, 0xde, 0x86, 0xf5, 0x1d, 0xa9, 0xb5, 0x8a, 0x9c, 0x8c, 0xc8, 0xd4, 0xa6, 0x1e, 0x94, 0xde, 0x21, 0x79, 0xe5, 0xf9, 0x15, 0xbd, 0x3f, 0x9f, 0xb4, 0x32, 0x44, 0x33, 0x77, 0xd, 0xf7, 0xe4, 0x58, 0x3a, 0x71, 0xb9, 0xcb, 0x21, 0xe3, 0x2, 0x98, 0x4b, 0xa5, 0x31, 0xd6, 0x8b, 0xa7, 0xb1, 0x6f, 0x7f, 0xe1, 0xd0, 0x90, 0xf7, 0xfc, 0x10, 0x99, 0x45, 0xde, 0x7f, 0x5c, 0xb8, 0x99, 0x7f, 0xfc, 0x39, 0x10, 0x5d, 0x9d, 0x96, 0xb7, 0xa9, 0x7f, 0xfc, 0x11, 0xe9, 0xfe, 0xa, 0x4, 0x15, 0x8c, 0x3d, 0xed, 0x77, 0xa2, 0xa7, 0xd7, 0x59, 0xa2, 0xb9, 0x25, 0xe5, 0x4d, 0x2c, 0xb8, 0x5, 0x83, 0xbd };
#endif
#ifdef M1_ECC
static uint8_t signerCert[] = { 0x30, 0x82, 0x1, 0xe1, 0x30, 0x82, 0x1, 0x87, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2, 0x9, 0x0, 0xbe, 0x63, 0xe5, 0x3d, 0x63, 0x2c, 0x1b, 0x20, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x4d, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0x8, 0xc, 0xa, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x14, 0x30, 0x12, 0x6, 0x3, 0x55, 0x4, 0x7, 0xc, 0xb, 0x53, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x43, 0x6c, 0x61, 0x72, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0xa, 0x4d, 0x65, 0x64, 0x69, 0x75, 0x6d, 0x20, 0x4f, 0x6e, 0x65, 0x30, 0x1e, 0x17, 0xd, 0x31, 0x37, 0x30, 0x37, 0x31, 0x38, 0x30, 0x31, 0x30, 0x38, 0x31, 0x33, 0x5a, 0x17, 0xd, 0x31, 0x38, 0x30, 0x37, 0x31, 0x38, 0x30, 0x31, 0x30, 0x38, 0x31, 0x33, 0x5a, 0x30, 0x4d, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0x8, 0xc, 0xa, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x14, 0x30, 0x12, 0x6, 0x3, 0x55, 0x4, 0x7, 0xc, 0xb, 0x53, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x43, 0x6c, 0x61, 0x72, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0xa, 0x4d, 0x65, 0x64, 0x69, 0x75, 0x6d, 0x20, 0x4f, 0x6e, 0x65, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x3d, 0x67, 0xe2, 0x59, 0x59, 0xd, 0x99, 0x9f, 0x64, 0x2f, 0xf9, 0x27, 0x86, 0xad, 0x59, 0xc1, 0xd6, 0x15, 0xa7, 0xd4, 0xbb, 0xa4, 0xa5, 0x49, 0x9, 0x6f, 0xd3, 0x32, 0xc7, 0x5d, 0xff, 0xa7, 0xb7, 0x62, 0x8, 0xf9, 0x42, 0x1b, 0x6c, 0xfb, 0xc5, 0x1b, 0x4, 0x94, 0x98, 0x50, 0xe7, 0x3, 0xc9, 0x55, 0x0, 0xdf, 0xc, 0x53, 0x9b, 0xf0, 0x51, 0x2f, 0x89, 0xd7, 0x4a, 0x19, 0x48, 0xf7, 0xa3, 0x50, 0x30, 0x4e, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0xab, 0xc8, 0x46, 0x5d, 0xb6, 0x5f, 0x9e, 0xf, 0x19, 0x8, 0x7a, 0xc0, 0xf0, 0x7a, 0x1b, 0x18, 0xa1, 0x88, 0x54, 0x24, 0x30, 0x1f, 0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0xab, 0xc8, 0x46, 0x5d, 0xb6, 0x5f, 0x9e, 0xf, 0x19, 0x8, 0x7a, 0xc0, 0xf0, 0x7a, 0x1b, 0x18, 0xa1, 0x88, 0x54, 0x24, 0x30, 0xc, 0x6, 0x3, 0x55, 0x1d, 0x13, 0x4, 0x5, 0x30, 0x3, 0x1, 0x1, 0xff, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x3, 0x48, 0x0, 0x30, 0x45, 0x2, 0x20, 0x43, 0x7e, 0xe6, 0x5a, 0x99, 0xdb, 0x30, 0x0, 0x52, 0x80, 0x87, 0x78, 0xf4, 0xd3, 0x35, 0x11, 0x30, 0x40, 0xed, 0x7d, 0xde, 0x66, 0xb9, 0xfe, 0xe4, 0xcf, 0xeb, 0x72, 0x6c, 0xa8, 0xa3, 0x97, 0x2, 0x21, 0x0, 0xde, 0xe9, 0xba, 0x3c, 0x5e, 0x6c, 0x33, 0xbd, 0x37, 0xf6, 0x57, 0xe8, 0xd3, 0x8e, 0x90, 0xee, 0x8f, 0x84, 0x7d, 0xef, 0xca, 0x3e, 0x2c, 0x4f, 0xf, 0x25, 0x20, 0x5e, 0xfc, 0xd4, 0x30, 0x54 };
static uint8_t deviceCert[] = { 0x30, 0x82, 0x1, 0xd6, 0x30, 0x82, 0x1, 0x7d, 0x2, 0x8, 0x6, 0x6, 0xd2, 0x9c, 0xbb, 0x3, 0x70, 0x0, 0x30, 0x9, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x1, 0x30, 0x4d, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0x8, 0xc, 0xa, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x14, 0x30, 0x12, 0x6, 0x3, 0x55, 0x4, 0x7, 0xc, 0xb, 0x53, 0x61, 0x6e, 0x74, 0x61, 0x20, 0x43, 0x6c, 0x61, 0x72, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0xa, 0x4d, 0x65, 0x64, 0x69, 0x75, 0x6d, 0x20, 0x4f, 0x6e, 0x65, 0x30, 0x1e, 0x17, 0xd, 0x31, 0x37, 0x30, 0x37, 0x31, 0x38, 0x31, 0x35, 0x31, 0x37, 0x35, 0x39, 0x5a, 0x17, 0xd, 0x31, 0x38, 0x30, 0x37, 0x31, 0x38, 0x31, 0x35, 0x31, 0x37, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x9b, 0x31, 0xb, 0x30, 0x9, 0x6, 0x3, 0x55, 0x4, 0x6, 0x13, 0x2, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0x8, 0xc, 0xa, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x13, 0x30, 0x11, 0x6, 0x3, 0x55, 0x4, 0xa, 0xc, 0xa, 0x4d, 0x65, 0x64, 0x69, 0x75, 0x6d, 0x20, 0x4f, 0x6e, 0x65, 0x31, 0x1b, 0x30, 0x19, 0x6, 0x3, 0x55, 0x4, 0xb, 0xc, 0x12, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x31, 0x45, 0x30, 0x43, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0x3c, 0x5a, 0x4e, 0x41, 0x53, 0x37, 0x5a, 0x43, 0x45, 0x53, 0x42, 0x35, 0x53, 0x42, 0x45, 0x34, 0x35, 0x46, 0x36, 0x5a, 0x4b, 0x45, 0x41, 0x42, 0x51, 0x47, 0x56, 0x54, 0x47, 0x4d, 0x4e, 0x42, 0x52, 0x47, 0x45, 0x59, 0x54, 0x47, 0x4d, 0x42, 0x59, 0x47, 0x51, 0x59, 0x54, 0x41, 0x4d, 0x42, 0x51, 0x2f, 0x7a, 0x6c, 0x36, 0x54, 0x68, 0x30, 0x47, 0x50, 0x79, 0x43, 0x6b, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x70, 0x28, 0x4a, 0xf2, 0x91, 0xc5, 0xaf, 0xed, 0x65, 0x63, 0x78, 0xab, 0x20, 0xd8, 0xfa, 0xa5, 0x97, 0xd9, 0x8f, 0x36, 0xdb, 0x8a, 0xf6, 0xc6, 0xcd, 0x88, 0x4e, 0x9e, 0xb9, 0x26, 0x2c, 0xa2, 0x87, 0xf2, 0xeb, 0xc9, 0x1f, 0xb2, 0xf4, 0x3c, 0xb, 0xd6, 0xf1, 0xe9, 0x2c, 0xd9, 0x28, 0x2f, 0xb4, 0x15, 0xfc, 0xb7, 0xf2, 0xe6, 0xa6, 0x1e, 0x54, 0xf0, 0x26, 0xa8, 0x66, 0xed, 0x50, 0x56, 0x30, 0x9, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x1, 0x3, 0x48, 0x0, 0x30, 0x45, 0x2, 0x20, 0x70, 0x7, 0x5f, 0x4e, 0xef, 0xbd, 0xae, 0xce, 0xfd, 0x28, 0x98, 0x6c, 0xb1, 0x28, 0x60, 0x1c, 0xa1, 0xff, 0x6c, 0x5, 0x10, 0xa1, 0x1b, 0xef, 0x13, 0xa3, 0xae, 0xbc, 0xc9, 0x35, 0xa9, 0x5c, 0x2, 0x21, 0x0, 0xe7, 0x67, 0xfb, 0x14, 0xb7, 0xc6, 0x56, 0xb8, 0xff, 0xd4, 0x71, 0xcb, 0x6f, 0xbf, 0x58, 0xf3, 0x31, 0xe, 0xad, 0x80, 0x7b, 0xd0, 0xed, 0x97, 0x80, 0x5c, 0x97, 0x89, 0x64, 0x6c, 0xc3, 0x5f };
#endif


/**
 * \brief Set a parent key to output buffer.
 *
 * \param outKey[out]            Parent key buffer
 * \param keysize[in]            Length of the parent key
 * \return ATCA_SUCCESS          On success
 */
ATCA_STATUS atca_tls_set_enc_key(uint8_t* outKey, uint16_t keysize)
{
	int ret = ATCA_SUCCESS;

	do {

		if (outKey == NULL || keysize != ATCA_KEY_SIZE) BREAK(ret, "Failed: invalid param");

		memcpy(outKey, ATCA_TLS_PARENT_ENC_KEY, keysize);

	} while(0);

	return ret;
}

/**
 * \brief Set a parent key to used as encryption key.
 *
 * \return ATCA_SUCCESS          On success
 */
int atca_tls_init_enc_key(void)
{
	uint8_t ret = ATCA_SUCCESS;

	do {

		/* Write encryption key to slot 4. */
		ret = atcatls_set_enckey((uint8_t*)ATCA_TLS_PARENT_ENC_KEY, TLS_SLOT_ENC_PARENT, false);
		if (ret != ATCA_SUCCESS) BREAK(ret, "Failed: Write key");

		/* Set callback to read pre master secret from slot 1. */
		ret = atcatlsfn_set_get_enckey(atca_tls_set_enc_key);
		if (ret != ATCA_SUCCESS) BREAK(ret, "Failed: Set encrypted key");

	} while(0);

	return ret;
}

/**
 * \brief Create the pre master secret using own private key and peer's public key.
 *
 * \param ssl[inout]             As input, public key buffer of AWS IoT, as output, key buffer for pre master secret
 * \param pubKey[out]            Public key buffer of Thing
 * \param size[out]              Length of the public key
 * \param inOut[inout]           Not used
 * \return ATCA_SUCCESS          On success
 */
int atca_tls_create_pms_cb(WOLFSSL* ssl, unsigned char* pubKey, unsigned int* size, unsigned char inOut)
{
	int ret = ATCA_SUCCESS;
	uint8_t peerPubKey[ECC_BUFSIZE];
	uint32_t peerPubKeyLen = sizeof(peerPubKey);

	do {

		if (ssl->arrays->preMasterSecret == NULL || pubKey == NULL || size == NULL || inOut != 0) BREAK(ret, "Failed: invalid param");

		/* Export public key imported in X9.63 format. */
		ret = wc_ecc_export_x963(ssl->peerEccKey, peerPubKey, (word32*)&peerPubKeyLen);
		if (ret != MP_OKAY) BREAK(ret, "Failed: export public key");
		atcab_printbin_label((const uint8_t*)"Peer's public key\r\n", peerPubKey, peerPubKeyLen);

		/* Read the Device public key from slot 0. */
		pubKey[0] = ATCA_PUB_KEY_SIZE + 1;
		pubKey[1] = 0x04;
		ret = atcab_get_pubkey(TLS_SLOT_AUTH_PRIV, &pubKey[2]);
		if (ret != 0) BREAK(ret, "Failed: read device public key");
		*size = ATCA_PUB_KEY_SIZE + 2;

		/* Compute pre master secret with Device private and public key of AWS IoT. 
		   Securely Read the pre master secret from 0th + 1 slot. */
		ret = atcatls_ecdh(TLS_SLOT_AUTH_PRIV, peerPubKey + 1, ssl->arrays->preMasterSecret);
		if (ret != 0) BREAK(ret, "Failed: create PMS");
		ssl->arrays->preMasterSz = ATCA_KEY_SIZE;
		atcab_printbin_label((const uint8_t*)"Client public key to be sent\r\n", &pubKey[2], *size - 2);

	} while(0);
	
	return ret;
}

/**
 * \brief Generate random number to be required on ClientHello step of TLS.
 *
 * \param count[in]              Number of random required by WolfSSL
 * \param rand_out[out]          Pointer to store random number generated by ATECC508A
 * \return ATCA_SUCCESS          On success
 */
int atca_tls_get_random_number(uint32_t count, uint8_t* rand_out)
{
	int ret = ATCA_SUCCESS;
	uint8_t i = 0, rnd_num[RANDOM_NUM_SIZE];
	uint32_t copy_count = 0;

	do {

		if (rand_out == NULL) BREAK(ret, "Failed: invalid param");

		while (i < count) {

			ret = atcatls_random(rnd_num);
			if (ret != 0) BREAK(ret, "Failed: create random number");

			copy_count = (count - i > RANDOM_NUM_SIZE) ? RANDOM_NUM_SIZE : count - i;
			memcpy(&rand_out[i], rnd_num, copy_count);
			i += copy_count;
		}
		atcab_printbin_label((const uint8_t*)"Random Number\r\n", rand_out, count);

	} while(0);

	return ret;
}

/**
 * \brief Get signer public key to build device certificate..
 *
 * \param pubKey[out]            Pointer to certificate structure
 * \return ATCA_SUCCESS          On success
 */
int atca_tls_get_signer_public_key(uint8_t *pubKey)
{
	uint8_t ret = ATCA_SUCCESS;
	size_t end_block = 3, start_block = 0;
	uint8_t paddedPubKey[96];

	memset(paddedPubKey, 0x00, sizeof(paddedPubKey));
	for (; start_block < end_block; start_block++) {
		ret = atcab_read_zone(DEVZONE_DATA, TLS_SLOT_SIGNER_PUBKEY, 
							start_block, 0, &paddedPubKey[(start_block - 0) * 32], 32);
		if (ret != ATCA_SUCCESS) return ret;
	}

	memcpy(&pubKey[32], &paddedPubKey[40], 32);
	memcpy(&pubKey[0], &paddedPubKey[4], 32);

	return ret;
}

/**
 * \brief Read the Signer certificate from a certificate definition & ATECC508A.
 * Convert the DER formatted certificate to PEM format.
 *
 * \param cert[inout]            Pointer to certificate structure
 * \return ATCA_SUCCESS          On success
 */
int atca_tls_build_signer_cert(t_atcert* cert)
{
	int ret = ATCACERT_E_SUCCESS;

	do {

		if (cert->signer_der == NULL || cert->signer_pem == NULL) BREAK(ret, "Failed: invalid param");

		//If out atcatls_get_cert(). We do not want to try to read from ATECC
		//So need to present new signer_der certificate, and set size.
#if 0
		ret = atcatls_get_cert(&g_cert_def_1_signer, NULL, cert->signer_der, (size_t*)&cert->signer_der_size);
		if (ret != ATCACERT_E_SUCCESS) BREAK(ret, "Failed: read signer certificate");

#else
		//999 Place DER cert here that was converted using OPENSSL
		memcpy(cert->signer_der, signerCert, sizeof(signerCert));
		cert->signer_der_size = sizeof(signerCert);
#endif	
		//Seemingly harmless print function
		atcab_printbin_label((const uint8_t*)"Signer DER certficate\r\n", cert->signer_der, cert->signer_der_size);	
		
		
		//Encode to PEM, this will be done with the DER certificate that we introduced
		ret = atcacert_encode_pem_cert(cert->signer_der, cert->signer_der_size, (char*)cert->signer_pem, (size_t*)&cert->signer_pem_size);
		if (cert->signer_pem_size <= 0) BREAK(ret, "Failed: convert signer certificate");

		atcab_printbin_label((const uint8_t*)"Signer PEM certificate\r\n", &cert->signer_pem[0], cert->signer_pem_size);

		//Public key? using cert->signer_pubkey
		ret = atcacert_get_subj_public_key(&g_cert_def_1_signer, cert->signer_der, cert->signer_der_size, cert->signer_pubkey);
		if (ret != ATCACERT_E_SUCCESS) BREAK(ret, "Failed: read signer public key");

		atcab_printbin_label((const uint8_t*)"Signer public key\r\n", cert->signer_pubkey, ATCERT_PUBKEY_SIZE);

	} while(0);

	return ret;
}

/**
 * \brief Read the Device certificate from a certificate definition & ATECC508A.
 * Convert the DER formatted certificate to PEM format.
 *
 * \param cert[inout]            Pointer to certificate structure
 * \return ATCA_SUCCESS          On success
 */
int atca_tls_build_device_cert(t_atcert* cert)
{
	int ret = ATCA_SUCCESS;

	do {

		if (cert->device_der == NULL || cert->device_pem == NULL) BREAK(ret, "Failed: invalid param");

		//Introduce device certificate which is retrieved through server, (call get cert function) then convert to pem to be converted back to der
#if 0
		ret = atcatls_get_cert(&g_cert_def_2_device, cert->signer_pubkey, cert->device_der, (size_t*)&cert->device_der_size);
		if (ret != ATCACERT_E_SUCCESS) BREAK(ret, "Failed: read device certificate");
#else
		//Set device_der pointer to preallocated memory at top of this file
		memcpy(cert->device_der, deviceCert, sizeof(deviceCert));
		cert->device_der_size = sizeof(deviceCert);

#endif
		atcab_printbin_label((const uint8_t*)"Device DER certificate\r\n", cert->device_der, cert->device_der_size);

		ret = atcacert_encode_pem_cert(cert->device_der, cert->device_der_size, (char*)cert->device_pem, (size_t*)&cert->device_pem_size);
		if (cert->device_pem_size <= 0) BREAK(ret, "Failed: convert device certificate");
		atcab_printbin_label((const uint8_t*)"Device PEM certificate\r\n", cert->device_pem, cert->device_pem_size);

		ret = atcacert_get_subj_public_key(&g_cert_def_2_device, cert->device_der, cert->device_der_size, cert->device_pubkey);
		if (ret != ATCACERT_E_SUCCESS) BREAK(ret, "Failed: read device public key");
		atcab_printbin_label((const uint8_t*)"Device public key\r\n", cert->device_pubkey, ATCERT_PUBKEY_SIZE);

	} while(0);
	
	return ret;
}

/**
 * \brief Sign input digest computed in SHA256 on SeverKeyExchange step of TLS.
 *
 * \param ssl[in]                For the convenience
 * \param in[in]                 Input digest to sign
 * \param inSz[in]               Length of the digest
 * \param out[out]               Output buffer where the result of the signature should be stored
 * \param outSz[inout]           Size of the output buffer as input, and actual size of the signature as ouput
 * \param key[in]                Not used
 * \param keySz[in]              Not used
 * \param ctx[in]                For the convenience
 * \return ATCA_SUCCESS          On success
 */
int atca_tls_sign_certificate_cb(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
	int ret = ATCA_SUCCESS;
	mp_int r, s;

	do {

		if (in == NULL || out == NULL || outSz == NULL) BREAK(ret, "Failed: invalid param");

		/* Sign the input digest with the private key in slot 0. */
		ret = atcatls_sign(TLS_SLOT_AUTH_PRIV, in, out);
		if (ret != ATCA_SUCCESS) BREAK(ret, "Failed: sign digest");

		ret = mp_init_multi(&r, &s, NULL, NULL, NULL, NULL);
		if (ret != MP_OKAY) BREAK(ret, "Failed: init R and S");

		/* Load R and S. */    
		ret = mp_read_unsigned_bin(&r, &out[0], ATCA_KEY_SIZE);
		if (ret != MP_OKAY) {
			goto exit_sign;
		}
		ret = mp_read_unsigned_bin(&s, &out[ATCA_KEY_SIZE], ATCA_KEY_SIZE);
		if (ret != MP_OKAY) {
			goto exit_sign;
		}

	    /* Check for zeros */
		if (mp_iszero(&r) || mp_iszero(&s)) {
			ret = -1;
			goto exit_sign;        
		}

		/* convert mp_ints to ECDSA sig, initializes r and s internally */
		ret = StoreECC_DSA_Sig(out, outSz, &r, &s);
		if (ret != MP_OKAY) {
			goto exit_sign;      
		}

exit_sign:
		mp_clear(&r);
		mp_clear(&s);

		atcab_printbin_label((const uint8_t*)"Der Encoded Signature\r\n", out, *outSz);

	} while(0);

	return ret;
}

/**
 * \brief Verify signature received from AWS IoT to prove private key ownership on CertificateVerify step of TLS.
 *
 * \param ssl[in]                For the convenience
 * \param sig[in]                Signature to be verifyed by ATECC508A
 * \param sigSz[in]              Length of the signature
 * \param hash[in]               Input buffer containing the digest of the message
 * \param hashSz[in]             Length in bytes of the hash
 * \param key[in]                ECC public key of ASN.1 format
 * \param keySz[in]              Length of the key in bytes
 * \param result[out]            Result of the verification
 * \param ctx[in]                For the convenience
 * \return ATCA_SUCCESS          On success
 */
int atca_tls_verify_signature_cb(WOLFSSL* ssl, const byte* sig, word32 sigSz, const byte* hash, word32 hashSz, const byte* key, word32 keySz, int* result, void* ctx)
{
	int ret = ATCA_SUCCESS;
	bool verified = FALSE;
	uint8_t raw_sigature[ATCA_SIG_SIZE];	
	mp_int r, s;

	do {

		if (key == NULL || sig == NULL || hash == NULL || result == NULL) BREAK(ret, "Failed: invalid param");

	    memset(&r, 0, sizeof(r));
	    memset(&s, 0, sizeof(s));

		/* Decode ASN.1 formatted signature. */
	    ret = DecodeECC_DSA_Sig(sig, sigSz, &r, &s);
	    if (ret != MP_OKAY) {
	        return -1;
	    }

	    /* Extract R and S. */
	    ret = mp_to_unsigned_bin(&r, &raw_sigature[0]);
	    if (ret != MP_OKAY) {
	        goto exit_verify;
	    }

	    ret = mp_to_unsigned_bin(&s, &raw_sigature[ATCA_KEY_SIZE]);
	    if (ret != MP_OKAY) {
	        goto exit_verify;
	    }

        /* Verify the signature extracted in 64 bytes length. */
		ret = atcatls_verify(hash, raw_sigature, key + 1, &verified);
		if (ret != 0 || (verified != TRUE)) { 
			BREAK(ret, "Failed: verify signature");
		} else { 
			*result = TRUE;
			BREAK(ret, "Verified: signature");
		}

exit_verify:
		mp_clear(&r);
		mp_clear(&s);

	} while(0);

	return ret;
}
