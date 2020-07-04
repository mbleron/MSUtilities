create or replace package xutl_offcrypto is
/* ======================================================================================

  MIT License

  Copyright (c) 2017-2020 Marc Bleron

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.

=========================================================================================
    Change history :
    Marc Bleron       2017-05-24     Creation
    Marc Bleron       2018-02-03     RC4 routines for .xls files
    Marc Bleron       2018-05-27     Crypto routines for ODF files
    Marc Bleron       2020-03-11     Added RC4 CryptoAPI for .xls files
    Marc Bleron       2020-06-24     Added encryption routines
====================================================================================== */

  invalid_cdf               exception;
  pragma exception_init (invalid_cdf, -20710);

  invalid_password          exception;
  pragma exception_init (invalid_password, -20711);
  
  unsupported_aes_keysize   exception;
  pragma exception_init (unsupported_aes_keysize, -20712);
  
  unsupported_cipher_alg    exception;
  pragma exception_init (unsupported_cipher_alg, -20713);
  
  unsupported_hash_alg      exception;
  pragma exception_init (unsupported_hash_alg, -20714);
  
  unsupported_cipher_chain  exception;
  pragma exception_init (unsupported_cipher_chain, -20715);
  
  unsupported_csp           exception;
  pragma exception_init (unsupported_csp, -20716);
  
  unsupported_enc_method    exception;
  pragma exception_init (unsupported_enc_method, -20717);
  
  unsupported_enc_version   exception;
  pragma exception_init (unsupported_enc_version, -20718);
  
  type rc4_info_t is record (
    baseKey     raw(20)
  , keySize     pls_integer
  , fCryptoAPI  boolean
  );

  procedure set_validation (p_mode in boolean);
  procedure set_debug (p_mode in boolean);
  function rawToBase64 (input in raw) return varchar2;

  function get_key_binary_rc4 (
    keyInfo   in rc4_info_t
  , blockNum  in binary_integer
  )
  return raw;
  
  function get_binary_rc4_info (
    stream    in raw
  , password  in varchar2
  , validate  in boolean default true
  )
  return rc4_info_t;
  
  function get_package (
    p_cdf_hdl   in xutl_cdf.cdf_handle
  , p_password  in varchar2
  , p_autoclose in boolean default true
  )
  return blob;
  
  function get_package (
    p_file      in blob
  , p_password  in varchar2
  )
  return blob;

  function get_part_ODF (
    encryptedPart in blob
  , XMLEncData    in xmltype
  , password      in varchar2
  )
  return blob;
    
  function encrypt_package (
    p_package     in blob
  , p_password    in varchar2
  , p_version     in varchar2
  , p_cipher      in varchar2
  , p_hash        in varchar2
  )
  return blob;

end xutl_offcrypto;
/
