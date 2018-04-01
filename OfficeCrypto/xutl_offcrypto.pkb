create or replace package body xutl_offcrypto is

  -- 2.3.2 
  -- AlgID values
  RC4               constant pls_integer := 26625; -- 00006801
  AES128            constant pls_integer := 26126; -- 0000660E
  AES192            constant pls_integer := 26127; -- 0000660F
  AES256            constant pls_integer := 26128; -- 00006610
  -- AlgIDHash values
  HASH_SHA1         constant pls_integer := 32772; -- 00008004
  -- Provider Type
  PROVIDER_RC4      constant pls_integer := 1;     -- 00000001
  PROVIDER_AES      constant pls_integer := 24;    -- 00000018
  
  ERR_NOT_CDF       constant varchar2(128) := 'Input file is not a valid CFBF container';
  ERR_INVALID_PWD   constant varchar2(128) := 'Invalid password';
  ERR_AES_KEYSIZE   constant varchar2(128) := 'Unsupported AES key size : %s';
  ERR_CIPHER_ALG    constant varchar2(128) := 'Unsupported cipher algorithm : %s';
  ERR_HASH_ALG      constant varchar2(128) := 'Unsupported hash algorithm : %s';
  ERR_CIPHER_CHAIN  constant varchar2(128) := 'Unsupported cipher chaining mode : %s';
  ERR_CS_PROVIDER   constant varchar2(128) := 'Unsupported crypto service provider';
  ERR_ENC_METHOD    constant varchar2(128) := 'Unsupported encryption method';
  ERR_ENC_VERSION   constant varchar2(128) := 'Unsupported encryption version : %s';

  POW16_4           constant integer := 65536; 
  POW16_8           constant integer := 4294967296;
  POW16_12          constant integer := 281474976710656;

  type StandardEncryptionInfo_t is record (
    vMajor                 pls_integer
  , vMinor                 pls_integer
  , Flags                  raw(1)
  , fCryptoAPI             boolean
  , fAES                   boolean
  , fExternal              boolean
  , HeaderSize             pls_integer
  , AlgID                  pls_integer
  , AlgIDHash              pls_integer
  , KeySize                pls_integer
  , ProviderType           pls_integer
  , SaltSize               pls_integer
  , Salt                   raw(16)
  , EncryptedVerifier      raw(16)
  , VerifierHashSize       pls_integer
  , EncryptedVerifierHash  raw(32)
  , EncVerifierHashSize    pls_integer
  );
  
  type AgileKeyData_t is record (
    saltSize     integer
  , blockSize    integer
  , keyBits      integer
  , hashSize     integer
  , cipherAlg    pls_integer
  , cipherChain  pls_integer
  , hashAlg      pls_integer
  , saltValue    raw(64)
  );
  
  type AgileKeyEncryptor_t is record (
    uri                   varchar2(256)
  , spinCount             integer
  , saltSize              integer
  , blockSize             integer
  , keyBits               integer
  , hashSize              integer
  , cipherAlg             pls_integer
  , cipherChain           pls_integer
  , hashAlg               pls_integer
  , saltValue             raw(64)
  , encVerifierHashInput  raw(64)
  , encVerifierHashValue  raw(64)
  , encryptedKeyValue     raw(64)
  );
  
  type AgileEncryptionInfo_t is record (
    vMajor          pls_integer
  , vMinor          pls_integer
  , XmlDescriptor   blob
  , keyData         AgileKeyData_t
  , keyEncryptor    AgileKeyEncryptor_t
  , hashCache       raw(64)
  );
  
  type BinaryRC4EncryptionHeader_t is record (
    wEncryptionType        pls_integer
  , vMajor                 pls_integer
  , vMinor                 pls_integer  
  , saltValue              raw(16)
  , encryptedVerifier      raw(16)
  , encryptedVerifierHash  raw(16)
  );
  
  validation_mode  boolean := true;
  debug_mode       boolean := false;

  procedure set_validation (p_mode in boolean)
  is 
  begin
    validation_mode := p_mode;
  end;

  procedure set_debug (p_mode in boolean)
  is
  begin
    debug_mode := p_mode;  
  end;
  
  procedure debug (message in varchar2)
  is
  begin
    if debug_mode then
      dbms_output.put_line(message);
    end if;
  end;
  
  procedure error (
    errcode in pls_integer
  , message in varchar2
  , arg1    in varchar2 default null
  , arg2    in varchar2 default null
  , arg3    in varchar2 default null
  ) 
  is
  begin
    raise_application_error(errcode, utl_lms.format_message(message, arg1, arg2, arg3));
  end;

  function to_int32 (p_bytes in raw) return pls_integer
  is
  begin
    return utl_raw.cast_to_binary_integer(p_bytes, utl_raw.little_endian);
  end;

  function to_int64 (bytes in raw) return integer
  is
  begin
    return utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,7,2), utl_raw.little_endian) * POW16_12
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,5,2), utl_raw.little_endian) * POW16_8
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,3,2), utl_raw.little_endian) * POW16_4
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,1,2), utl_raw.little_endian);
  end;

  procedure adjustSize (bytes in out nocopy raw, targetSize in pls_integer, padding in raw)
  is
    len  pls_integer := utl_raw.length(bytes);
  begin 
    if len > targetSize then
      bytes := utl_raw.substr(bytes, 1, targetSize);
    elsif len < targetSize then
      bytes := utl_raw.concat(bytes, utl_raw.copies(padding, targetSize - len));
    end if;
  end;
  
  function map_CipherAlg (p_alg in varchar2, p_keyBits in pls_integer default null)
  return pls_integer
  is
    output  pls_integer;
  begin
    case p_alg
    when 'AES' then 
      case p_keyBits
      when 128 then
        output := dbms_crypto.ENCRYPT_AES128;
      when 192 then
        output := dbms_crypto.ENCRYPT_AES192;
      when 256 then
        output := dbms_crypto.ENCRYPT_AES256;
      else
        -- Unsupported AES key size : %s
        error(-20712, ERR_AES_KEYSIZE, p_keyBits);
      end case;
    when 'DES' then
      output := dbms_crypto.ENCRYPT_DES;
    when '3DES' then
      output := dbms_crypto.ENCRYPT_3DES;
    when '3DES_112' then
      output := dbms_crypto.ENCRYPT_3DES_2KEY;
    else
      -- Unsupported cipher algorithm : %s
      error(-20713, ERR_CIPHER_ALG, p_alg);
    end case;
    return output;
  end;
  
  function map_HashAlg (p_alg in varchar2)
  return pls_integer
  is
    output  pls_integer;
  begin
    case p_alg
    when 'SHA1' then 
      output := dbms_crypto.HASH_SH1;
    when 'MD5' then
      output := dbms_crypto.HASH_MD5;
    when 'MD4' then
      output := dbms_crypto.HASH_MD4;
    -- SHA-2 hash algorithms available starting with Oracle 12
    $IF DBMS_DB_VERSION.VERSION >= 12 
    $THEN
    when 'SHA256' then
      output := dbms_crypto.HASH_SH256;
    when 'SHA384' then
      output := dbms_crypto.HASH_SH384;
    when 'SHA512' then
      output := dbms_crypto.HASH_SH512;
    $END
    else
      -- Unsupported hash algorithm : %s
      error(-20714, ERR_HASH_ALG, p_alg);
    end case;
    return output;
  end;

  function map_CipherChainMode (p_mode in varchar2)
  return pls_integer
  is
    output  pls_integer;
  begin
    case p_mode
    when 'ChainingModeCBC' then 
      output := dbms_crypto.CHAIN_CBC;
    when 'ChainingModeCFB' then
      output := dbms_crypto.CHAIN_CFB;
    else
      -- Unsupported cipher chaining mode : %s
      error(-20715, ERR_CIPHER_CHAIN, p_mode);
    end case;
    return output;
  end;  

  procedure read_BinaryRC4EncInfo (
    stream  in raw
  , info    in out nocopy BinaryRC4EncryptionHeader_t
  )
  is
  begin
       
    -- 0 = XOR, 1 = RC4
    info.wEncryptionType := to_int32(utl_raw.substr(stream, 1, 2));
    debug('wEncryptionType = '||info.wEncryptionType);
    
    if info.wEncryptionType = 1 then
    
      info.vMajor := to_int32(utl_raw.substr(stream, 3, 2));
      debug('vMajor = '||info.vMajor);
    
      info.vMinor := to_int32(utl_raw.substr(stream, 5, 2));
      debug('vMinor = '||info.vMinor);
       
      if info.vMajor = 1 and info.vMinor = 1 then
    
        -- RC4 encryption header structure - [MS-OFFCRYPTO], 2.3.6.1
        info.saltValue := utl_raw.substr(stream, 7, 16);
        debug('saltValue = '||info.saltValue);  

        info.encryptedVerifier := utl_raw.substr(stream, 23, 16);
        debug('encryptedVerifier = '||info.encryptedVerifier);
        
        info.encryptedVerifierHash := utl_raw.substr(stream, 39, 16);
        debug('encryptedVerifierHash = '||info.encryptedVerifierHash);
        
      else
        
        error(-20718, ERR_ENC_VERSION, info.vMajor||'.'||info.vMinor);
      
      end if;
    
    else
      
      error(-20717, ERR_ENC_METHOD);
      
    end if;
  
  end;
  
  procedure read_StandardEncInfo (
    stream  in out nocopy blob
  , info    in out nocopy StandardEncryptionInfo_t
  )
  is
  
    BIT02          constant raw(1) := hextoraw('04');
    BIT05          constant raw(1) := hextoraw('20');
    BIT04          constant raw(1) := hextoraw('10');

    tmp_AlgID      pls_integer;
    tmp_AlgIDHash  pls_integer;
    offset         integer;
      
  begin
    
    info.HeaderSize   := to_int32(dbms_lob.substr(stream, 4, 9));
    info.Flags        := dbms_lob.substr(stream, 1, 12+1);
    tmp_AlgID         := to_int32(dbms_lob.substr(stream, 4, 12+9));
    tmp_AlgIDHash     := to_int32(dbms_lob.substr(stream, 4, 12+13));
    info.KeySize      := to_int32(dbms_lob.substr(stream, 4, 12+17))/8;
    info.ProviderType := to_int32(dbms_lob.substr(stream, 4, 12+21));

    debug('ProviderType = '||info.ProviderType);
    case info.ProviderType
    when PROVIDER_AES then
      info.EncVerifierHashSize := 32;
    when PROVIDER_RC4 then
      info.EncVerifierHashSize := 20;
    else
      -- Unsupported crypto service provider
      error(-20716, ERR_CS_PROVIDER);
    end case;
    
    info.fCryptoAPI   := ( utl_raw.bit_and(info.Flags, BIT02) = BIT02 );
    info.fAES         := ( utl_raw.bit_and(info.Flags, BIT05) = BIT05 );
    info.fExternal    := ( utl_raw.bit_and(info.Flags, BIT04) = BIT04 );
    
    offset := 12 + info.HeaderSize + 1;
    
    info.SaltSize              := to_int32(dbms_lob.substr(stream, 4, offset + 0));
    info.Salt                  := dbms_lob.substr(stream, 16, offset + 4);
    info.EncryptedVerifier     := dbms_lob.substr(stream, 16, offset + 20);
    info.VerifierHashSize      := to_int32(dbms_lob.substr(stream, 4, offset + 36));
    info.EncryptedVerifierHash := dbms_lob.substr(stream, info.EncVerifierHashSize, offset + 40);
    
    if info.fExternal then
      -- Unsupported encryption method
      error(-20717, ERR_ENC_METHOD);
      
    elsif info.fCryptoAPI and info.fAES then
    
      if info.fAES then
        
        case tmp_AlgID
        when 0 then 
          info.AlgID := dbms_crypto.ENCRYPT_AES128;
        when AES128 then
          info.AlgID := dbms_crypto.ENCRYPT_AES128;
        when AES192 then
          info.AlgID := dbms_crypto.ENCRYPT_AES192;
        when AES256 then 
          info.AlgID := dbms_crypto.ENCRYPT_AES256;
        else
          error(-20717, ERR_ENC_METHOD);
        end case;
        
      else
        
        case tmp_AlgID 
        when 0 then
          info.AlgID := dbms_crypto.ENCRYPT_RC4;
        when RC4 then
          info.AlgID := dbms_crypto.ENCRYPT_RC4;
        else
          error(-20717, ERR_ENC_METHOD);
        end case;
      
      end if;
        
    end if;
    
    if tmp_AlgIDHash in (0, HASH_SHA1) then
      info.AlgIDHash := dbms_crypto.HASH_SH1;
    else
      error(-20717, ERR_ENC_METHOD);
    end if;
      
    dbms_lob.freetemporary(stream);
  
  end;

  procedure read_AgileXmlDesc (
    info in out nocopy AgileEncryptionInfo_t
  )
  is
  
    tmp_kdCipherAlg    varchar2(30);
    tmp_kdCipherChain  varchar2(30);
    tmp_kdHashAlg      varchar2(30);   
    tmp_keCipherAlg    varchar2(30);
    tmp_keCipherChain  varchar2(30);
    tmp_keHashAlg      varchar2(30);

    xmldesc            xmltype := xmltype(info.XmlDescriptor, nls_charset_id('AL32UTF8'));
    
  begin
    
    debug(xmldesc.getclobval(1,2));
    
    select kd_saltSize   
         , kd_blockSize  
         , kd_keyBits    
         , kd_hashSize   
         , kd_cipherAlg  
         , kd_cipherChain
         , kd_hashAlg    
         , utl_encode.base64_decode(utl_raw.cast_to_raw(kd_saltValue)) as kd_saltValue
         , ke_uri
         , ke_spinCount
         , ke_saltSize
         , ke_blockSize
         , ke_keyBits
         , ke_hashSize
         , ke_cipherAlg
         , ke_cipherChain
         , ke_hashAlg
         , utl_encode.base64_decode(utl_raw.cast_to_raw(ke_saltValue)) as ke_saltValue
         , utl_encode.base64_decode(utl_raw.cast_to_raw(ke_encVerifierHashInput)) as ke_encVerifierHashInput
         , utl_encode.base64_decode(utl_raw.cast_to_raw(ke_encVerifierHashValue)) as ke_encVerifierHashValue
         , utl_encode.base64_decode(utl_raw.cast_to_raw(ke_encKeyValue)) as ke_encKeyValue
    into info.keyData.saltSize   
       , info.keyData.blockSize  
       , info.keyData.keyBits    
       , info.keyData.hashSize   
       , tmp_kdCipherAlg           -- info.keyData.cipherAlg  
       , tmp_kdCipherChain         -- info.keyData.cipherChain
       , tmp_kdHashAlg             -- info.keyData.hashAlg    
       , info.keyData.saltValue
       --
       , info.keyEncryptor.uri
       , info.keyEncryptor.spinCount
       , info.keyEncryptor.saltSize
       , info.keyEncryptor.blockSize
       , info.keyEncryptor.keyBits
       , info.keyEncryptor.hashSize
       , tmp_keCipherAlg           -- info.keyEncryptor.cipherAlg
       , tmp_keCipherChain         -- info.keyEncryptor.cipherChain
       , tmp_keHashAlg             -- info.keyEncryptor.hashAlg
       , info.keyEncryptor.saltValue
       , info.keyEncryptor.encVerifierHashInput
       , info.keyEncryptor.encVerifierHashValue
       , info.keyEncryptor.encryptedKeyValue
    from xmltable(
           xmlnamespaces(
             'http://schemas.microsoft.com/office/2006/keyEncryptor/password' as "p"
           , default 'http://schemas.microsoft.com/office/2006/encryption'
           )
         , '/encryption'
           passing xmldesc
           columns 
           -- keyData
             kd_saltSize     integer       path 'keyData/@saltSize'
           , kd_blockSize    integer       path 'keyData/@blockSize'
           , kd_keyBits      integer       path 'keyData/@keyBits'
           , kd_hashSize     integer       path 'keyData/@hashSize'
           , kd_cipherAlg    varchar2(30)  path 'keyData/@cipherAlgorithm'
           , kd_cipherChain  varchar2(30)  path 'keyData/@cipherChaining'
           , kd_hashAlg      varchar2(30)  path 'keyData/@hashAlgorithm'
           , kd_saltValue    varchar2(128) path 'keyData/@saltValue'
           -- keyEncryptor
           , ke_uri                   varchar2(256) path 'keyEncryptors/keyEncryptor/@uri'
           , ke_spinCount             integer       path 'keyEncryptors/keyEncryptor/p:encryptedKey/@spinCount'
           , ke_saltSize              integer       path 'keyEncryptors/keyEncryptor/p:encryptedKey/@saltSize'
           , ke_blockSize             integer       path 'keyEncryptors/keyEncryptor/p:encryptedKey/@blockSize'
           , ke_keyBits               integer       path 'keyEncryptors/keyEncryptor/p:encryptedKey/@keyBits'
           , ke_hashSize              integer       path 'keyEncryptors/keyEncryptor/p:encryptedKey/@hashSize'
           , ke_cipherAlg             varchar2(30)  path 'keyEncryptors/keyEncryptor/p:encryptedKey/@cipherAlgorithm'
           , ke_cipherChain           varchar2(30)  path 'keyEncryptors/keyEncryptor/p:encryptedKey/@cipherChaining'
           , ke_hashAlg               varchar2(30)  path 'keyEncryptors/keyEncryptor/p:encryptedKey/@hashAlgorithm'
           , ke_saltValue             varchar2(128) path 'keyEncryptors/keyEncryptor/p:encryptedKey/@saltValue'
           , ke_encVerifierHashInput  varchar2(128) path 'keyEncryptors/keyEncryptor/p:encryptedKey/@encryptedVerifierHashInput'
           , ke_encVerifierHashValue  varchar2(128) path 'keyEncryptors/keyEncryptor/p:encryptedKey/@encryptedVerifierHashValue'
           , ke_encKeyValue           varchar2(128) path 'keyEncryptors/keyEncryptor/p:encryptedKey/@encryptedKeyValue'
         )
    ;

    info.keyData.cipherAlg   := map_CipherAlg(tmp_kdCipherAlg, info.keyData.keyBits);
    info.keyData.cipherChain := map_CipherChainMode(tmp_kdCipherChain);
    info.keyData.hashAlg     := map_HashAlg(tmp_kdHashAlg);
    
    info.keyEncryptor.cipherAlg   := map_CipherAlg(tmp_keCipherAlg, info.keyEncryptor.keyBits);
    info.keyEncryptor.cipherChain := map_CipherChainMode(tmp_keCipherChain);
    info.keyEncryptor.hashAlg     := map_HashAlg(tmp_keHashAlg);  
  
  end;

  procedure read_AgileEncInfo (
    stream  in out nocopy blob
  , info    in out nocopy AgileEncryptionInfo_t
  )
  is
  begin

    dbms_lob.createtemporary(info.XmlDescriptor, true);
    dbms_lob.copy(info.XmlDescriptor, stream, dbms_lob.getlength(stream)-8, 1, 9);
    dbms_lob.freetemporary(stream);
    
    read_AgileXmlDesc(info);    
  
  end;
  
  function get_key_binary_rc4 (
    baseKey   in raw
  , blockNum  in binary_integer
  )
  return raw
  is
    blockNumRaw  raw(4) := utl_raw.cast_from_binary_integer(blockNum, utl_raw.little_endian);
  begin
    return utl_raw.substr(dbms_crypto.Hash(utl_raw.concat(baseKey, blockNumRaw), dbms_crypto.HASH_MD5), 1, 16);
  end;

  function get_key_binary_rc4_base (
    stream    in raw
  , password  in varchar2
  , validate  in boolean default true
  )
  return raw
  is
  
    info                BinaryRC4EncryptionHeader_t;  
    encPassword         raw(1024);
    truncatedHash       raw(5);
    intermediateBuffer  raw(336);
    baseKey             raw(16);
    derivedKey          raw(16);
    
    decrypted           raw(32);
    verifierHash_1      raw(16);
    verifierHash_2      raw(16);
    
  begin
    
    read_BinaryRC4EncInfo(stream, info);

    -- 2.3.6.2 Encryption Key Derivation
    encPassword := utl_i18n.string_to_raw(password, 'AL16UTF16LE');
    truncatedHash := utl_raw.substr(dbms_crypto.Hash(encPassword, dbms_crypto.HASH_MD5), 1, 5);
    intermediateBuffer := utl_raw.copies(utl_raw.concat(truncatedHash, info.saltValue), 16);
    baseKey := utl_raw.substr(dbms_crypto.Hash(intermediateBuffer, dbms_crypto.HASH_MD5), 1, 5);
    debug('baseKey = '||baseKey);
    
    -- 2.3.6.4 Password Verification
    if validate then
      
      derivedKey := get_key_binary_rc4(baseKey, 0);
      debug('derivedKey = '||derivedKey);
    
      -- The RC4 decryption stream MUST NOT be reset between decrypting EncryptedVerifier and EncryptedVerifierHash.
      decrypted := dbms_crypto.Decrypt(
                     utl_raw.concat(info.encryptedVerifier, info.encryptedVerifierHash)
                   , dbms_crypto.ENCRYPT_RC4
                   , derivedKey
                   );
      
      verifierHash_1 := dbms_crypto.Hash(utl_raw.substr(decrypted,1,16), dbms_crypto.HASH_MD5);
      verifierHash_2 := utl_raw.substr(decrypted,17,16);
      debug('verifierHash_1 = '||verifierHash_1);
      debug('verifierHash_2 = '||verifierHash_2);
          
      if verifierHash_1 != verifierHash_2 then
        error(-20711, ERR_INVALID_PWD);
      end if;
      
    end if;
    
    return baseKey;
    
  end;
  
  function get_key_standard (
    info     in out nocopy StandardEncryptionInfo_t
  , password in varchar2
  , validate in boolean default true
  )
  return raw
  is
  
    hdata           raw(64);
    x1              raw(64) := utl_raw.copies(hextoraw('36'),64);
    x2              raw(64) := utl_raw.copies(hextoraw('5C'),64);
    keyDerived      raw(64);
    verifierHash_1  raw(64);
    verifierHash_2  raw(64);
    encType         pls_integer;
    
  begin

    hdata := dbms_crypto.Hash(utl_raw.concat(info.Salt, utl_i18n.string_to_raw(password,'AL16UTF16LE')), info.AlgIDHash);
    for i in 0 .. 49999 loop
      hdata := dbms_crypto.Hash(utl_raw.concat(utl_raw.cast_from_binary_integer(i, utl_raw.little_endian), hdata), info.AlgIDHash);
    end loop;
    hdata := dbms_crypto.Hash(utl_raw.concat(hdata, hextoraw('00000000')), info.AlgIDHash);
    
    x1 := dbms_crypto.Hash(utl_raw.bit_xor(x1, hdata), info.AlgIDHash);
    x2 := dbms_crypto.Hash(utl_raw.bit_xor(x2, hdata), info.AlgIDHash);
    keyDerived := utl_raw.substr(utl_raw.concat(x1,x2), 1, info.keySize);
    debug('keyDerived = '||keyDerived);
    
    -- 2.3.4.9 Password Verification (Standard Encryption)
    if validate then
      
      -- ECB : 2.3.4.7
      encType := info.AlgID + dbms_crypto.CHAIN_ECB + dbms_crypto.PAD_NONE;
      verifierHash_1 := dbms_crypto.Hash(dbms_crypto.Decrypt(info.EncryptedVerifier, encType, keyDerived), info.AlgIDHash);
      verifierHash_2 := utl_raw.substr(dbms_crypto.Decrypt(info.EncryptedVerifierHash, encType, keyDerived), 1, info.verifierHashSize);
      
      if verifierHash_1 != verifierHash_2 then
        error(-20711, ERR_INVALID_PWD);
      end if;
      
    end if;
    
    return keyDerived;
    
  end;  
    
  function get_key_agile (
    info     in out nocopy AgileEncryptionInfo_t
  , password in varchar2
  , validate in boolean default true
  )
  return raw
  is
  
    hdata                 raw(64);
    keyValueDecryptorKey  raw(64);
    verifierInputKey      raw(64);
    verifierHashKey       raw(64);   
    decVerifierHashInput  raw(64);
    decVerifierHash       raw(64);
    decKeyValue           raw(64);    
    verifierHash_1        raw(64);
    verifierHash_2        raw(64);
    keySize               pls_integer := info.keyEncryptor.keyBits/8;
    encType               pls_integer;
    
    function generateKey (blockKey in raw) return raw
    is
    begin
      
      if info.hashCache is null then
        hdata := dbms_crypto.Hash(utl_raw.concat(info.keyEncryptor.saltValue, utl_i18n.string_to_raw(password,'AL16UTF16LE')), info.keyEncryptor.hashAlg);
        for i in 0 .. info.keyEncryptor.spinCount - 1 loop
          hdata := dbms_crypto.Hash(utl_raw.concat(utl_raw.cast_from_binary_integer(i, utl_raw.little_endian), hdata), info.keyEncryptor.hashAlg);
        end loop;
        info.hashCache := hdata;
      else
        hdata := info.hashCache;
      end if;
      
      hdata := dbms_crypto.Hash(utl_raw.concat(hdata, blockKey), info.keyEncryptor.hashAlg);
      adjustSize(hdata, keySize, hextoraw('36'));
      
      return hdata;  
    
    end;

  begin

    encType := info.keyEncryptor.cipherAlg + info.keyEncryptor.cipherChain + dbms_crypto.PAD_ZERO;
    
    if validate then
    
      -- blockKey from 2.3.4.13 #encryptedKeyValue
      keyValueDecryptorKey := generateKey(hextoraw('146E0BE7ABACD0D6'));
      debug('keyValueDecryptorKey = '||keyValueDecryptorKey);
      -- blockKey from 2.3.4.13 #encryptedVerifierHashInput
      verifierInputKey := generateKey(hextoraw('FEA7D2763B4B9E79'));
      debug('verifierInputKey = '||verifierInputKey);
      -- blockKey from 2.3.4.13 #encryptedVerifierHashValue
      verifierHashKey := generateKey(hextoraw('D7AA0F6D3061344E'));
      debug('verifierHashKey = '||verifierHashKey);
      
      decVerifierHashInput := 
      dbms_crypto.Decrypt(
        src => info.keyEncryptor.encVerifierHashInput
      , typ => encType
      , key => verifierInputKey
      , iv  => info.keyEncryptor.saltValue
      );
      
      decVerifierHash :=
      dbms_crypto.Decrypt(
        src => info.keyEncryptor.encVerifierHashValue
      , typ => encType
      , key => verifierHashKey
      , iv  => info.keyEncryptor.saltValue
      );
      
      verifierHash_1 := utl_raw.substr(decVerifierHash, 1, info.keyEncryptor.hashSize);
      verifierHash_2 := dbms_crypto.Hash(decVerifierHashInput, info.keyEncryptor.hashAlg);
      
      debug('decryptedVerifierHash              = '||verifierHash_1);
      debug('Hash of decryptedVerifierHashInput = '||verifierHash_2);
      
      if verifierHash_1 != verifierHash_2 then
        error(-20711, ERR_INVALID_PWD);
      end if;
    
    end if;
    
    decKeyValue :=
    dbms_crypto.Decrypt(
      src => info.keyEncryptor.encryptedKeyValue
    , typ => encType
    , key => keyValueDecryptorKey
    , iv  => info.keyEncryptor.saltValue
    );
    
    debug('decryptedKeyValue = '||decKeyValue);    
    return decKeyValue;

  end;
  
  function get_pack_standard (
    infoStream  in out nocopy blob
  , packStream  in out nocopy blob
  , password    in varchar2
  )
  return blob
  is
  
    info        standardEncryptionInfo_t;
    key         raw(64);
    encType     pls_integer;
    output      blob;
    packSize    integer;
    encPackage  blob;
    
  begin

    read_StandardEncInfo(infoStream, info);
    key := get_key_standard(info, password, validation_mode);
    
    encType := info.AlgID + dbms_crypto.CHAIN_ECB + dbms_crypto.PAD_NONE;
    
    packSize := to_int64(dbms_lob.substr(packStream, 8, 1));
    debug('packSize = '||packSize);
    
    dbms_lob.createtemporary(encPackage, true);
    dbms_lob.copy(encPackage, packStream, dbms_lob.getlength(packStream) - 8, 1, 9);
    dbms_lob.freetemporary(packStream);
    
    dbms_lob.createtemporary(output, true);
    dbms_crypto.Decrypt(output, encPackage, encType, key);   
    dbms_lob.freetemporary(encPackage);
    
    dbms_lob.trim(output, packSize);
    
    return output;
    
  end;

  function get_pack_agile (
    infoStream  in out nocopy blob
  , packStream  in out nocopy blob
  , password    in varchar2
  )
  return blob
  is
  
    info         AgileEncryptionInfo_t;
    packSize     integer;
    encPackage   blob;
    encPackSize  integer;   
    output       blob;
    amount       integer;
    offset       integer := 1;
    buffer       raw(4096);
    clear        raw(4096);  
    key          raw(64);
    iv           raw(64);
    
  begin
    
    read_AgileEncInfo(infoStream, info);
    key := get_key_agile(info, password, validation_mode);

    packSize := to_int64(dbms_lob.substr(packStream, 8, 1));
    debug('packSize = '||packSize);
        
    dbms_lob.createtemporary(encPackage, true);
    dbms_lob.copy(encPackage, packStream, dbms_lob.getlength(packStream) - 8, 1, 9);
    dbms_lob.freetemporary(packStream);    
    
    dbms_lob.createtemporary(output, true);
    encPackSize := dbms_lob.getlength(encPackage);
    debug('encPackSize = '||encPackSize);
    amount := 4096;
    
    -- 2.3.4.15
    for i in 0 .. ceil(encPackSize/4096) - 1 loop
      
      dbms_lob.read(encPackage, amount, offset, buffer);
      debug('['||i||'] amount read = '||amount);
      offset := offset + amount;
      
      -- 2.3.4.12 IV Generation
      iv := dbms_crypto.Hash(
              utl_raw.concat(info.keyData.saltValue, utl_raw.cast_from_binary_integer(i, utl_raw.little_endian))
            , info.keyData.hashAlg
            );
            
      adjustSize(iv, info.keyData.blockSize, hextoraw('36'));
      
      clear := dbms_crypto.Decrypt(
                 buffer
               , info.keyData.cipherAlg + info.keyData.cipherChain + dbms_crypto.PAD_NONE
               , key
               , iv
               );
      
      dbms_lob.writeappend(output, utl_raw.length(clear), clear);
    
    end loop;
    
    dbms_lob.freetemporary(encPackage);
    dbms_lob.trim(output, packSize);
    
    return output;
  
  end;

  function get_package (
    p_cdf_hdl   in xutl_cdf.cdf_handle
  , p_password  in varchar2
  , p_autoclose in boolean default true
  )
  return blob 
  is
  
    --hdl      xutl_cdf.cdf_handle;
    stream1  blob;
    stream2  blob;
    output   blob;
    vMajor   pls_integer;
    vMinor   pls_integer;
    vFull    varchar2(10);
    
  begin
  
    --hdl := xutl_cdf.open_file(p_file);
    stream1 := xutl_cdf.get_stream(p_cdf_hdl, '/EncryptionInfo');
    stream2 := xutl_cdf.get_stream(p_cdf_hdl, '/EncryptedPackage');
    
    if p_autoclose then
      xutl_cdf.close_file(p_cdf_hdl);
    end if;
    
    vMajor := to_int32(dbms_lob.substr(stream1, 2, 1));
    vMinor := to_int32(dbms_lob.substr(stream1, 2, 3));
    vFull := to_char(vMajor)||'.'||to_char(vMinor);
    debug('Encryption version = '||vFull);
    
    -- vMajor = 3 : Office 2007 SP1
    -- vMajor = 4 : Office 2007 SP2, 2010, 2013 
    -- vMinor = 3 : extensible encryption
    if vMajor in (3,4) and vMinor = 2 then
      output := get_pack_standard(stream1, stream2, p_password);
    elsif vMajor = 4 and vMinor = 4 then
      output := get_pack_agile(stream1, stream2, p_password);
    else
      -- Unsupported encryption version : %s
      error(-20718, ERR_ENC_VERSION, vFull);
    end if;
    
    dbms_lob.freetemporary(stream1);
    dbms_lob.freetemporary(stream2);
    
    return output;
  
  end;
  
  function get_package (
    p_file      in blob
  , p_password  in varchar2
  )
  return blob 
  is
  
    hdl      xutl_cdf.cdf_handle;
    --stream1  blob;
    --stream2  blob;
    --output   blob;
    --vMajor   pls_integer;
    --vMinor   pls_integer;
    --vFull    varchar2(10);
    
  begin
    
    if not xutl_cdf.is_cdf(p_file) then
      error(-20710, ERR_NOT_CDF);
    end if;
  
    hdl := xutl_cdf.open_file(p_file);
    
    /*
    stream1 := xutl_cdf.get_stream(hdl, '/EncryptionInfo');
    stream2 := xutl_cdf.get_stream(hdl, '/EncryptedPackage');
    xutl_cdf.close_file(hdl);
    
    vMajor := to_int32(dbms_lob.substr(stream1, 2, 1));
    vMinor := to_int32(dbms_lob.substr(stream1, 2, 3));
    vFull := to_char(vMajor)||'.'||to_char(vMinor);
    debug('Encryption version = '||vFull);
    
    -- vMajor = 3 : Office 2007 SP1
    -- vMajor = 4 : Office 2007 SP2, 2010, 2013 
    -- vMinor = 3 : extensible encryption
    if vMajor in (3,4) and vMinor = 2 then
      output := get_pack_standard(stream1, stream2, p_password);
    elsif vMajor = 4 and vMinor = 4 then
      output := get_pack_agile(stream1, stream2, p_password);
    else
      -- Unsupported encryption version : %s
      error(-20718, ERR_ENC_VERSION, vFull);
    end if;
    
    return output;
    */
    return get_package(hdl, p_password);
  
  end;

end xutl_offcrypto;
/
