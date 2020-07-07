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
  ERR_HASH_ALG_CHK  constant varchar2(128) := 'Unsupported checksum type : %s';
  ERR_CIPHER_CHAIN  constant varchar2(128) := 'Unsupported cipher chaining mode : %s';
  ERR_CS_PROVIDER   constant varchar2(128) := 'Unsupported crypto service provider';
  ERR_ENC_METHOD    constant varchar2(128) := 'Unsupported encryption method';
  ERR_ENC_VERSION   constant varchar2(128) := 'Unsupported encryption version : %s';
  ERR_KD_ALG        constant varchar2(128) := 'Unsupported key-derivation algorithm : %s';
  ERR_HMAC          constant varchar2(128) := 'Unsupported HMAC algorithm';

  P2_16             constant integer := 65536;
  P2_31             constant integer := 2147483648;
  P2_32             constant integer := 4294967296;
  P2_48             constant integer := 281474976710656;

  type VersionInfo_t is record (
    vMajor  pls_integer
  , vMinor  pls_integer
  , vFull   varchar2(3)
  );

  type StandardEncryptionInfo_t is record (
    versionInfo            VersionInfo_t
  , Flags                  raw(4)
  , fCryptoAPI             boolean
  , fAES                   boolean
  , fExternal              boolean
  , HeaderSize             pls_integer
  , AlgID_Ext              pls_integer
  , AlgID                  pls_integer
  , AlgIDHash              pls_integer
  , AlgIDHash_Ext          pls_integer
  , KeySize                pls_integer
  , ProviderType           pls_integer
  , CSPName                raw(512)
  , SaltSize               pls_integer
  , Salt                   raw(16)
  , EncryptedVerifier      raw(16)
  , VerifierHashSize       pls_integer
  , EncryptedVerifierHash  raw(32)
  , EncVerifierHashSize    pls_integer
  );
  
  type AgileDataIntegrity_t is record (
    encryptedHmacKey    raw(64)
  , encryptedHmacValue  raw(64)
  , hashMacAlg          pls_integer
  );
  
  type AgileKeyData_t is record (
    saltSize           integer
  , blockSize          integer
  , keyBits            integer
  , hashSize           integer
  , cipherAlgString    varchar2(16)
  , cipherAlg          pls_integer
  , cipherChainString  varchar2(16)
  , cipherChain        pls_integer
  , hashAlgString      varchar2(16)
  , hashAlg            pls_integer
  , saltValue          raw(64)
  );
  
  type AgileKeyEncryptor_t is record (
    uri                   varchar2(256)
  , spinCount             integer
  , saltSize              integer
  , blockSize             integer
  , keyBits               integer
  , hashSize              integer
  , cipherAlgString       varchar2(16)
  , cipherAlg             pls_integer
  , cipherChainString     varchar2(16)
  , cipherChain           pls_integer
  , hashAlgString         varchar2(16)
  , hashAlg               pls_integer
  , saltValue             raw(64)
  , encVerifierHashInput  raw(64)
  , encVerifierHashValue  raw(64)
  , encryptedKeyValue     raw(64)
  -- helpers
  , hashCache             raw(64)
  , password              varchar2(255)
  );
  
  type AgileEncryptionInfo_t is record (
    versionInfo     VersionInfo_t
  , XmlDescriptor   blob
  , keyData         AgileKeyData_t
  , keyEncryptor    AgileKeyEncryptor_t
  , dataIntegrity   AgileDataIntegrity_t
  );
  
  type EncryptionVerifier_t is record (
    saltSize               pls_integer
  , salt                   raw(16)
  , encryptedVerifier      raw(16)
  , verifierHashSize       pls_integer
  , encryptedVerifierHash  raw(32)
  );
  
  type BinaryRC4EncryptionHeader_t is record (
    wEncryptionType        pls_integer
  , versionInfo            VersionInfo_t
  , fCryptoAPI             boolean
  -- RC4
  , saltValue              raw(16)
  , encryptedVerifier      raw(16)
  , encryptedVerifierHash  raw(16)
  -- RC4 CryptoAPI
  , keySize                pls_integer
  , cryptoAPIVerifier      EncryptionVerifier_t
  );
  
  type ODF_EncryptionData_t is record (
    checksum             raw(128)
  , checksum_type        varchar2(256)
  , algorithm_iv         raw(128)
  , algorithm_name       varchar2(256)
  , key_deriv_salt       raw(128)
  , key_deriv_iteration  pls_integer
  , key_deriv_size       pls_integer
  , key_deriv_name       varchar2(256)
  , start_key_gen_size   pls_integer
  , start_key_gen_name   varchar2(256)
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

  function base64ToBlob (
    input in varchar2 
  )
  return blob
  is
  begin
    return to_blob(utl_encode.base64_decode(utl_raw.cast_to_raw(input)));
  end;
  
  function rawToBase64 (
    input in raw
  )
  return varchar2
  is
  begin
    return translate(utl_raw.cast_to_varchar2(utl_encode.base64_encode(input)), '_'||chr(13)||chr(10), '_');
  end;

  function to_bytes(n in integer, sz in pls_integer default 4) 
  return raw
  is
    output     raw(8);
    output_sz  pls_integer := 4;
  begin
    
    if n < P2_31 then
      output := utl_raw.cast_from_binary_integer(n, utl_raw.little_endian);
    elsif n < P2_32 then
      output := utl_raw.cast_from_binary_integer(n - P2_32, utl_raw.little_endian);
    else
      output := utl_raw.concat(to_bytes(mod(n, P2_32)), to_bytes(trunc(n / P2_32)));
      output_sz := 8;
    end if;
    
    return case when output_sz = sz then output
                when output_sz > sz then utl_raw.substr(output, 1, sz)
                else utl_raw.overlay(output, utl_raw.copies('00', sz))
           end;
  end;

  function to_int32 (p_bytes in raw) return pls_integer
  is
  begin
    return utl_raw.cast_to_binary_integer(p_bytes, utl_raw.little_endian);
  end;

  function to_int64 (bytes in raw) return integer
  is
  begin
    return utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,7,2), utl_raw.little_endian) * P2_48
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,5,2), utl_raw.little_endian) * P2_32
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,3,2), utl_raw.little_endian) * P2_16
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

  function map_HashMacAlg (p_alg in varchar2)
  return pls_integer
  is
    output  pls_integer;
  begin
    case p_alg
    when 'SHA1' then 
      output := dbms_crypto.HMAC_SH1;
    when 'MD5' then
      output := dbms_crypto.HMAC_MD5;
    -- SHA-2 hash algorithms available starting with Oracle 12
    $IF DBMS_DB_VERSION.VERSION >= 12 
    $THEN
    when 'SHA256' then
      output := dbms_crypto.HMAC_SH256;
    when 'SHA384' then
      output := dbms_crypto.HMAC_SH384;
    when 'SHA512' then
      output := dbms_crypto.HMAC_SH512;
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

  procedure BlowfishDecrypt (
    input   in blob
  , key     in raw
  , iv      in raw
  , output  in out nocopy blob
  )
  as language java name 'db.office.crypto.BlowfishImpl.decrypt(java.sql.Blob, byte[], byte[], java.sql.Blob[])';

  function PBKDF2 (
    PRF       in pls_integer
  , password  in raw
  , salt      in raw
  , c         in pls_integer
  , dkLen     in pls_integer
  )
  return raw
  is

    hLen        pls_integer;
    DK          raw(256);
    
    function F (i in pls_integer) return raw is
      output  raw(20);
      u       raw(20);
    begin
      u := dbms_crypto.Mac(utl_raw.concat(salt, utl_raw.cast_from_binary_integer(i, utl_raw.big_endian)), PRF, password);
      output := u;
      for k in 2 .. c loop
        u := dbms_crypto.Mac(u, dbms_crypto.HMAC_SH1, password);
        output := utl_raw.bit_xor(output, u);
      end loop;
      return output;
    end;
    
  begin
    
    hLen := case PRF
              when dbms_crypto.HMAC_MD5 then 16
              when dbms_crypto.HMAC_SH1 then 20
              $IF DBMS_DB_VERSION.VERSION >= 12 
              $THEN
              when dbms_crypto.HMAC_SH256 then 32
              when dbms_crypto.HMAC_SH384 then 48
              when dbms_crypto.HMAC_SH512 then 64
              $END
              else 0
            end;
            
    if hLen = 0 then
      error(-20714, ERR_HMAC);
    end if;
    
    for i in 1 .. ceil(dkLen/hLen) loop
      DK := utl_raw.concat(DK, F(i));
    end loop; 
    DK := utl_raw.substr(DK, 1, dkLen);
    
    return DK;   
  
  end;

  function inflate (
    deflateData  in out nocopy blob
  )
  return blob
  is
    tmp_gz  blob := hextoraw('1F8B08000000000000FF'); -- GZIP header
    output  blob;   
    ctx     binary_integer;
    buf     raw(32767);
  begin
    dbms_lob.copy(tmp_gz, deflateData, dbms_lob.getlength(deflateData), 11, 1);    
    dbms_lob.createtemporary(output, true);
    
    -- initialize piecewise uncompress context
    ctx := utl_compress.lz_uncompress_open(tmp_gz);
    -- uncompress data in chunks of 32k bytes, until NO_DATA_FOUND is raised
    loop
      begin
        utl_compress.lz_uncompress_extract(ctx, buf);
      exception
        when no_data_found then
          exit;
      end;
      dbms_lob.writeappend(output, utl_raw.length(buf), buf);
    end loop;
    -- close context
    utl_compress.lz_uncompress_close(ctx);
    
    debug('Uncompressed size = '||dbms_lob.getlength(output));
    
    return output;
    
  end;

  procedure read_BinaryRC4EncInfo (
    stream  in raw
  , info    in out nocopy BinaryRC4EncryptionHeader_t
  )
  is
    pos                   pls_integer := 1;
    mark                  pls_integer;
    encryptionHeaderSize  pls_integer;
    
    function readBytes(len in pls_integer) return raw is
      bytes  raw(32767);
    begin
      bytes := utl_raw.substr(stream, pos, len);
      pos := pos + len;
      return bytes;
    end;
    procedure skip(len in pls_integer) is
    begin
      pos := pos + len;
    end;
  
  begin
       
    -- 0 = XOR, 1 = RC4
    info.wEncryptionType := to_int32(readBytes(2));
    debug('wEncryptionType = '||info.wEncryptionType);
    
    if info.wEncryptionType = 1 then
    
      info.versionInfo.vMajor := to_int32(readBytes(2));
      info.versionInfo.vMinor := to_int32(readBytes(2));
      info.versionInfo.vFull := info.versionInfo.vMajor || '.' || info.versionInfo.vMinor;
      debug('vFull = '||info.versionInfo.vFull);
       
      if info.versionInfo.vMajor = 1 and info.versionInfo.vMinor = 1 then
    
        -- RC4 encryption header structure - [MS-OFFCRYPTO], 2.3.6.1
        info.fCryptoAPI := false;
        
        info.saltValue := readBytes(16);
        debug('saltValue = '||info.saltValue);  

        info.encryptedVerifier := readBytes(16);
        debug('encryptedVerifier = '||info.encryptedVerifier);
        
        info.encryptedVerifierHash := readBytes(16);
        debug('encryptedVerifierHash = '||info.encryptedVerifierHash);
        
      elsif info.versionInfo.vMajor in (2,3,4) and info.versionInfo.vMinor = 2 then
      
        -- RC4 CryptoAPI Encryption Header - [MS-OFFCRYPTO], 2.3.5.1
        info.fCryptoAPI := true;
        skip(4); -- EncryptionHeader.Flags
        encryptionHeaderSize := to_int32(readBytes(4));
        mark := pos; -- mark beginning of EncryptionHeader
        skip(16); -- skip Flags, SizeExtra, AlgID and AlgIDHash
        info.keySize := to_int32(readBytes(4))/8;  -- keySize in bytes
        if info.keySize = 0 then
          info.keySize := 5; -- 40 bits
        end if;
        pos := mark;
        skip(encryptionHeaderSize); -- skip header
        -- start reading EncryptionVerifier structure
        info.cryptoAPIVerifier.saltSize := to_int32(readBytes(4));
        info.cryptoAPIVerifier.salt := readBytes(16);
        info.cryptoAPIVerifier.encryptedVerifier := readBytes(16);
        info.cryptoAPIVerifier.verifierHashSize := to_int32(readBytes(4));
        info.cryptoAPIVerifier.encryptedVerifierHash := readBytes(20);
      
      else
        
        error(-20718, ERR_ENC_VERSION, info.versionInfo.vFull);
      
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
  
    BIT02          constant raw(4) := hextoraw('04000000');
    BIT04          constant raw(4) := hextoraw('10000000');
    BIT05          constant raw(4) := hextoraw('20000000');

    tmp_AlgID      pls_integer;
    tmp_AlgIDHash  pls_integer;
    offset         integer;
      
  begin
    
    info.HeaderSize   := to_int32(dbms_lob.substr(stream, 4, 9));
    info.Flags        := dbms_lob.substr(stream, 4, 12+1);
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
    info.fExternal    := ( utl_raw.bit_and(info.Flags, BIT04) = BIT04 );
    info.fAES         := ( utl_raw.bit_and(info.Flags, BIT05) = BIT05 );
    
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

  procedure read_ODF_EncryptionData (
    XMLEncData  in xmltype
  , encData     in out nocopy ODF_EncryptionData_t
  )
  is
  begin

    select utl_encode.base64_decode(utl_raw.cast_to_raw(checksum)) as checksum
         , checksum_type
         , utl_encode.base64_decode(utl_raw.cast_to_raw(algorithm_iv)) as algorithm_iv
         , algorithm_name
         , utl_encode.base64_decode(utl_raw.cast_to_raw(key_deriv_salt)) as key_deriv_salt
         , key_deriv_iteration
         , nvl(key_deriv_size, 16)
         , key_deriv_name
         , nvl(start_key_gen_size, 20)
         , nvl(start_key_gen_name, 'SHA1')
    into encData
    from xmltable(
           xmlnamespaces(
             'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0' as "m"
           , default 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'
           )
         , '/encryption-data'
           passing XMLEncData
           columns checksum             varchar2(128) path '@m:checksum'
                 , checksum_type        varchar2(256) path '@m:checksum-type'
                 , algorithm_iv         varchar2(128) path 'algorithm/@m:initialisation-vector'
                 , algorithm_name       varchar2(256) path 'algorithm/@m:algorithm-name'
                 , key_deriv_salt       varchar2(128) path 'key-derivation/@m:salt'
                 , key_deriv_iteration  number        path 'key-derivation/@m:iteration-count'
                 , key_deriv_size       number        path 'key-derivation/@m:key-size'
                 , key_deriv_name       varchar2(256) path 'key-derivation/@m:key-derivation-name'
                 , start_key_gen_size   number        path 'start-key-generation/@m:key-size'
                 , start_key_gen_name   varchar2(256) path 'start-key-generation/@m:start-key-generation-name'
         );
         
    if encData.key_deriv_name not in (
      'PBKDF2'
    , 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#pbkdf2'
    )
    then
      error(-20719, ERR_KD_ALG, encData.key_deriv_name);
    end if;
    
    debug(encData.algorithm_name);
    
  end;
  
  function get_key_binary_rc4 (
    keyInfo   in rc4_info_t
  , blockNum  in binary_integer
  )
  return raw
  is
    blockNumRaw  raw(4) := utl_raw.cast_from_binary_integer(blockNum, utl_raw.little_endian);
    hfinal       raw(20);
    key          raw(16);
  begin
    if keyInfo.fCryptoAPI then
      hfinal := dbms_crypto.Hash(utl_raw.concat(keyInfo.baseKey, blockNumRaw), dbms_crypto.HASH_SH1);
      key := utl_raw.substr(hfinal, 1, keyInfo.keySize);
      if keyInfo.keySize = 5 then
        key := utl_raw.concat(key, utl_raw.copies('00', 11));
      end if;
    else
      key := utl_raw.substr(dbms_crypto.Hash(utl_raw.concat(keyInfo.baseKey, blockNumRaw), dbms_crypto.HASH_MD5), 1, 16);
    end if;
    return key;
  end;

  function get_key_ODF (
    encData   in ODF_EncryptionData_t
  , password  in varchar2
  )
  return raw
  is
    derivedKey       raw(128);
    startKeyHashAlg  pls_integer;
  begin
    
    -- Start key generation hash algorithm
    if encData.start_key_gen_name in ('SHA1','http://www.w3.org/2000/09/xmldsig#sha1') then
      startKeyHashAlg := dbms_crypto.HASH_SH1;
    $IF DBMS_DB_VERSION.VERSION >= 12 
    $THEN
    elsif encData.start_key_gen_name in ('http://www.w3.org/2000/09/xmldsig#sha256') then
      startKeyHashAlg := dbms_crypto.HASH_SH256;
    $END
    else
      error(-20714, ERR_HASH_ALG, encData.start_key_gen_name);
    end if;
    
    derivedKey := PBKDF2(
                    PRF      => dbms_crypto.HMAC_SH1
                  , password => dbms_crypto.Hash(utl_i18n.string_to_raw(password,'AL32UTF8'), startKeyHashAlg)
                  , salt     => encData.key_deriv_salt
                  , c        => encData.key_deriv_iteration
                  , dkLen    => encData.key_deriv_size
                  );

    return derivedKey;
    
  end;

  function get_part_ODF (
    encryptedPart in blob
  , XMLEncData    in xmltype
  , password      in varchar2
  )
  return blob
  is
    encData          ODF_EncryptionData_t;
    derivedKey       raw(128);
    output1          blob; -- compressed (DEFLATE) data
    output2          blob; -- uncompressed data
    outputSize       integer;
    padSize          pls_integer;
    checksumHashAlg  pls_integer;
    checksum         raw(128);
  begin
    
    read_ODF_EncryptionData(XMLEncData, encData);
    derivedKey := get_key_ODF(encData, password);
    
    dbms_lob.createtemporary(output1, true);
    
    if encData.algorithm_name = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then
      
      dbms_crypto.Decrypt(
        dst => output1
      , src => encryptedPart
      , typ => dbms_crypto.ENCRYPT_AES256 + dbms_crypto.CHAIN_CBC + dbms_crypto.PAD_NONE
      , key => derivedKey
      , iv  => encData.algorithm_iv
      );
      
      -- W3C padding mode appears to be used (https://www.w3.org/TR/xmlenc-core1/#sec-Padding), 
      -- which is similar to ISO10126, so padding size is given by the last byte : 
      outputSize := dbms_lob.getlength(output1);
      padSize := utl_raw.cast_to_binary_integer(dbms_lob.substr(output1, 1, outputSize));
      debug('padSize='||padSize);
      dbms_lob.trim(output1, outputSize - padSize);
      
    elsif encData.algorithm_name in ('Blowfish CFB','urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#blowfish') then
      
      -- Java method
      BlowfishDecrypt(encryptedPart, derivedKey, encData.algorithm_iv, output1);
      /*
      -- PL/SQL
      output1 := 
      xutl_crypto.Blowfish_decrypt(
        src => encryptedPart
      , typ => xutl_crypto.CHAIN_CFB + xutl_crypto.PAD_NONE
      , key => derivedKey
      , iv  => encData.algorithm_iv
      );
      */
      
    else
      error(-20713, ERR_CIPHER_ALG, encData.algorithm_name); 
    end if;
    
    if validation_mode then
      
      if encData.checksum_type in ('SHA1/1K','urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha1-1k') then
        checksumHashAlg := dbms_crypto.HASH_SH1;
      $IF DBMS_DB_VERSION.VERSION >= 12 
      $THEN
      elsif encData.checksum_type = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k' then
        checksumHashAlg := dbms_crypto.HASH_SH256;
      $END
      else
        error(-20714, ERR_HASH_ALG_CHK, encData.checksum_type);
      end if;
      
      checksum := dbms_crypto.Hash(dbms_lob.substr(output1, 1024), checksumHashAlg);
      if checksum != encData.checksum then
        error(-20711, ERR_INVALID_PWD);
      end if;
      
    end if;
    
    output2 := inflate(output1);
    dbms_lob.freetemporary(output1);
  
    return output2;
    
  end;

  function get_binary_rc4_info (
    stream    in raw
  , password  in varchar2
  , validate  in boolean default true
  )
  return rc4_info_t
  is
  
    info                BinaryRC4EncryptionHeader_t;  
    encPassword         raw(1024) := utl_i18n.string_to_raw(password, 'AL16UTF16LE');
    truncatedHash       raw(5);
    intermediateBuffer  raw(336);
    derivedKey          raw(16);
    
    decrypted           raw(36);
    verifierHash_1      raw(20);
    verifierHash_2      raw(20);
    
    keyInfo             rc4_info_t;
    
  begin
    
    read_BinaryRC4EncInfo(stream, info);
    
    keyInfo.fCryptoAPI := info.fCryptoAPI;

    if info.fCryptoAPI then
      -- 2.3.5.2 RC4 CryptoAPI Encryption Key Generation
      keyInfo.baseKey := dbms_crypto.Hash(utl_raw.concat(info.cryptoAPIVerifier.salt, encPassword), dbms_crypto.HASH_SH1);
      keyInfo.keySize := info.keySize;
    else
      -- 2.3.6.2 Encryption Key Derivation
      truncatedHash := utl_raw.substr(dbms_crypto.Hash(encPassword, dbms_crypto.HASH_MD5), 1, 5);
      intermediateBuffer := utl_raw.copies(utl_raw.concat(truncatedHash, info.saltValue), 16);
      keyInfo.baseKey := utl_raw.substr(dbms_crypto.Hash(intermediateBuffer, dbms_crypto.HASH_MD5), 1, 5);
    end if;
    
    debug('baseKey = '||keyInfo.baseKey);
    
    -- 2.3.6.4 Password Verification
    if validate then
      
      derivedKey := get_key_binary_rc4(keyInfo, 0);
      debug('derivedKey = '||derivedKey);
    
      if info.fCryptoAPI then
        -- 2.3.5.6
        -- The RC4 decryption stream MUST NOT be reset between decrypting EncryptedVerifier and EncryptedVerifierHash.
        decrypted := dbms_crypto.Decrypt(
                       utl_raw.concat(info.cryptoAPIVerifier.encryptedVerifier, info.cryptoAPIVerifier.encryptedVerifierHash)
                     , dbms_crypto.ENCRYPT_RC4
                     , derivedKey
                     );
        verifierHash_1 := dbms_crypto.Hash(utl_raw.substr(decrypted,1,16), dbms_crypto.HASH_SH1);
        verifierHash_2 := utl_raw.substr(decrypted,17,20);
        
      else
        -- 2.3.6.4
        -- The RC4 decryption stream MUST NOT be reset between decrypting EncryptedVerifier and EncryptedVerifierHash.
        decrypted := dbms_crypto.Decrypt(
                       utl_raw.concat(info.encryptedVerifier, info.encryptedVerifierHash)
                     , dbms_crypto.ENCRYPT_RC4
                     , derivedKey
                     );
        verifierHash_1 := dbms_crypto.Hash(utl_raw.substr(decrypted,1,16), dbms_crypto.HASH_MD5);
        verifierHash_2 := utl_raw.substr(decrypted,17,16);

      end if;
      
      debug('verifierHash_1 = '||verifierHash_1);
      debug('verifierHash_2 = '||verifierHash_2);
          
      if verifierHash_1 != verifierHash_2 then
        error(-20711, ERR_INVALID_PWD);
      end if;
      
    end if;
    
    return keyInfo;
    
  end;
  
  function standardEncryptionKey (
    info     in StandardEncryptionInfo_t
  , password in varchar2
  )
  return raw
  is
    hdata           raw(64);
    x1              raw(64) := utl_raw.copies(hextoraw('36'),64);
    x2              raw(64) := utl_raw.copies(hextoraw('5C'),64);
    keyDerived      raw(64);
  begin

    -- 2.3.4.7 ECMA-376 Document Encryption Key Generation (Standard Encryption)

    hdata := dbms_crypto.Hash(utl_raw.concat(info.Salt, utl_i18n.string_to_raw(password,'AL16UTF16LE')), info.AlgIDHash);
    for i in 0 .. 49999 loop
      hdata := dbms_crypto.Hash(utl_raw.concat(utl_raw.cast_from_binary_integer(i, utl_raw.little_endian), hdata), info.AlgIDHash);
    end loop;
    hdata := dbms_crypto.Hash(utl_raw.concat(hdata, hextoraw('00000000')), info.AlgIDHash);
    
    x1 := dbms_crypto.Hash(utl_raw.bit_xor(x1, hdata), info.AlgIDHash);
    x2 := dbms_crypto.Hash(utl_raw.bit_xor(x2, hdata), info.AlgIDHash);
    keyDerived := utl_raw.substr(utl_raw.concat(x1,x2), 1, info.keySize);
    
    debug('keyDerived = '||keyDerived);
    
    return keyDerived;
    
  end;
  
  function get_key_standard (
    info     in StandardEncryptionInfo_t
  , password in varchar2
  , validate in boolean default true
  )
  return raw
  is
  
    keyDerived      raw(64);
    verifierHash_1  raw(64);
    verifierHash_2  raw(64);
    encType         pls_integer;
    
  begin

    keyDerived := standardEncryptionKey(info, password);
    
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

  function agileEncryptionKey (
    keyEnc    in out nocopy AgileKeyEncryptor_t
  , blockKey  in raw
  ) 
  return raw
  is
    hdata    raw(64);
    keySize  pls_integer := keyEnc.keyBits/8;
  begin
      
    if keyEnc.hashCache is null then
      hdata := dbms_crypto.Hash(utl_raw.concat(keyEnc.saltValue, utl_i18n.string_to_raw(keyEnc.password,'AL16UTF16LE')), keyEnc.hashAlg);
      for i in 0 .. keyEnc.spinCount - 1 loop
        hdata := dbms_crypto.Hash(utl_raw.concat(utl_raw.cast_from_binary_integer(i, utl_raw.little_endian), hdata), keyEnc.hashAlg);
      end loop;
      keyEnc.hashCache := hdata;
    else
      hdata := keyEnc.hashCache;
    end if;
      
    hdata := dbms_crypto.Hash(utl_raw.concat(hdata, blockKey), keyEnc.hashAlg);
    adjustSize(hdata, keySize, hextoraw('36'));
      
    return hdata;  
    
  end;  
    
  function get_key_agile (
    info     in out nocopy AgileEncryptionInfo_t
  , password in varchar2
  , validate in boolean default true
  )
  return raw
  is
  
    
    keyValueDecryptorKey  raw(64);
    verifierInputKey      raw(64);
    verifierHashKey       raw(64);   
    decVerifierHashInput  raw(64);
    decVerifierHash       raw(64);
    decKeyValue           raw(64);    
    verifierHash_1        raw(64);
    verifierHash_2        raw(64);
    
    encType               pls_integer;

  begin

    info.keyEncryptor.password := password;
    encType := info.keyEncryptor.cipherAlg + info.keyEncryptor.cipherChain + dbms_crypto.PAD_ZERO;
    
    if validate then
    
      -- blockKey from 2.3.4.13 #encryptedKeyValue
      keyValueDecryptorKey := agileEncryptionKey(info.keyEncryptor, hextoraw('146E0BE7ABACD0D6'));
      debug('keyValueDecryptorKey = '||keyValueDecryptorKey);
      -- blockKey from 2.3.4.13 #encryptedVerifierHashInput
      verifierInputKey := agileEncryptionKey(info.keyEncryptor, hextoraw('FEA7D2763B4B9E79'));
      debug('verifierInputKey = '||verifierInputKey);
      -- blockKey from 2.3.4.13 #encryptedVerifierHashValue
      verifierHashKey := agileEncryptionKey(info.keyEncryptor, hextoraw('D7AA0F6D3061344E'));
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

  function get_DS_StrongEncryptionDataSpc
  return blob
  is
  begin
    return base64ToBlob('CAAAAAEAAAAyAAAAUwB0AHIAbwBuAGcARQBuAGMAcgB5AHAAdABpAG8AbgBUAHIA
YQBuAHMAZgBvAHIAbQAAAA==');
  end;
  
  function get_DS_DataSpaceMap
  return blob
  is
  begin
    return base64ToBlob('CAAAAAEAAABoAAAAAQAAAAAAAAAgAAAARQBuAGMAcgB5AHAAdABlAGQAUABhAGMA
awBhAGcAZQAyAAAAUwB0AHIAbwBuAGcARQBuAGMAcgB5AHAAdABpAG8AbgBEAGEA
dABhAFMAcABhAGMAZQAAAA==');
  end;

  function get_DS_StrongEncryptionTrnsfrm
  return blob
  is
  begin
    return base64ToBlob('WAAAAAEAAABMAAAAewBGAEYAOQBBADMARgAwADMALQA1ADYARQBGAC0ANAA2ADEA
MwAtAEIARABEADUALQA1AEEANAAxAEMAMQBEADAANwAyADQANgB9AE4AAABNAGkA
YwByAG8AcwBvAGYAdAAuAEMAbwBuAHQAYQBpAG4AZQByAC4ARQBuAGMAcgB5AHAA
dABpAG8AbgBUAHIAYQBuAHMAZgBvAHIAbQAAAAEAAAABAAAAAQAAAAAAAAAAAAAA
AAAAAAQAAAA=');
  end;

  function get_DS_Version
  return blob
  is
  begin
    return base64ToBlob('PAAAAE0AaQBjAHIAbwBzAG8AZgB0AC4AQwBvAG4AdABhAGkAbgBlAHIALgBEAGEA
dABhAFMAcABhAGMAZQBzAAEAAAABAAAAAQAAAA==');
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
    stream1      blob;
    stream2      blob;
    output       blob;
    versionInfo  VersionInfo_t;
  begin
    stream1 := xutl_cdf.get_stream(p_cdf_hdl, '/EncryptionInfo');
    stream2 := xutl_cdf.get_stream(p_cdf_hdl, '/EncryptedPackage');
    
    if p_autoclose then
      xutl_cdf.close_file(p_cdf_hdl);
    end if;
    
    versionInfo.vMajor := to_int32(dbms_lob.substr(stream1, 2, 1));
    versionInfo.vMinor := to_int32(dbms_lob.substr(stream1, 2, 3));
    versionInfo.vFull := to_char(versionInfo.vMajor)||'.'||to_char(versionInfo.vMinor);
    debug('Encryption version = '||versionInfo.vFull);
    
    -- vMajor = 3 : Office 2007 SP1
    -- vMajor = 4 : Office 2007 SP2, 2010, 2013, 2016 
    -- vMinor = 3 : extensible encryption
    if versionInfo.vMajor in (3,4) and versionInfo.vMinor = 2 then
      output := get_pack_standard(stream1, stream2, p_password);
    elsif versionInfo.vMajor = 4 and versionInfo.vMinor = 4 then
      output := get_pack_agile(stream1, stream2, p_password);
    else
      -- Unsupported encryption version : %s
      error(-20718, ERR_ENC_VERSION, versionInfo.vFull);
    end if;
    
    return output;
  
  end;
  
  function get_package (
    p_file      in blob
  , p_password  in varchar2
  )
  return blob 
  is
    hdl      xutl_cdf.cdf_handle;
  begin    
    if not xutl_cdf.is_cdf(p_file) then
      error(-20710, ERR_NOT_CDF);
    end if;
    hdl := xutl_cdf.open_file(p_file);
    return get_package(hdl, p_password);
  end;

  function make_cdf (
    encryptionInfo    in blob
  , encryptedPackage  in blob
  )
  return blob
  is
    cdf     xutl_cdf.cdf_handle;
    output  blob;
  begin
    cdf := xutl_cdf.new_file;
    -- default DataSpaces streams
    xutl_cdf.add_stream(cdf, '/'||chr(6)||'DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace', get_DS_StrongEncryptionDataSpc);
    xutl_cdf.add_stream(cdf, '/'||chr(6)||'DataSpaces/DataSpaceMap', get_DS_DataSpaceMap);
    xutl_cdf.add_stream(cdf, '/'||chr(6)||'DataSpaces/TransformInfo/StrongEncryptionTransform/'||chr(6)||'Primary', get_DS_StrongEncryptionTrnsfrm);
    xutl_cdf.add_stream(cdf, '/'||chr(6)||'DataSpaces/Version', get_DS_Version);
    -- 
    xutl_cdf.add_stream(cdf, '/EncryptionInfo', encryptionInfo);
    xutl_cdf.add_stream(cdf, '/EncryptedPackage', encryptedPackage);
    output := xutl_cdf.get_file(cdf);
    xutl_cdf.close_file(cdf);    
    return output;
  end;

  function encrypt_pack_standard (
    p_package     in blob
  , p_password    in varchar2
  , p_version     in VersionInfo_t
  --, p_cipher      in varchar2
  --, p_hash        in varchar2
  )
  return blob
  is
    
    encInfo           StandardEncryptionInfo_t;
    keyDerived        raw(64);
    encType           pls_integer;
    verifier          raw(16);
    
    encryptedPackage  blob;
    encPackStream     blob;
    encInfoStream     blob;
    
  begin
    
    encInfo.versionInfo := p_version;
    encInfo.fCryptoAPI := true;
    encInfo.fAES := true;
    encInfo.fExternal := false;
    encInfo.Flags := to_bytes(
                       case when encInfo.fCryptoAPI then 4  else 0 end
                     + case when encInfo.fExternal  then 16 else 0 end
                     + case when encInfo.fAES       then 32 else 0 end
                     );
                     
    
    encInfo.AlgID_Ext := AES128;
    encInfo.AlgID := dbms_crypto.ENCRYPT_AES128;
    encInfo.AlgIDHash_Ext := HASH_SHA1;
    encInfo.AlgIDHash := dbms_crypto.HASH_SH1;
    encInfo.KeySize := 16;  -- key size in bytes
    encInfo.ProviderType := PROVIDER_AES;
    encInfo.CSPName := utl_i18n.string_to_raw('Microsoft Enhanced RSA and AES Cryptographic Provider' || chr(0), 'AL16UTF16LE');
    
    encInfo.HeaderSize := 4 * 8 -- Flags, SizeExtra, AlgID, AlgIDHash, KeySize, ProviderType, Reserved1, Reserved2
                        + utl_raw.length(encInfo.CSPName);
                        
    -- 2.3.3 EncryptionVerifier
    encInfo.SaltSize := 16;
    encInfo.Salt := dbms_crypto.RandomBytes(encInfo.SaltSize);
    
    keyDerived := standardEncryptionKey(encInfo, p_password);
    
    encType := encInfo.AlgID + dbms_crypto.CHAIN_ECB + dbms_crypto.PAD_ZERO;

    verifier := dbms_crypto.RandomBytes(16);
    encInfo.EncryptedVerifier := dbms_crypto.encrypt(verifier, encType, keyDerived);
    encInfo.VerifierHashSize := 20; -- SHA-1
    encInfo.EncryptedVerifierHash := dbms_crypto.encrypt(
                                       src => dbms_crypto.hash(verifier, encInfo.AlgIDHash)
                                     , typ => encType
                                     , key => keyDerived
                                     );
    
    -- ------------------------------------------------------
    --  EncryptedPackage stream
    -- ------------------------------------------------------
    dbms_lob.createtemporary(encryptedPackage, true);
   
    dbms_crypto.encrypt(
      dst => encryptedPackage
    , src => p_package
    , typ => encType
    , key => keyDerived
    );
    
    dbms_lob.createtemporary(encPackStream, true);
    dbms_lob.writeappend(encPackStream, 8, to_bytes(dbms_lob.getlength(p_package), 8));
    dbms_lob.copy(encPackStream, encryptedPackage, dbms_lob.getlength(encryptedPackage), 9);
    dbms_lob.freetemporary(encryptedPackage);
    
    -- ------------------------------------------------------
    --  EncryptionInfo stream
    -- ------------------------------------------------------
    dbms_lob.createtemporary(encInfoStream, true);
    
    dbms_lob.writeappend(encInfoStream, 2, to_bytes(encInfo.versionInfo.vMajor, 2));
    dbms_lob.writeappend(encInfoStream, 2, to_bytes(encInfo.versionInfo.vMinor, 2));
    dbms_lob.writeappend(encInfoStream, 4, encInfo.Flags);
    dbms_lob.writeappend(encInfoStream, 4, to_bytes(encInfo.HeaderSize));
    -- EncryptionHeader
    dbms_lob.writeappend(encInfoStream, 4, encInfo.Flags);
    dbms_lob.writeappend(encInfoStream, 4, '00000000'); -- SizeExtra
    dbms_lob.writeappend(encInfoStream, 4, to_bytes(encInfo.AlgID_Ext));
    dbms_lob.writeappend(encInfoStream, 4, to_bytes(encInfo.AlgIDHash_Ext));
    dbms_lob.writeappend(encInfoStream, 4, to_bytes(encInfo.KeySize * 8)); -- key size in bits
    dbms_lob.writeappend(encInfoStream, 4, to_bytes(encInfo.ProviderType));
    dbms_lob.writeappend(encInfoStream, 4, '00000000');  -- Reserved1
    dbms_lob.writeappend(encInfoStream, 4, '00000000');  -- Reserved2
    dbms_lob.writeappend(encInfoStream, utl_raw.length(encInfo.CSPName), encInfo.CSPName);
    -- EncryptionVerifier
    dbms_lob.writeappend(encInfoStream, 4, to_bytes(encInfo.SaltSize));
    dbms_lob.writeappend(encInfoStream, encInfo.SaltSize, encInfo.Salt);
    dbms_lob.writeappend(encInfoStream, utl_raw.length(encInfo.EncryptedVerifier), encInfo.EncryptedVerifier);
    dbms_lob.writeappend(encInfoStream, 4, to_bytes(encInfo.VerifierHashSize));
    dbms_lob.writeappend(encInfoStream, utl_raw.length(encInfo.EncryptedVerifierHash), encInfo.EncryptedVerifierHash);
    
    return make_cdf(encInfoStream, encPackStream);
    
  end;
  
  function encrypt_pack_agile (
    p_package     in blob
  , p_password    in varchar2
  , p_version     in VersionInfo_t
  , p_cipher      in varchar2
  , p_hash        in varchar2
  )
  return blob
  is
    keyData        AgileKeyData_t;
    keyEnc         AgileKeyEncryptor_t;
    dataInt        AgileDataIntegrity_t;
    
    encType        pls_integer;
    
    encryptionKey  raw(64);
    verifierInput  raw(16);
    
    xmlDescriptor  blob;
    encInfoStream  blob;
    encPackStream  blob;
    amount         pls_integer;
    offset         integer := 1;
    buffer         raw(4096);
    ciphertext     raw(4096);  
    iv             raw(64);
    inputSize      integer;
    
    hmacKeyInput   raw(64);
    
  begin
    -- allowed cipher algorithm
    if p_cipher not in ('AES128','AES256') then
      error(-20713, ERR_CIPHER_ALG, p_cipher);
    end if;
    
    -- allowed hash algorithm
    if p_hash not in ('SHA1','SHA512') then
      error(-20714, ERR_HASH_ALG, p_hash);
    end if;
    
    keyData.cipherAlgString := 'AES';
    keyData.saltSize := 16;
    keyData.blockSize := 16; -- AES block size
    
    keyEnc.cipherAlgString := 'AES';
    keyEnc.saltSize := 16;
    keyEnc.blockSize := 16;
    
    case p_cipher
    when 'AES128' then
      keyData.keyBits := 128;
      keyEnc.keyBits := 128;
    when 'AES256' then
      keyData.keyBits := 256;
      keyEnc.keyBits := 256;
    end case;
    
    keyData.cipherAlg := map_CipherAlg(keyData.cipherAlgString, keyData.keyBits);
    keyEnc.cipherAlg := map_CipherAlg(keyEnc.cipherAlgString, keyEnc.keyBits);
    
    case p_hash
    when 'SHA1' then
      keyData.hashSize := 20;
      keyEnc.hashSize := 20;      
    when 'SHA512' then
      keyData.hashSize := 64;
      keyEnc.hashSize := 64;
    end case;
    
    keyData.hashAlgString := p_hash;
    keyData.hashAlg := map_HashAlg(keyData.hashAlgString);
    keyEnc.hashAlgString := p_hash;
    keyEnc.hashAlg := map_HashAlg(keyEnc.hashAlgString);
    
    dataInt.hashMacAlg := map_HashMacAlg(keyData.hashAlgString);
    
    keyData.cipherChainString := 'ChainingModeCBC';
    keyData.cipherChain := map_CipherChainMode(keyData.cipherChainString);
    keyEnc.cipherChainString := 'ChainingModeCBC';
    keyEnc.cipherChain := map_CipherChainMode(keyEnc.cipherChainString);    

    keyData.saltValue := dbms_crypto.RandomBytes(keyData.saltSize);
    
    keyEnc.uri := 'http://schemas.microsoft.com/office/2006/keyEncryptor/password';
    keyEnc.spinCount := 100000;
    keyEnc.saltValue := dbms_crypto.RandomBytes(keyEnc.saltSize);
    
    keyEnc.password := p_password;
    encType := keyEnc.cipherAlg + keyEnc.cipherChain + dbms_crypto.PAD_ZERO;
    
    -- 2.3.4.13 #encryptedVerifierHashInput
    verifierInput := dbms_crypto.RandomBytes(keyEnc.saltSize);
    
    keyEnc.encVerifierHashInput := 
    dbms_crypto.encrypt(
      src => verifierInput
    , typ => encType
    , key => agileEncryptionKey(keyEnc, hextoraw('FEA7D2763B4B9E79'))
    , iv  => keyEnc.saltValue
    );
    
    debug('encryptedVerifierHashInput = '||keyEnc.encVerifierHashInput);
    
    -- 2.3.4.13 #encryptedVerifierHashValue
    keyEnc.encVerifierHashValue :=
    dbms_crypto.encrypt(
      src => dbms_crypto.Hash(verifierInput, keyEnc.hashAlg)
    , typ => encType
    , key => agileEncryptionKey(keyEnc, hextoraw('D7AA0F6D3061344E'))
    , iv  => keyEnc.saltValue
    );
    
    debug('encryptedVerifierHashValue = '||keyEnc.encVerifierHashValue);
    
    -- 2.3.4.13 #encryptedKeyValue
    encryptionKey := dbms_crypto.RandomBytes(keyData.keyBits/8);
    
    keyEnc.encryptedKeyValue :=
    dbms_crypto.encrypt(
      src => encryptionKey
    , typ => encType
    , key => agileEncryptionKey(keyEnc, hextoraw('146E0BE7ABACD0D6'))
    , iv  => keyEnc.saltValue
    );
    
    debug('encryptedKeyValue = '||keyEnc.encryptedKeyValue);
    
    inputSize := dbms_lob.getlength(p_package);
    amount := 4096;
    dbms_lob.createtemporary(encPackStream, true);
    
    -- unencrypted package size
    dbms_lob.writeappend(encPackStream, 8, to_bytes(inputSize, 8));
    
    -- 2.3.4.15
    for i in 0 .. ceil(inputSize/4096) - 1 loop
      
      dbms_lob.read(p_package, amount, offset, buffer);
      debug('['||i||'] amount read = '||amount);
      offset := offset + amount;
      
      -- 2.3.4.12 IV Generation
      iv := dbms_crypto.Hash(
              utl_raw.concat(keyData.saltValue, utl_raw.cast_from_binary_integer(i, utl_raw.little_endian))
            , keyData.hashAlg
            );
            
      adjustSize(iv, keyData.blockSize, hextoraw('36'));
      
      ciphertext := dbms_crypto.Encrypt(
                      buffer
                    , encType
                    , encryptionKey
                    , iv
                    );
      
      dbms_lob.writeappend(encPackStream, utl_raw.length(ciphertext), ciphertext);
    
    end loop;
    
    -- 2.3.4.14 DataIntegrity Generation
    hmacKeyInput := dbms_crypto.RandomBytes(keyData.hashSize);
    
    dataInt.encryptedHmacKey := 
    dbms_crypto.Encrypt(
      src => hmacKeyInput
    , typ => encType
    , key => encryptionKey
    , iv  => dbms_crypto.Hash(utl_raw.concat(keyData.saltValue, '5FB2AD010CB9E1F6'), keyData.hashAlg)
    );
    
    dataInt.encryptedHmacValue := 
    dbms_crypto.Encrypt(
      src => dbms_crypto.Mac(
               src => encPackStream
             , typ => dataInt.hashMacAlg
             , key => hmacKeyInput
             )
    , typ => encType
    , key => encryptionKey
    , iv  => dbms_crypto.Hash(utl_raw.concat(keyData.saltValue, 'A0677F02B22C8433'), keyData.hashAlg)
    );   
    
    select xmlserialize(document
             xmlelement("encryption"
             , xmlattributes(
                 'http://schemas.microsoft.com/office/2006/encryption' as "xmlns"
               , 'http://schemas.microsoft.com/office/2006/keyEncryptor/password' as "xmlns:p"
               )
             , xmlelement("keyData"
               , xmlattributes(
                   keyData.saltSize as "saltSize"
                 , keyData.blockSize as "blockSize"
                 , keyData.keyBits as "keyBits"
                 , keyData.hashSize as "hashSize"
                 , keyData.cipherAlgString as "cipherAlgorithm"
                 , keyData.cipherChainString as "cipherChaining"
                 , keyData.hashAlgString as "hashAlgorithm"
                 , utl_raw.cast_to_varchar2(utl_encode.base64_encode(keyData.saltValue)) as "saltValue"
                 )
               )
             , xmlelement("dataIntegrity"
               , xmlattributes(
                   rawToBase64(dataInt.encryptedHmacKey) as "encryptedHmacKey"
                 , rawToBase64(dataInt.encryptedHmacValue) as "encryptedHmacValue"
                 )
               )
             , xmlelement("keyEncryptors"
               , xmlelement("keyEncryptor"
                 , xmlattributes(keyEnc.uri as "uri")
                 , xmlelement("p:encryptedKey"
                   , xmlattributes(
                       keyEnc.spinCount as "spinCount"
                     , keyEnc.saltSize as "saltSize"
                     , keyEnc.blockSize as "blockSize"
                     , keyEnc.keyBits as "keyBits"
                     , keyEnc.hashSize as "hashSize"
                     , keyEnc.cipherAlgString as "cipherAlgorithm"
                     , keyEnc.cipherChainString as "cipherChaining"
                     , keyEnc.hashAlgString as "hashAlgorithm"
                     , rawToBase64(keyEnc.saltValue) as "saltValue"
                     , rawToBase64(keyEnc.encVerifierHashInput) as "encryptedVerifierHashInput"
                     , rawToBase64(keyEnc.encVerifierHashValue) as "encryptedVerifierHashValue"
                     , rawToBase64(keyEnc.encryptedKeyValue) as "encryptedKeyValue"
                     )
                   )
                 )
               )
             )
             as blob encoding 'UTF-8' no indent
           )
    into xmlDescriptor
    from dual;
    
    --dbms_output.put_line(xmlDescriptor.getClobVal(1,2));
    
    dbms_lob.createtemporary(encInfoStream, true);
    dbms_lob.writeappend(encInfoStream, 2, to_bytes(p_version.vMajor, 2));
    dbms_lob.writeappend(encInfoStream, 2, to_bytes(p_version.vMinor, 2));
    dbms_lob.writeappend(encInfoStream, 4, '40000000'); -- reserved
    dbms_lob.copy(encInfoStream, xmlDescriptor, dbms_lob.getlength(xmlDescriptor), 9);
    
    return make_cdf(encInfoStream, encPackStream);
    
  end;
  
  function encrypt_package (
    p_package     in blob
  , p_password    in varchar2
  , p_version     in varchar2
  , p_cipher      in varchar2
  , p_hash        in varchar2
  )
  return blob
  is
    output       blob;
    versionInfo  VersionInfo_t;
  begin
    versionInfo.vMajor := substr(p_version, 1, 1);
    versionInfo.vMinor := substr(p_version, 3, 1);
    versionInfo.vFull := to_char(versionInfo.vMajor)||'.'||to_char(versionInfo.vMinor);
    
    if versionInfo.vMajor in (3,4) and versionInfo.vMinor = 2 then
      output := encrypt_pack_standard(p_package, p_password, versionInfo /*, p_cipher, p_hash*/);
    elsif versionInfo.vMajor = 4 and versionInfo.vMinor = 4 then
      output := encrypt_pack_agile(p_package, p_password, versionInfo, p_cipher, p_hash);
    else
      error(-20718, ERR_ENC_VERSION, versionInfo.vFull);
    end if;
    
    return output;
    
  end;

end xutl_offcrypto;
/
