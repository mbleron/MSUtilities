create or replace package body xutl_cdf is

  SIGNATURE            constant raw(8) := hextoraw('D0CF11E0A1B11AE1');

  FREESECT             constant pls_integer := -1; -- FFFFFFFF
  ENDOFCHAIN           constant pls_integer := -2; -- FFFFFFFE
  FATSECT              constant pls_integer := -3; -- FFFFFFFD
  NOSTREAM             constant pls_integer := -1; -- FFFFFFFF
  
  TYPE_STORAGE         constant raw(1) := hextoraw('01');
  TYPE_STREAM          constant raw(1) := hextoraw('02');
  TYPE_ROOT            constant raw(1) := hextoraw('05');
  
  POW16_4              constant integer := 65536; 
  POW16_8              constant integer := 4294967296;
  POW16_12             constant integer := 281474976710656;
  
  ERR_INVALID_HANDLE   constant varchar2(128) := 'Invalid context handle';
  ERR_NO_STREAM_FOUND  constant varchar2(128) := 'No stream found';
  ERR_INVALID_OFFSET   constant varchar2(128) := 'Specified offset (%s) must be lower than stream size (%s)';
  
  subtype name_t is varchar2(31 char);
  
  type name_array_t is table of name_t;
  type int32_array_t is table of pls_integer;
  type path_map_t is table of pls_integer index by varchar2(4000);

  type cdf_header_t is record (
    minor_version        raw(2)
  , major_version        raw(2)
  , byte_order           raw(2)
  , sect_size            pls_integer
  , mini_sect_size       pls_integer
  , dir_sect_cnt         pls_integer
  , fat_sect_cnt         pls_integer
  , dir_strt_sect        pls_integer
  , mini_size_cutoff     pls_integer
  , minifat_strt_sect    pls_integer
  , minifat_sect_cnt     pls_integer
  , difat_strt_sect      pls_integer
  , difat_sect_cnt       pls_integer
  -- extra field read from root directory entry
  , ministream_strt_sect pls_integer
  );
  
  type cdf_dir_entry_t is record (
    entry_name         name_t
  , object_type        raw(1)
  , color_flag         raw(1)
  , left_sibling_id    pls_integer
  , right_sibling_id   pls_integer
  , child_id           pls_integer
  , creation_time      raw(8)
  , modified_time      raw(8)
  , clsid              raw(16)
  , strt_sect          pls_integer
  , stream_size        integer
  );
  
  type cdf_directory_t is table of cdf_dir_entry_t;

  type cdf_file_t is record (
    header   cdf_header_t
  , difat    int32_array_t
  , fat      int32_array_t
  , dir      cdf_directory_t
  , dir_map  path_map_t
  , minifat  int32_array_t
  , content  blob
  );
  
  type cdf_cache_t is table of cdf_file_t index by pls_integer;
  
  cdf_cache   cdf_cache_t;
  debug_mode  boolean := false;
  
  -- not used
  function parse_path (p_path in varchar2) return name_array_t
  is
    p1     binary_integer := 1;
    p2     binary_integer := 1;
    item   name_t;
    names  name_array_t := name_array_t();
  begin
      
    while p1 != 0 loop
          
      p1 := instr(p_path, '/', p2);
          
      if p1 = 0 then
        item := substr(p_path, p2);
      else
        item := substr(p_path, p2, p1-p2);
        p2 := p1 + 1;     
      end if;
      names.extend;
      names(names.last) := item;
          
    end loop;
    
    return names;
    
  end;

  function to_int32 (bytes in raw) return pls_integer
  is
  begin
    return utl_raw.cast_to_binary_integer(bytes, utl_raw.little_endian);
  end;
  
  function to_int64 (bytes in raw) return integer
  is
  begin
    return utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,7,2), utl_raw.little_endian) * POW16_12
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,5,2), utl_raw.little_endian) * POW16_8
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,3,2), utl_raw.little_endian) * POW16_4
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,1,2), utl_raw.little_endian);
  end;
  
  -- as per [MS-DTYP] specs, 2.3.3 
  function to_filetime (bytes in raw) return date 
  is
    n  integer := to_int64(bytes); -- nbr of 100-nanosecond intervals since date 1601-01-01
  begin
    return case when n != 0 then date '1601-01-01' + n/86400e7 end;
  end;
  
  procedure build_map (dir in out nocopy cdf_directory_t, path_map in out nocopy path_map_t)
  is
    path      varchar2(4000);
    
    procedure traverse(idx in pls_integer, path in varchar2 default null) is
    begin  
      
      case dir(idx).object_type
      when TYPE_STORAGE then -- storage
        if dir(idx).child_id != NOSTREAM then
          traverse(dir(idx).child_id+1, path || '/' || dir(idx).entry_name);
        end if;
      when TYPE_STREAM then -- stream
        path_map(path || '/' || dir(idx).entry_name) := idx;
        if debug_mode then
          dbms_output.put_line('['||to_char(idx)||'] '|| path || '/' || dir(idx).entry_name);
        end if;
      when TYPE_ROOT then -- root
        traverse(dir(idx).child_id+1);
      else
        null;
      end case;
      
      if dir(idx).left_sibling_id != NOSTREAM then
        traverse(dir(idx).left_sibling_id+1, path);
      end if;
      if dir(idx).right_sibling_id != NOSTREAM then
        traverse(dir(idx).right_sibling_id+1, path);
      end if;    
      
    end;
    
  begin
    traverse(1);    
  end;
  
  procedure read_header (
    file in out nocopy cdf_file_t 
  )
  is
  begin
    
    file.header.minor_version     := dbms_lob.substr(file.content, 2, 25);
    file.header.major_version     := dbms_lob.substr(file.content, 2, 27);
    file.header.byte_order        := dbms_lob.substr(file.content, 2, 29);
    file.header.sect_size         := power(2, to_int32(dbms_lob.substr(file.content, 2, 31)));
    file.header.mini_sect_size    := power(2, to_int32(dbms_lob.substr(file.content, 2, 33)));
    file.header.dir_sect_cnt      := to_int32(dbms_lob.substr(file.content, 4, 41));
    file.header.fat_sect_cnt      := to_int32(dbms_lob.substr(file.content, 4, 45));
    file.header.dir_strt_sect     := to_int32(dbms_lob.substr(file.content, 4, 49));
    file.header.mini_size_cutoff  := to_int32(dbms_lob.substr(file.content, 4, 57));
    file.header.minifat_strt_sect := to_int32(dbms_lob.substr(file.content, 4, 61));
    file.header.minifat_sect_cnt  := to_int32(dbms_lob.substr(file.content, 4, 65));
    file.header.difat_strt_sect   := to_int32(dbms_lob.substr(file.content, 4, 69));
    file.header.difat_sect_cnt    := to_int32(dbms_lob.substr(file.content, 4, 73));
    
    file.difat := int32_array_t();
    file.difat.extend(109);
    
    for i in 1 .. 109 loop
      file.difat(i) := to_int32(dbms_lob.substr(file.content, 4, 77 + 4*(i - 1)));
    end loop;
    
    if debug_mode then
      dbms_output.put_line('minor_version     = '|| file.header.minor_version);
      dbms_output.put_line('major_version     = '|| file.header.major_version);
      dbms_output.put_line('byte_order        = '|| file.header.byte_order);
      dbms_output.put_line('sect_size         = '|| file.header.sect_size);
      dbms_output.put_line('mini_sect_size    = '|| file.header.mini_sect_size);
      dbms_output.put_line('dir_sect_cnt      = '|| file.header.dir_sect_cnt);
      dbms_output.put_line('fat_sect_cnt      = '|| file.header.fat_sect_cnt);
      dbms_output.put_line('dir_strt_sect     = '|| file.header.dir_strt_sect);
      dbms_output.put_line('mini_size_cutoff  = '|| file.header.mini_size_cutoff);
      dbms_output.put_line('minifat_strt_sect = '|| file.header.minifat_strt_sect);
      dbms_output.put_line('minifat_sect_cnt  = '|| file.header.minifat_sect_cnt);
      dbms_output.put_line('difat_strt_sect   = '|| file.header.difat_strt_sect);
      dbms_output.put_line('difat_sect_cnt    = '|| file.header.difat_sect_cnt);
    end if;
    
  end;

  function read_chain (
    fat_array in out nocopy int32_array_t
  , strt_sect in pls_integer
  )
  return int32_array_t
  is
    chain      int32_array_t := int32_array_t();
    next_sect  pls_integer := strt_sect;
  begin
    while next_sect != ENDOFCHAIN loop
      chain.extend;
      chain(chain.last) := next_sect;
      next_sect := fat_array(next_sect + 1); -- +1 because FAT PL/SQL array starts at index 1
    end loop;
    return chain;
  end;
  
  procedure read_difat (
    file in out nocopy cdf_file_t
  )
  is
    offset           integer;
    amount           integer;
    buffer           raw(4);
    next_sect        pls_integer;
    sect_array_size  pls_integer; -- DIFAT sector array size
    difat_size       pls_integer;
  begin
    
    if file.header.difat_sect_cnt != 0 then
      
      sect_array_size := file.header.sect_size/4;
      next_sect := file.header.difat_strt_sect;
        
      while next_sect != ENDOFCHAIN loop
      
        offset := (next_sect + 1) * file.header.sect_size + 1;

        difat_size := file.difat.count;
        file.difat.extend(sect_array_size - 1);
        
        amount := 4;
        
        for i in 1 .. sect_array_size loop
          dbms_lob.read(file.content, amount, offset + 4*(i-1), buffer);
          next_sect := to_int32(buffer);
          if i < sect_array_size then
            file.difat(difat_size + i) := next_sect; 
          end if;
          -- last field of DIFAT sector contains next DIFAT sector location
        end loop;
      
      end loop;
    
    end if;
    
  end;
  
  procedure read_fat (
    file in out nocopy cdf_file_t
  )
  is
    offset           integer;
    amount           integer;
    buffer           raw(4);
    next_sect        pls_integer;
    sect_array_size  pls_integer; -- FAT sector array size
    fat_size         pls_integer; 
  begin
      
    sect_array_size := file.header.sect_size/4;
    file.fat := int32_array_t();
        
    for j in 1 .. file.header.fat_sect_cnt loop
      
      next_sect := file.difat(j);
      offset := (next_sect + 1) * file.header.sect_size + 1;
      
      fat_size := file.fat.count;
      file.fat.extend(sect_array_size); -- allocate FAT sector
      
      amount := 4;
        
      for i in 1 .. sect_array_size loop
        dbms_lob.read(file.content, amount, offset + 4*(i-1), buffer);
        file.fat(fat_size + i) := to_int32(buffer);
      end loop;
      
    end loop;
    
  end;

  procedure read_minifat (
    file in out nocopy cdf_file_t
  )
  is
    offset           integer;
    amount           integer;
    buffer           raw(4);
    next_sect        pls_integer;
    sect_array_size  pls_integer; -- MiniFAT sector array size
    minifat_size     pls_integer;
    chain            int32_array_t;
  begin
      
    sect_array_size := file.header.sect_size/4;
    file.minifat := int32_array_t();
    chain := read_chain(file.fat, file.header.minifat_strt_sect);
        
    for j in 1 .. file.header.minifat_sect_cnt loop

      next_sect := chain(j);
      offset := (next_sect + 1) * file.header.sect_size + 1;      
      minifat_size := file.minifat.count;
      file.minifat.extend(sect_array_size); -- allocate FAT sector
      
      amount := 4;
        
      for i in 1 .. sect_array_size loop
        dbms_lob.read(file.content, amount, offset + 4*(i-1), buffer);
        file.minifat(minifat_size + i) := to_int32(buffer);
      end loop;
      
    end loop;
    
  end;

  procedure read_directory (
    file in out nocopy cdf_file_t
  )
  is
    ENTRY_SIZE         constant pls_integer := 128;
    offset             integer;
    buffer             raw(64);
    next_sect          pls_integer;
    sector_array_size  pls_integer; -- directory sector array size
    dir_size           pls_integer;
    chain              int32_array_t;
    entry_name_size    pls_integer;
  begin
      
    sector_array_size := file.header.sect_size/ENTRY_SIZE;
    file.dir := cdf_directory_t();
    chain := read_chain(file.fat, file.header.dir_strt_sect);
    
    for j in 1 .. chain.count loop
      
      next_sect := chain(j);
      offset := (next_sect + 1) * file.header.sect_size + 1;
      
      dir_size := file.dir.count;
      file.dir.extend(sector_array_size); -- allocate directory sector
        
      for i in 1 .. sector_array_size loop
        
        entry_name_size := to_int32(dbms_lob.substr(file.content, 2, offset + 64));
        buffer := dbms_lob.substr(file.content, entry_name_size-2, offset);
        
        file.dir(dir_size + i).entry_name       := utl_i18n.raw_to_char(buffer, 'AL16UTF16LE');
        file.dir(dir_size + i).object_type      := dbms_lob.substr(file.content, 1, offset + 66);
        file.dir(dir_size + i).color_flag       := dbms_lob.substr(file.content, 1, offset + 67);
        file.dir(dir_size + i).left_sibling_id  := to_int32(dbms_lob.substr(file.content, 4, offset + 68));
        file.dir(dir_size + i).right_sibling_id := to_int32(dbms_lob.substr(file.content, 4, offset + 72));
        file.dir(dir_size + i).child_id         := to_int32(dbms_lob.substr(file.content, 4, offset + 76));
        file.dir(dir_size + i).clsid            := dbms_lob.substr(file.content, 16, offset + 80);
        file.dir(dir_size + i).creation_time    := dbms_lob.substr(file.content, 8, offset + 100);
        file.dir(dir_size + i).modified_time    := dbms_lob.substr(file.content, 8, offset + 108);
        file.dir(dir_size + i).strt_sect        := to_int32(dbms_lob.substr(file.content, 4, offset + 116));
        file.dir(dir_size + i).stream_size      := to_int64(dbms_lob.substr(file.content, 8, offset + 120));
        
        offset := offset + ENTRY_SIZE;
        
      end loop;
      
    end loop;
    
    file.header.ministream_strt_sect := file.dir(1).strt_sect;
    
    if debug_mode then
      dbms_output.put_line('======== start Directory dump ========');
      for i in 1 .. file.dir.count loop   
        dbms_output.put_line('-------- Entry '||to_char(i-1));
        dbms_output.put_line(file.dir(i).entry_name||' [' ||length(file.dir(i).entry_name)||']');
        dbms_output.put_line('Object type   = '||file.dir(i).object_type);
        dbms_output.put_line('Size          = '||file.dir(i).stream_size);
        dbms_output.put_line('Start sect    = '||file.dir(i).strt_sect);
        dbms_output.put_line('Creation time = '||file.dir(i).creation_time);
        dbms_output.put_line('Modified time = '||file.dir(i).modified_time);
        dbms_output.put_line('CLSID         = '||file.dir(i).clsid);
      end loop;
      dbms_output.put_line('======== end Directory dump ========');
    end if;
    
    build_map(file.dir, file.dir_map);   
    
  end;
  
  function get_stream_int (
    file   in out nocopy cdf_file_t
  , path   in varchar2
  , offset in integer
  )
  return blob
  is
  
    idx                       pls_integer;
    strt_sect                 pls_integer;
    chain                     int32_array_t;
    base_sect_size            pls_integer;
    sect_size                 pls_integer;
    stream_size               integer;
    stream                    blob;
    
    amount                    integer; 
    dest_offset               integer := 1;
    src_offset                integer;
    
    ministream_chain          int32_array_t;
    ministream_array_size     pls_integer;
    ministream_strt_sect      pls_integer;
    target_ministream_sect    pls_integer;
    target_ministream_offset  pls_integer;
    is_mini                   boolean := false;
    curr_sect_idx             pls_integer;
    i                         pls_integer;
    skipped                   integer := nvl(offset, 0);
    first_segment             boolean := true;
    
  begin
    
    if not file.dir_map.exists(path) then
      raise_application_error(-20702, ERR_NO_STREAM_FOUND);
    end if;
    idx := file.dir_map(path);
    
    stream_size := file.dir(idx).stream_size;
    if skipped >= stream_size then
      raise_application_error(-20703, utl_lms.format_message(ERR_INVALID_OFFSET,to_char(skipped),to_char(stream_size)));
    end if;
    
    strt_sect := file.dir(idx).strt_sect;
    base_sect_size := file.header.sect_size;
    
    -- regular or mini-stream?
    if stream_size >= file.header.mini_size_cutoff then      
      chain := read_chain(file.fat, strt_sect);
      sect_size := base_sect_size;
    else      
      is_mini := true;
      
      sect_size := file.header.mini_sect_size; -- usually 64 bytes
      ministream_strt_sect := file.header.ministream_strt_sect;
      ministream_chain := read_chain(file.fat, ministream_strt_sect);
      -- number of minisectors in ministream sector : 
      ministream_array_size := base_sect_size / sect_size;
      chain := read_chain(file.minifat, strt_sect);   
    end if;
  
    dbms_lob.createtemporary(stream, true);
    
    -- corrected stream size
    stream_size := stream_size - skipped;
    
    -- start segment in fat or minifat chain
    i := trunc(skipped / sect_size);
    -- corrected offset in the 1st target sector or minisector
    skipped := mod(skipped, sect_size); 
    
    --for i in 1 .. chain.count loop
    while i < chain.count loop
      
      i := i + 1;
      
      amount := least(stream_size-dest_offset+1, sect_size);
      curr_sect_idx := chain(i);
      
      if is_mini then
        target_ministream_sect := trunc(curr_sect_idx/ministream_array_size);
        target_ministream_offset := mod(curr_sect_idx,ministream_array_size);
        src_offset := ( ministream_chain(target_ministream_sect + 1) + 1 ) * base_sect_size 
                      + target_ministream_offset * sect_size + 1;
      else
        src_offset := (curr_sect_idx + 1) * sect_size + 1;
      end if;
      
      -- apply offset param for the 1st segment
      if first_segment then
        src_offset := src_offset + skipped;
        if amount > skipped then
          amount := amount - skipped;
        end if;
        first_segment := false;
      end if;
      
      dbms_lob.copy(stream, file.content, amount, dest_offset, src_offset);
      dest_offset := dest_offset + amount;
      
    end loop;
    
    return stream;
  
  end;
  
  function is_cdf (p_file in blob) 
  return boolean
  is
  begin
    return ( dbms_lob.substr(p_file, 8) = SIGNATURE );
  end;
  
  procedure set_debug (p_mode in boolean)
  is
  begin
    debug_mode := p_mode;  
  end;
  
  function open_file (p_file in blob)
  return cdf_handle
  is
    cdf   cdf_file_t;
    hdl   cdf_handle;
  begin
    
    hdl := nvl(cdf_cache.last,0) + 1;
    
    cdf.content := p_file;
    read_header(cdf);
    read_difat(cdf);
    read_fat(cdf);
    read_minifat(cdf);
    read_directory(cdf);
    
    cdf_cache(hdl) := cdf;
    
    return hdl;
    
  end;
  
  procedure close_file (p_hdl in cdf_handle)
  is
  begin
    if cdf_cache.exists(p_hdl) then
      if dbms_lob.istemporary(cdf_cache(p_hdl).content) = 1 then
        dbms_lob.freetemporary(cdf_cache(p_hdl).content);
      end if;
      cdf_cache.delete(p_hdl);
    else
      raise_application_error(-20701, ERR_INVALID_HANDLE);
    end if;
  end;

  function stream_exists (
    p_hdl   in cdf_handle
  , p_path  in varchar2
  )
  return boolean
  is
  begin
    if not cdf_cache.exists(p_hdl) then
      raise_application_error(-20701, ERR_INVALID_HANDLE);
    end if;
    return cdf_cache(p_hdl).dir_map.exists(p_path);
  end;

  function get_stream (
    p_hdl    in cdf_handle
  , p_path   in varchar2
  , p_offset in integer default 0
  )
  return blob
  is
  begin
    if not cdf_cache.exists(p_hdl) then
      raise_application_error(-20701, ERR_INVALID_HANDLE);
    end if;
    return get_stream_int(cdf_cache(p_hdl), p_path, p_offset);
  end;

  function get_stream (
    p_file   in blob
  , p_path   in varchar2
  , p_offset in integer default 0
  )
  return blob
  is
    hdl     cdf_handle;
    stream  blob;
  begin
    hdl := open_file(p_file);
    stream := get_stream(hdl, p_path, p_offset);
    close_file(hdl);
    return stream;
  end;
  
  function get_streams (
    p_file    in blob
  , p_pattern in varchar2 default '*'
  )
  return entry_list_t pipelined
  is
    hdl      cdf_handle;
    dir_map  path_map_t;
    entry    entry_t;
    idx      pls_integer;
  begin
    hdl := open_file(p_file);
    dir_map := cdf_cache(hdl).dir_map;
    entry.path := dir_map.first;
    while entry.path is not null loop
      if regexp_like(entry.path, p_pattern) then
        idx := dir_map(entry.path);
        entry.creation_time := to_filetime(cdf_cache(hdl).dir(idx).creation_time);
        entry.modified_time := to_filetime(cdf_cache(hdl).dir(idx).modified_time);
        entry.stream := get_stream_int(cdf_cache(hdl), entry.path, 0);
        entry.stream_size := dbms_lob.getlength(entry.stream);
        pipe row (entry);
      end if;
      entry.path := dir_map.next(entry.path);
    end loop;
    close_file(hdl);    
    return;
  end;

end xutl_cdf;
/
