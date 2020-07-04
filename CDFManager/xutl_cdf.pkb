create or replace package body xutl_cdf is

  SIGNATURE            constant raw(8) := hextoraw('D0CF11E0A1B11AE1');

  FREESECT             constant pls_integer := -1; -- FFFFFFFF
  ENDOFCHAIN           constant pls_integer := -2; -- FFFFFFFE
  FATSECT              constant pls_integer := -3; -- FFFFFFFD
  DIFSECT              constant pls_integer := -4; -- FFFFFFFC
  NOSTREAM             constant pls_integer := -1; -- FFFFFFFF
  
  TYPE_UNKNOWN         constant raw(1) := hextoraw('00');
  TYPE_STORAGE         constant raw(1) := hextoraw('01');
  TYPE_STREAM          constant raw(1) := hextoraw('02');
  TYPE_ROOT            constant raw(1) := hextoraw('05');
  
  COLOR_RED            constant raw(1) := hextoraw('00');
  COLOR_BLACK          constant raw(1) := hextoraw('01');
  
  P2_16                constant integer := 65536;
  P2_31                constant integer := 2147483648;
  P2_32                constant integer := 4294967296;
  P2_48                constant integer := 281474976710656;
  
  ERR_INVALID_HANDLE     constant varchar2(128) := 'Invalid context handle';
  ERR_NO_STREAM_FOUND    constant varchar2(128) := 'No stream found';
  ERR_INVALID_OFFSET     constant varchar2(128) := 'Specified offset (%s) must be lower than stream size (%s)';
  ERR_DUP_ENTRY_NAME     constant varchar2(128) := 'Duplicate entry name : %s';
  ERR_NULL_STORAGE_PATH  constant varchar2(128) := 'Storage path cannot be null';
  ERR_NOT_STORAGE        constant varchar2(128) := 'Path %s is not a storage object';
  ERR_NO_STORAGE_FOUND   constant varchar2(128) := 'Path %s does not exist';
  
  subtype name_t is varchar2(31 char);
  
  type name_array_t is table of name_t;
  type int32_array_t is table of pls_integer index by pls_integer;
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
  , difat                int32_array_t
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
  , sect_cnt           pls_integer
  , stream_content     blob
  -- red-black tree attributes
  , entry_key          raw(62)
  , parent_id          pls_integer
  );
  
  type cdf_dir_entries_t is table of cdf_dir_entry_t index by pls_integer;

  type cdf_directory_t is record (
    path_map  path_map_t
  , entries   cdf_dir_entries_t
  );

  type cdf_file_t is record (
    header   cdf_header_t
  , difat    int32_array_t
  , fat      int32_array_t
  , dir      cdf_directory_t
  , minifat  int32_array_t
  , content  blob
  );
  
  type cdf_cache_t is table of cdf_file_t index by pls_integer;
  
  type writer_t is record (
    offset     integer := 1
  , sect_size  pls_integer
  );
  
  cdf_cache   cdf_cache_t;
  debug_mode  boolean := false;

  procedure debug (
    message  in varchar2
  , arg1     in varchar2 default null
  , arg2     in varchar2 default null
  , arg3     in varchar2 default null
  )
  is
  begin
    if debug_mode then
      dbms_output.put_line(utl_lms.format_message(message, arg1, arg2, arg3));
    end if;
  end;
  
  procedure error (
    code     in pls_integer
  , message  in varchar2
  , arg1     in varchar2 default null
  , arg2     in varchar2 default null
  , arg3     in varchar2 default null
  )
  is
  begin
    raise_application_error(code, utl_lms.format_message(message, arg1, arg2, arg3));   
  end;

  procedure dump_dir (dir in cdf_directory_t)
  is
  begin
 
    dbms_output.put_line('======== start Directory dump ========');
    for i in 0 .. dir.entries.count - 1 loop   
      dbms_output.put_line('-------- Entry '||to_char(i));
      dbms_output.put_line(dir.entries(i).entry_name||' [' ||length(dir.entries(i).entry_name)||']');
      dbms_output.put_line('Object type   = '||case dir.entries(i).object_type 
                                               when TYPE_ROOT then 'Root' 
                                               when TYPE_STORAGE then 'Storage' 
                                               when TYPE_STREAM then 'Stream' 
                                               when TYPE_UNKNOWN then 'Unallocated' end);
      dbms_output.put_line('Color flag    = '||case dir.entries(i).color_flag
                                               when COLOR_RED then 'Red'
                                               when COLOR_BLACK then 'Black'
                                               end);
      dbms_output.put_line('Left sibling  = '||dir.entries(i).left_sibling_id);
      dbms_output.put_line('Right sibling = '||dir.entries(i).right_sibling_id);
      dbms_output.put_line('Child         = '||dir.entries(i).child_id);
      dbms_output.put_line('Size          = '||dir.entries(i).stream_size);
      dbms_output.put_line('Start sect    = '||dir.entries(i).strt_sect);
      dbms_output.put_line('Creation time = '||dir.entries(i).creation_time);
      dbms_output.put_line('Modified time = '||dir.entries(i).modified_time);
      dbms_output.put_line('CLSID         = '||dir.entries(i).clsid);
    end loop;
    dbms_output.put_line('======== end Directory dump ========');  
  
  end;

  function parse_path (
    p_path in varchar2
  ) 
  return name_array_t
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
      if item is not null or names is empty then
        names.extend;
        names(names.last) := item;
      end if;
    end loop;
    return names;
  end;

  function create_sort_key (
    input in varchar2 
  )
  return raw
  is
    c    char(1 char);
    key  raw(62);
  begin
    for i in 1 .. length(input) loop
      c := substr(input, i, 1);
      -- we only upper-case characters in the BMP (encoded as a single UCS-2 unit)
      -- surrogate pairs are output as is
      if length2(c) = 1 then
        c := nls_upper(c, 'NLS_SORT=BINARY');
      end if;
      key := utl_raw.concat(key, utl_i18n.string_to_raw(c, 'AL16UTF16'));
    end loop;
    return key; 
  end;

  function compare_key (
    key1  in raw
  , key2  in raw
  )
  return pls_integer
  is
    keysize1  pls_integer := utl_raw.length(key1);
    keysize2  pls_integer := utl_raw.length(key2);
  begin
    return case when keysize1 < keysize2 then -1
                when keysize1 > keysize2 then 1
                when key1 < key2 then -1
                when key1 > key2 then 1
                else 0
           end; 
  end;

  function new_entry (
    object_type     in raw
  , entry_name      in varchar2 default null
  , stream_content  in blob default null
  )
  return cdf_dir_entry_t
  is
    entry  cdf_dir_entry_t;
  begin
    entry.object_type := object_type;
    if entry_name is not null then
      entry.entry_name := entry_name;
      entry.entry_key := create_sort_key(entry_name);
    end if;
    entry.color_flag := COLOR_RED;
    entry.left_sibling_id := NOSTREAM;
    entry.right_sibling_id := NOSTREAM;
    entry.child_id := NOSTREAM;
    entry.clsid := '00000000000000000000000000000000';
    entry.creation_time := '0000000000000000';
    entry.modified_time := '0000000000000000';
    entry.strt_sect := 0;
    if object_type in (TYPE_STORAGE, TYPE_UNKNOWN) then
      entry.stream_size := 0;
    elsif object_type = TYPE_STREAM then
      entry.stream_content := stream_content;
      entry.stream_size := dbms_lob.getlength(stream_content);
    end if; 
    return entry;
  end;

  procedure add_entry_int (
    t            in out nocopy cdf_dir_entries_t
  , entry_id     in pls_integer
  , storage_id   in pls_integer
  )
  is
    local_root_id  pls_integer; -- root of the red-black tree containing this entry

    function getParent (n in pls_integer)
    return pls_integer
    is
    begin
      return case when n is not null then t(n).parent_id end;
    end;
    
    function getSibling (n in pls_integer)
    return pls_integer
    is
      p  pls_integer := getParent(n);
    begin
      if p is null then
        return null;
      elsif n = t(p).left_sibling_id then
        return t(p).right_sibling_id;
      else
        return t(p).left_sibling_id;
      end if;
    end;
    
    function getUncle (n in pls_integer)
    return pls_integer
    is
    begin
      return getSibling(getParent(n));
    end;
    
    procedure rotateLeft (n in pls_integer)
    is
      nnew  pls_integer := t(n).right_sibling_id;
      p     pls_integer := getParent(n);
    begin
      debug('RotateLeft(%d)', n);
      t(n).right_sibling_id := t(nnew).left_sibling_id;
      t(nnew).left_sibling_id := n;
      t(n).parent_id := nnew;
      if t(n).right_sibling_id != NOSTREAM then
        t(t(n).right_sibling_id).parent_id := n;
      end if;
      if p is not null then
        if n = t(p).left_sibling_id then
          t(p).left_sibling_id := nnew;
        elsif n = t(p).right_sibling_id then
          t(p).right_sibling_id := nnew;
        end if;
      end if;
      t(nnew).parent_id := p;
    end;

    procedure rotateRight (n in pls_integer)
    is
      nnew  pls_integer := t(n).left_sibling_id;
      p     pls_integer := getParent(n);
    begin
      debug('RotateRight(%d)', n);
      t(n).left_sibling_id := t(nnew).right_sibling_id;
      t(nnew).right_sibling_id := n;
      t(n).parent_id := nnew;
      if t(n).left_sibling_id != NOSTREAM then
        t(t(n).left_sibling_id).parent_id := n;
      end if;
      if p is not null then
        if n = t(p).left_sibling_id then
          t(p).left_sibling_id := nnew;
        elsif n = t(p).right_sibling_id then
          t(p).right_sibling_id := nnew;
        end if;
      end if;
      t(nnew).parent_id := p;
    end;
    
    procedure insertRecurse (root in pls_integer, n in pls_integer)
    is
    begin
      debug('InsertRecurse(%d)', n);
      if root is not null then
        case compare_key(t(n).entry_key, t(root).entry_key)
        when -1 then
          if t(root).left_sibling_id != NOSTREAM then
            insertRecurse(t(root).left_sibling_id, n);
            return;
          else
            t(root).left_sibling_id := n;
          end if;
        when 1 then
          if t(root).right_sibling_id != NOSTREAM then
            insertRecurse(t(root).right_sibling_id, n);
            return;
          else
            t(root).right_sibling_id := n;
          end if;
        else
          error(-20704, ERR_DUP_ENTRY_NAME, t(n).entry_name);
        end case;
      end if;
      t(n).parent_id := root;
      t(n).left_sibling_id := NOSTREAM;
      t(n).right_sibling_id := NOSTREAM;
      t(n).color_flag := COLOR_RED;
    end;
    
    procedure insertCase1 (n in pls_integer)
    is
    begin
      debug('InsertCase1(%d)', n);
      t(n).color_flag := COLOR_BLACK;
    end;

    procedure insertRepairTree (n in pls_integer);

    procedure insertCase3 (n in pls_integer)
    is
      p  pls_integer := getParent(n);
      g  pls_integer := getParent(p);
    begin
      debug('InsertCase3(%d)', n);
      t(p).color_flag := COLOR_BLACK;
      t(getSibling(p)).color_flag := COLOR_BLACK;
      t(g).color_flag := COLOR_RED;
      insertRepairTree(g);
    end;
    
    procedure insertCase4Step2 (n in pls_integer)
    is
      p  pls_integer := getParent(n);
      g  pls_integer := getParent(p);
    begin
      debug('insertCase4Step2(%d)', n);
      if n = t(p).left_sibling_id then
        rotateRight(g);
      else
        rotateLeft(g);
      end if;
      t(p).color_flag := COLOR_BLACK;
      t(g).color_flag := COLOR_RED;    
    end;

    procedure insertCase4 (n in pls_integer)
    is
      p  pls_integer := getParent(n);
      g  pls_integer := getParent(p);
      nnew  pls_integer := n;
    begin
      debug('InsertCase4(%d)', n);
      if n = t(p).right_sibling_id and p = t(g).left_sibling_id then
        rotateLeft(p);
        nnew := t(n).left_sibling_id;
      elsif n = t(p).left_sibling_id and p = t(g).right_sibling_id then
        rotateRight(p);
        nnew := t(n).right_sibling_id;
      end if;
      insertCase4Step2(nnew);
    end;
    
    procedure insertRepairTree (n in pls_integer)
    is
    begin
      debug('InsertRepairTree(%d)', n);
      if getParent(n) is null then
        insertCase1(n);
      elsif t(getParent(n)).color_flag = COLOR_BLACK then
        --insertCase2(n);
        null;
      elsif getUncle(n) != NOSTREAM and t(getUncle(n)).color_flag = COLOR_RED then
        insertCase3(n);
      else
        insertCase4(n);
      end if;
    end;
    
    function insertNode (root in pls_integer, n in pls_integer)
    return pls_integer
    is
      newroot  pls_integer;
      parent   pls_integer;
    begin
      debug('---------------');
      debug('InsertNode(%d)', n);
      debug('---------------');
      insertRecurse(root, n);
      insertRepairTree(n);
      newroot := n;
      loop
        parent := getParent(newroot);
        exit when parent is null;
        newroot := parent;
      end loop;
      debug('Node color : %s', case when t(n).color_flag = COLOR_RED then 'RED' else 'BLACK' end);
      return newroot;
    end;
  
  begin
    -- get child tree of the container
    if storage_id is not null then
      local_root_id := nullif(t(storage_id).child_id, -1);
    end if;
    local_root_id := insertNode(local_root_id, entry_id);
    -- update child_id pointer in the container : 
    if storage_id is not null then
      t(storage_id).child_id := local_root_id;
    end if;
  end;

  procedure add_entry (
    dir             in out nocopy cdf_directory_t
  , entry_name      in varchar2
  , object_type     in raw
  , storage_path    in varchar2
  , stream_content  in blob default null
  )
  is
    entry_id    pls_integer;
    storage_id  pls_integer;
    entry_path  varchar2(4000);
  begin
    if storage_path is null then
      if dir.entries.exists(0) then
        error(-20704, ERR_NULL_STORAGE_PATH);
      end if;
    else
      if dir.path_map.exists(storage_path) then
        storage_id := dir.path_map(storage_path);
        if dir.entries(storage_id).object_type not in (TYPE_ROOT, TYPE_STORAGE) then
          error(-20704, ERR_NOT_STORAGE, storage_path);
        end if;
      else
        error(-20704, ERR_NO_STORAGE_FOUND, storage_path);
      end if;
    end if;
    
    entry_id := nvl(dir.entries.last, -1) + 1;
    dir.entries(entry_id) := new_entry(object_type, entry_name, stream_content);    
    add_entry_int(dir.entries, entry_id, storage_id);
     
    if entry_id = 0 then
      entry_path := '/';
    elsif storage_id = 0 then
      entry_path := storage_path || entry_name;
    else
      entry_path := storage_path || '/' || entry_name;
    end if;
    dir.path_map(entry_path) := entry_id;
    
  end;
  
  procedure add_stream (
    p_hdl      in cdf_handle
  , p_name     in varchar2
  , p_path     in varchar2
  , p_content  in blob
  )
  is
  begin
    add_entry(
      dir            => cdf_cache(p_hdl).dir
    , entry_name     => p_name
    , object_type    => TYPE_STREAM
    , storage_path   => p_path
    , stream_content => p_content
    );
  end;
  
  procedure add_stream (
    p_hdl       in cdf_handle
  , p_pathname  in varchar2
  , p_content   in blob
  )
  is
    type path_array_t is table of varchar2(4000);
    paths  path_array_t := path_array_t();
    names  name_array_t := parse_path(p_pathname);
  begin
    if names(1) is not null then
      error(-20704, 'An absolute path name is required');
    end if;
    paths.extend(names.count-1);
    paths(1) := names(1);
    for i in 2 .. names.count-1 loop
      paths(i) := paths(i-1) || '/' || names(i);
    end loop;
    if paths(1) is null then
      paths(1) := '/';
    end if;
    
    for i in 1 .. paths.count loop
      if not cdf_cache(p_hdl).dir.path_map.exists(paths(i)) then
        add_entry(cdf_cache(p_hdl).dir, names(i), TYPE_STORAGE, paths(i-1));
      end if;
    end loop;
    add_entry(cdf_cache(p_hdl).dir, names(names.last), TYPE_STREAM, paths(names.last - 1), p_content);
    
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

  function to_int32 (bytes in raw) return pls_integer
  is
  begin
    return utl_raw.cast_to_binary_integer(bytes, utl_raw.little_endian);
  end;
  
  function to_int64 (bytes in raw) return integer
  is
  begin
    return utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,7,2), utl_raw.little_endian) * P2_48
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,5,2), utl_raw.little_endian) * P2_32
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,3,2), utl_raw.little_endian) * P2_16
         + utl_raw.cast_to_binary_integer(utl_raw.substr(bytes,1,2), utl_raw.little_endian);
  end;
  
  -- as per [MS-DTYP] specs, 2.3.3 
  function to_filetime (bytes in raw) return date 
  is
    n  integer := to_int64(bytes); -- nbr of 100-nanosecond intervals since date 1601-01-01
  begin
    return case when n != 0 then date '1601-01-01' + n/86400e7 end;
  end;
  
  procedure build_map (dir in cdf_dir_entries_t, path_map in out nocopy path_map_t)
  is
    path      varchar2(4000);
    
    procedure traverse(idx in pls_integer, path in varchar2 default null) is
    begin  
      
      case dir(idx).object_type
      when TYPE_STORAGE then -- storage
        if dir(idx).child_id != NOSTREAM then
          traverse(dir(idx).child_id, path || '/' || dir(idx).entry_name);
        end if;
      when TYPE_STREAM then -- stream
        path_map(path || '/' || dir(idx).entry_name) := idx;
      when TYPE_ROOT then -- root
        traverse(dir(idx).child_id);
      else
        null;
      end case;
      
      if dir(idx).left_sibling_id != NOSTREAM then
        traverse(dir(idx).left_sibling_id, path);
      end if;
      if dir(idx).right_sibling_id != NOSTREAM then
        traverse(dir(idx).right_sibling_id, path);
      end if;    
      
    end;
    
  begin
    traverse(0);    
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
    
    for i in 1 .. 109 loop
      file.difat(i) := to_int32(dbms_lob.substr(file.content, 4, 77 + 4 * (i - 1)));
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
    fat_array in int32_array_t
  , strt_sect in pls_integer
  )
  return int32_array_t
  is
    idx        pls_integer := 1;
    chain      int32_array_t;
    next_sect  pls_integer := strt_sect;
  begin
    while next_sect != ENDOFCHAIN loop
      chain(idx) := next_sect;
      next_sect := fat_array(next_sect);
      idx := idx + 1;
    end loop;
    return chain;
  end;
  
  procedure read_difat (
    file in out nocopy cdf_file_t
  )
  is
    offset           integer;
    amount           pls_integer := 4;
    buffer           raw(4);
    next_sect        pls_integer;
    sect_array_size  pls_integer; -- DIFAT sector array size
    idx              pls_integer;
  begin
    
    if file.header.difat_sect_cnt != 0 then
      
      sect_array_size := file.header.sect_size/4;
      next_sect := file.header.difat_strt_sect;
      idx := file.difat.last;
        
      while next_sect != ENDOFCHAIN loop
      
        offset := (next_sect + 1) * file.header.sect_size + 1;
        
        for i in 1 .. sect_array_size loop
          dbms_lob.read(file.content, amount, offset + 4*(i-1), buffer);
          next_sect := to_int32(buffer);
          if i < sect_array_size then
            idx := idx + 1;
            file.difat(idx) := next_sect; 
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
    amount           pls_integer := 4;
    buffer           raw(4);
    next_sect        pls_integer;
    sect_array_size  pls_integer := file.header.sect_size/4; -- FAT sector array size
    idx              pls_integer := 0;
  begin
            
    for j in 1 .. file.header.fat_sect_cnt loop
      
      next_sect := file.difat(j);
      offset := (next_sect + 1) * file.header.sect_size + 1;
              
      for i in 1 .. sect_array_size loop
        dbms_lob.read(file.content, amount, offset + 4*(i-1), buffer);
        file.fat(idx) := to_int32(buffer);
        idx := idx + 1;
      end loop;
      
    end loop;
    
  end;

  procedure read_minifat (
    file in out nocopy cdf_file_t
  )
  is
    offset           integer;
    amount           pls_integer := 4;
    buffer           raw(4);
    next_sect        pls_integer;
    sect_array_size  pls_integer := file.header.sect_size/4; -- MiniFAT sector array size
    chain            int32_array_t;
    idx              pls_integer := 0;
  begin
    
    chain := read_chain(file.fat, file.header.minifat_strt_sect);
        
    for j in 1 .. file.header.minifat_sect_cnt loop

      next_sect := chain(j);
      offset := (next_sect + 1) * file.header.sect_size + 1;
        
      for i in 1 .. sect_array_size loop
        dbms_lob.read(file.content, amount, offset + 4*(i-1), buffer);
        file.minifat(idx) := to_int32(buffer);
        idx := idx + 1;
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
    sector_array_size  pls_integer := file.header.sect_size/ENTRY_SIZE; -- directory sector array size
    chain              int32_array_t;
    entry_name_size    pls_integer;
    entry_id           pls_integer := 0;
  begin
    
    chain := read_chain(file.fat, file.header.dir_strt_sect);
    
    for j in 1 .. chain.count loop
      
      next_sect := chain(j);
      offset := (next_sect + 1) * file.header.sect_size + 1;
        
      for i in 1 .. sector_array_size loop
        
        entry_name_size := to_int32(dbms_lob.substr(file.content, 2, offset + 64));
        buffer := dbms_lob.substr(file.content, entry_name_size-2, offset);
        debug('entry name %d : %s', i, buffer);
        file.dir.entries(entry_id).entry_name       := utl_i18n.raw_to_char(buffer, 'AL16UTF16LE');
        file.dir.entries(entry_id).object_type      := dbms_lob.substr(file.content, 1, offset + 66);
        file.dir.entries(entry_id).color_flag       := dbms_lob.substr(file.content, 1, offset + 67);
        file.dir.entries(entry_id).left_sibling_id  := to_int32(dbms_lob.substr(file.content, 4, offset + 68));
        file.dir.entries(entry_id).right_sibling_id := to_int32(dbms_lob.substr(file.content, 4, offset + 72));
        file.dir.entries(entry_id).child_id         := to_int32(dbms_lob.substr(file.content, 4, offset + 76));
        file.dir.entries(entry_id).clsid            := dbms_lob.substr(file.content, 16, offset + 80);
        file.dir.entries(entry_id).creation_time    := dbms_lob.substr(file.content, 8, offset + 100);
        file.dir.entries(entry_id).modified_time    := dbms_lob.substr(file.content, 8, offset + 108);
        file.dir.entries(entry_id).strt_sect        := to_int32(dbms_lob.substr(file.content, 4, offset + 116));
        file.dir.entries(entry_id).stream_size      := to_int64(dbms_lob.substr(file.content, 8, offset + 120));
        
        offset := offset + ENTRY_SIZE;
        entry_id := entry_id + 1;
        
      end loop;
      
    end loop;
    
    file.header.ministream_strt_sect := file.dir.entries(0).strt_sect;
    
    if debug_mode then
      dump_dir(file.dir);
    end if;
    
    build_map(file.dir.entries, file.dir.path_map);   
    
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
    
    if not file.dir.path_map.exists(path) then
      error(-20702, ERR_NO_STREAM_FOUND);
    end if;
    idx := file.dir.path_map(path);
    
    stream_size := file.dir.entries(idx).stream_size;
    if skipped >= stream_size then
      error(-20703, ERR_INVALID_OFFSET, to_char(skipped), to_char(stream_size));
    end if;
    
    strt_sect := file.dir.entries(idx).strt_sect;
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
  
  function new_file (
    p_version  in pls_integer default V4 
  )
  return cdf_handle
  is
    cdf   cdf_file_t;
    hdl   cdf_handle;
  begin
    -- file version
    if p_version is null or p_version = V4 then
      cdf.header.major_version := '0400';
      cdf.header.sect_size := 4096;
    elsif p_version = V3 then
      cdf.header.major_version := '0300';
      cdf.header.sect_size := 512;
    else
      error(-20705, 'Invalid file version');
    end if;
    cdf.header.minor_version := '3E00';
    
    -- directory root entry
    add_entry(cdf.dir, 'Root Entry', TYPE_ROOT, null);
    
    hdl := nvl(cdf_cache.last,0) + 1;   
    cdf_cache(hdl) := cdf;
    return hdl;
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
      -- free file content
      if dbms_lob.istemporary(cdf_cache(p_hdl).content) = 1 then
        dbms_lob.freetemporary(cdf_cache(p_hdl).content);
      end if;
      -- free directory entries
      for i in 0 .. cdf_cache(p_hdl).dir.entries.last loop
        if dbms_lob.istemporary(cdf_cache(p_hdl).dir.entries(i).stream_content) = 1 then
          dbms_lob.freetemporary(cdf_cache(p_hdl).dir.entries(i).stream_content);
        end if;
      end loop;
      cdf_cache.delete(p_hdl);
    else
      error(-20701, ERR_INVALID_HANDLE);
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
      error(-20701, ERR_INVALID_HANDLE);
    end if;
    return cdf_cache(p_hdl).dir.path_map.exists(p_path);
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
      error(-20701, ERR_INVALID_HANDLE);
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
    dir_map := cdf_cache(hdl).dir.path_map;
    entry.path := dir_map.first;
    while entry.path is not null loop
      if regexp_like(entry.path, p_pattern) then
        idx := dir_map(entry.path);
        entry.creation_time := to_filetime(cdf_cache(hdl).dir.entries(idx).creation_time);
        entry.modified_time := to_filetime(cdf_cache(hdl).dir.entries(idx).modified_time);
        entry.stream := get_stream_int(cdf_cache(hdl), entry.path, 0);
        entry.stream_size := dbms_lob.getlength(entry.stream);
        pipe row (entry);
      end if;
      entry.path := dir_map.next(entry.path);
    end loop;
    close_file(hdl);    
    return;
  end;
  
  function get_file (
    p_hdl  in cdf_handle
  )
  return blob
  is
    file                     cdf_file_t := cdf_cache(p_hdl);
    
    entry_name               raw(64);
    entry                    cdf_dir_entry_t;
    entry_size               integer;
    entry_id                 pls_integer;
    unused_entry_count       pls_integer;
    
    array_size               pls_integer; -- multipurpose array size
    array_idx                pls_integer; -- multipurpose array index
    
    fat_array_size           pls_integer := 0; -- total number of FAT entries
    minifat_array_size       pls_integer := 0; -- total number of MiniFAT entries
    ministream_size          pls_integer := 0;
    ministream_sector_count  pls_integer := 0;
    stream_sector_count      pls_integer := 0;
    entry_sector_count       pls_integer := 0;
    
    difat_array_size         pls_integer; -- total number of DIFAT entries
    difat_array_size_tmp     pls_integer;
    
    output                   blob;
    sector_number            pls_integer := 0;
    minisector_number        pls_integer := 0;
    
    header_writer            writer_t;
    difat_writer             writer_t;
    fat_writer               writer_t;
    dir_writer               writer_t;
    minifat_writer           writer_t;
    ministream_writer        writer_t;
    stream_writer            writer_t;

    procedure write (writer in out nocopy writer_t, buf in raw) is
      buf_size  pls_integer := utl_raw.length(buf);
    begin
      dbms_lob.write(output, buf_size, writer.offset, buf);
      writer.offset := writer.offset + buf_size;
    end;
    
    procedure write_stream (
      writer   in out nocopy writer_t
    , content  in blob
    ) 
    is
      rem     integer := dbms_lob.getlength(content);
      amount  pls_integer := writer.sect_size;
      offset  integer := 1;
      buf     raw(4096);
    begin
      while rem != 0 loop
        dbms_lob.read(content, amount, offset, buf);
        offset := offset + amount;
        rem := rem - amount;
        write(writer, buf);
      end loop;
      -- align writer offset to next sector
      writer.offset := writer.offset + writer.sect_size - amount;
    end;
    
    procedure allocate_space (
      writer         in out nocopy writer_t
    , block_size     in pls_integer
    , block_cnt      in pls_integer default 1
    , block_default  in raw default '00000000'
    )
    is
      required  integer := block_size * block_cnt;
      rem       integer := required;
      buf       raw(32764) := utl_raw.copies(block_default, least(required/4, 8191));
      amount    pls_integer := utl_raw.length(buf);
    begin
      writer.offset := dbms_lob.getlength(output) + 1;
      writer.sect_size := block_size;
      loop
        dbms_lob.writeappend(output, amount, buf);
        rem := rem - amount;
        exit when rem = 0;
        amount := least(amount, rem);
      end loop;
    end;
    
    procedure set_chain (
      fat in out nocopy int32_array_t
    , sector_count in pls_integer
    , sector_number in out nocopy pls_integer
    )
    is
      strt_sect_num  pls_integer := sector_number;
    begin
      for i in 1 .. sector_count loop
        sector_number := sector_number + 1;
        if i < sector_count then
          fat(strt_sect_num + i - 1) := sector_number;
        else
          fat(strt_sect_num + i - 1) := ENDOFCHAIN;
        end if;
      end loop;
    end;
    
  begin
    
    file.header.byte_order := 'FEFF';
    file.header.mini_sect_size := 64;
    file.header.dir_sect_cnt := 0;  --unused in v3
    file.header.mini_size_cutoff := 4096;
    file.header.difat_sect_cnt := 0;
    
    -- For simplicity, required space for the DIFAT, FAT, directory, MiniFAT, MiniStream and regular streams
    -- is precalculated based on directory entries and sector size.
    -- Data is then written sequentially sector-wise in the output file.
    
    file.header.dir_sect_cnt := ceil(file.dir.entries.count * 128 / file.header.sect_size);
    unused_entry_count := file.header.dir_sect_cnt * (file.header.sect_size / 128) - file.dir.entries.count;
    
    for i in file.dir.entries.first .. file.dir.entries.last loop  
      if file.dir.entries(i).object_type = TYPE_STREAM then  
        entry_size := file.dir.entries(i).stream_size;
        if entry_size >= file.header.mini_size_cutoff then
          -- adding number of sector(s) required for this entry
          entry_sector_count := ceil(entry_size/file.header.sect_size);
          fat_array_size := fat_array_size + entry_sector_count;
        else
          -- adding number of minisector(s) required for this entry
          entry_sector_count := ceil(entry_size/file.header.mini_sect_size);
          minifat_array_size := minifat_array_size + entry_sector_count;
        end if;
        file.dir.entries(i).sect_cnt := entry_sector_count;
      end if;
    end loop;
    stream_sector_count := fat_array_size;
    
    -- adding number of sector(s) required for the MiniFAT
    file.header.minifat_sect_cnt := ceil(minifat_array_size * 4 / file.header.sect_size);
    fat_array_size := fat_array_size + file.header.minifat_sect_cnt;
    
    -- adding number of sector(s) required for the MiniStream
    ministream_size := minifat_array_size * file.header.mini_sect_size;
    ministream_sector_count := ceil(ministream_size / file.header.sect_size);
    fat_array_size := fat_array_size + ministream_sector_count;
    
    -- adding number of sector(s) required for the directory
    fat_array_size := fat_array_size + file.header.dir_sect_cnt;
    
    debug('initial fat_array_size = %d', fat_array_size);

    -- number of DIFAT entries required
    difat_array_size := ceil((fat_array_size * 4)/file.header.sect_size);
    debug('initial difat_array_size = %d', difat_array_size);
    
    if difat_array_size > 109 then
      loop
        debug('> iterate DIFAT allocation');
        -- last entry of DIFAT sector is for chaining
        file.header.difat_sect_cnt := ceil((difat_array_size - 109) * 4/(file.header.sect_size - 4));
        debug('  DIFAT sector count = %d', file.header.difat_sect_cnt);
        -- evaluating new DIFAT array size after including DIFAT sector(s) in the FAT
        difat_array_size_tmp := ceil(((fat_array_size + file.header.difat_sect_cnt) * 4)/file.header.sect_size);
        debug('  new DIFAT array size = %d', difat_array_size_tmp);
        -- stop if DIFAT array size does not change
        exit when difat_array_size_tmp = difat_array_size;
        -- else iterate
        difat_array_size := difat_array_size_tmp;
      end loop;
    end if;
    
    -- adding number of sector(s) required for the DIFAT
    fat_array_size := fat_array_size + file.header.difat_sect_cnt;
    file.header.fat_sect_cnt := difat_array_size;
    
    debug('minifat_array_size = %d', minifat_array_size);
    debug('fat_array_size = %d', fat_array_size);
    debug('difat_array_size = %d', difat_array_size);
    debug('difat_sector_count = %d', file.header.difat_sect_cnt);
    
    dbms_lob.createtemporary(output, true);
    
    -- allocate header space
    allocate_space(header_writer, file.header.sect_size);
    
    -- allocate DIFAT space
    if file.header.difat_sect_cnt != 0 then
      allocate_space(difat_writer, file.header.sect_size, file.header.difat_sect_cnt, to_bytes(FREESECT));
      file.header.difat_strt_sect := sector_number;
    end if;
    
    -- allocate FAT space
    allocate_space(fat_writer, file.header.sect_size, file.header.fat_sect_cnt, to_bytes(FREESECT));
    
    -- mark DIFAT sectors in the FAT
    for i in 1 .. file.header.difat_sect_cnt loop
      file.fat(sector_number) := DIFSECT;
      sector_number := sector_number + 1;
    end loop;
    
    -- mark FAT sectors in the FAT and set FAT sectors in DIFAT
    for i in 1 .. file.header.fat_sect_cnt loop
      file.fat(sector_number) := FATSECT;
      file.difat(i) := sector_number;
      sector_number := sector_number + 1;
    end loop;
    
    -- allocate directory space
    allocate_space(dir_writer, file.header.sect_size, file.header.dir_sect_cnt);
    file.header.dir_strt_sect := sector_number;
    -- set dir chain
    set_chain(file.fat, file.header.dir_sect_cnt, sector_number);
    
    -- allocate MiniFAT space
    if file.header.minifat_sect_cnt != 0 then
      
      allocate_space(minifat_writer, file.header.sect_size, file.header.minifat_sect_cnt);
      file.header.minifat_strt_sect := sector_number;
      -- set minifat chain
      set_chain(file.fat, file.header.minifat_sect_cnt, sector_number);
      
      -- allocate MiniStream space
      allocate_space(ministream_writer, file.header.mini_sect_size, ministream_sector_count * file.header.sect_size / file.header.mini_sect_size);
      file.header.ministream_strt_sect := sector_number;
      -- set ministream chain
      set_chain(file.fat, ministream_sector_count, sector_number);
      
    else
      
      file.header.minifat_strt_sect := ENDOFCHAIN;
      file.header.ministream_strt_sect := ENDOFCHAIN;
    
    end if;
    -- set ministream info in directory root entry
    file.dir.entries(0).strt_sect := file.header.ministream_strt_sect;
    file.dir.entries(0).stream_size := ministream_size;
    
    -- allocate normal stream space
    if stream_sector_count != 0 then
      allocate_space(stream_writer, file.header.sect_size, stream_sector_count);
    end if;
    
    -- write data streams
    for i in file.dir.entries.first .. file.dir.entries.last loop
      
      if file.dir.entries(i).object_type = TYPE_STREAM then
        entry_size := file.dir.entries(i).stream_size;
        if entry_size >= file.header.mini_size_cutoff then
          file.dir.entries(i).strt_sect := sector_number;
          write_stream(stream_writer, file.dir.entries(i).stream_content);
          set_chain(file.fat, file.dir.entries(i).sect_cnt, sector_number);
        else
          file.dir.entries(i).strt_sect := minisector_number;
          write_stream(ministream_writer, file.dir.entries(i).stream_content);
          set_chain(file.minifat, file.dir.entries(i).sect_cnt, minisector_number);
        end if;
      end if;
      
    end loop;
    
    -- -----------------------------------------------------------------
    -- write DIFAT
    -- -----------------------------------------------------------------
    -- First 109 entries are stored in the header
    for i in 1 .. least(file.difat.count, 109) loop
      file.header.difat(i) := file.difat(i);
    end loop;
    -- Mark remaining header slots (if any) as free
    for i in least(file.difat.count, 109) + 1 .. 109 loop
      file.header.difat(i) := FREESECT;
    end loop;
    
    -- last entry of a DIFAT sector is a pointer to the next sector, 
    -- except for the last one which must be ENDOFCHAIN
    array_size := file.header.sect_size / 4 - 1; -- number of FAT sectors per DIFAT sector
    array_idx := 0; -- array index into a single DIFAT sector
    sector_number := file.header.difat_strt_sect;
    
    for i in 110 .. file.difat.count loop
      write(difat_writer, to_bytes(file.difat(i)));
      array_idx := array_idx + 1;
      if array_idx = array_size then
        if i != file.difat.count then
          -- write pointer to next DIFAT sector
          sector_number := sector_number + 1;
          write(difat_writer, to_bytes(sector_number));
          array_idx := 0;
        end if;
      end if;
    end loop;
    
    -- write ENDOFCHAIN
    if file.header.difat_sect_cnt != 0 then
      -- jump to last sector entry
      difat_writer.offset := difat_writer.offset + (array_size - array_idx) * 4;
      write(difat_writer, to_bytes(ENDOFCHAIN));
    else
      file.header.difat_strt_sect := ENDOFCHAIN;
    end if;
    
    -- -----------------------------------------------------------------
    -- write FAT
    -- -----------------------------------------------------------------
    for i in file.fat.first .. file.fat.last loop
      write(fat_writer, to_bytes(file.fat(i)));
    end loop;
    
    -- -----------------------------------------------------------------
    -- write directory
    -- -----------------------------------------------------------------
    if unused_entry_count != 0 then
      entry := new_entry(TYPE_UNKNOWN);
      entry_id := file.dir.entries.last;
      -- filling remaining of last dir sector with unused entries
      for i in 1 .. unused_entry_count loop
        file.dir.entries(entry_id + i) := entry;
      end loop;
    end if;
    
    for i in file.dir.entries.first .. file.dir.entries.last loop
      
      entry := file.dir.entries(i);
      if entry.entry_name is not null then
        entry_name := utl_i18n.string_to_raw(entry.entry_name || chr(0), 'AL16UTF16LE');
        write(dir_writer, utl_raw.overlay(entry_name, utl_raw.copies('00',64)));
        write(dir_writer, to_bytes(utl_raw.length(entry_name), 2));
      else
        write(dir_writer, utl_raw.copies('00',64));
        write(dir_writer, to_bytes(0, 2));        
      end if;
      write(dir_writer, entry.object_type);
      write(dir_writer, entry.color_flag);
      write(dir_writer, to_bytes(entry.left_sibling_id));
      write(dir_writer, to_bytes(entry.right_sibling_id));
      write(dir_writer, to_bytes(entry.child_id));
      write(dir_writer, entry.clsid);
      write(dir_writer, '00000000'); -- State Bits
      write(dir_writer, entry.creation_time);
      write(dir_writer, entry.modified_time);
      write(dir_writer, to_bytes(entry.strt_sect));
      write(dir_writer, to_bytes(entry.stream_size,8));
    
    end loop;

    -- -----------------------------------------------------------------
    -- write MiniFAT
    -- -----------------------------------------------------------------
    for i in file.minifat.first .. file.minifat.last loop
      write(minifat_writer, to_bytes(file.minifat(i)));
    end loop;
    
    -- -----------------------------------------------------------------
    -- write header
    -- -----------------------------------------------------------------
    write(header_writer, SIGNATURE);
    write(header_writer, utl_raw.copies('00',16)); -- CLSID
    write(header_writer, file.header.minor_version);
    write(header_writer, file.header.major_version);
    write(header_writer, file.header.byte_order);
    write(header_writer, to_bytes(log(2, file.header.sect_size), 2)); -- Sector Shift
    write(header_writer, to_bytes(log(2, file.header.mini_sect_size), 2)); -- Mini Sector Shift
    write(header_writer, '000000000000'); -- Reserved
    if file.header.major_version = '0400' then
      write(header_writer, to_bytes(file.header.dir_sect_cnt));
    else
      write(header_writer, '00000000');
    end if;
    write(header_writer, to_bytes(file.header.fat_sect_cnt));
    write(header_writer, to_bytes(file.header.dir_strt_sect));
    write(header_writer, '00000000'); -- Transaction Signature Number
    write(header_writer, to_bytes(file.header.mini_size_cutoff));
    write(header_writer, to_bytes(file.header.minifat_strt_sect));
    write(header_writer, to_bytes(file.header.minifat_sect_cnt));
    write(header_writer, to_bytes(file.header.difat_strt_sect));
    write(header_writer, to_bytes(file.header.difat_sect_cnt));
    for i in 1 .. 109 loop
      write(header_writer, to_bytes(file.header.difat(i)));
    end loop;
    
    return output;

  end;

  procedure write_blob (
    p_directory  in varchar2
  , p_filename   in varchar2
  , p_content    in blob
  )
  is
    MAX_BUF_SIZE  constant pls_integer := 32767;
    file       utl_file.file_type;
    pos        integer := 1;
    chunkSize  pls_integer := dbms_lob.getchunksize(p_content);
    amt        pls_integer := least(trunc(MAX_BUF_SIZE/chunkSize)*chunkSize, MAX_BUF_SIZE);
    buf        raw(32767);
  begin
    file := utl_file.fopen(p_directory, p_filename, 'wb', 32767);
    loop
      begin
        dbms_lob.read(p_content, amt, pos, buf);
      exception
        when no_data_found then
          exit;
      end;
      utl_file.put_raw(file, buf);
      pos := pos + amt;
    end loop;
    utl_file.fclose(file);
  end;
  
  procedure write_file (
    p_hdl        in cdf_handle
  , p_directory  in varchar2
  , p_filename   in varchar2 
  )
  is
    output  blob;
  begin
    output := get_file(p_hdl);
    close_file(p_hdl);
    write_blob(p_directory, p_filename, output);
    dbms_lob.freetemporary(output);
  end;

end xutl_cdf;
/
