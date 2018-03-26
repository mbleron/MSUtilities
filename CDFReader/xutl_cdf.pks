create or replace package xutl_cdf is
/* ======================================================================================

  MIT License

  Copyright (c) 2017 Marc Bleron

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
    Marc Bleron       2017-05-08     Creation
    Marc Bleron       2017-05-25     Fixed get_stream offset bug
                                     Refactored exception numbers
====================================================================================== */

  invalid_handle   exception;
  pragma exception_init(invalid_handle, -20701);
  
  no_stream_found  exception;
  pragma exception_init(no_stream_found, -20702);
  
  invalid_stream_offset  exception;
  pragma exception_init(invalid_stream_offset, -20703);

  subtype cdf_handle is pls_integer;
  
  type entry_t is record (
    path           varchar2(4000)
  , stream_size    integer
  , creation_time  date
  , modified_time  date
  , stream         blob
  );
  
  type entry_list_t is table of entry_t;
  
  function is_cdf (p_file in blob) return boolean;

  function open_file (p_file in blob)
  return cdf_handle;
  
  function get_stream (
    p_hdl    in cdf_handle
  , p_path   in varchar2
  , p_offset in integer default 0
  )
  return blob;
  
  function get_stream (
    p_file   in blob
  , p_path   in varchar2
  , p_offset in integer default 0
  )
  return blob;
  
  function get_streams (
    p_file    in blob
  , p_pattern in varchar2 default '*'
  )
  return entry_list_t pipelined;
  
  procedure close_file (p_hdl in cdf_handle);
  procedure set_debug (p_mode in boolean);

end xutl_cdf;
/
