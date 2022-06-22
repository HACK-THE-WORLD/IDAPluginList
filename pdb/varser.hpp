
#ifndef VARSER_HPP
#define VARSER_HPP

// Variant serializer/deserializer.
struct varser_t
{
#ifdef __NT__
  static bool serialize(bytevec_t &out, const VARIANT &var);
#else
  static bool deserialize(VARIANT &var, const uchar **in, const uchar *const end);
#endif
};

#ifdef __NT__
//-------------------------------------------------------------------------
bool varser_t::serialize(bytevec_t &out, const VARIANT &var)
{
  out.pack_dw(var.vt);
  if ( (var.vt & VT_BYREF) == VT_BYREF
    || (var.vt & VT_ARRAY) == VT_ARRAY )
  {
    return false;
  }

  const size_t sz_before = out.size();
  switch ( var.vt )
  {
    case VT_EMPTY: // = 0x0000,
    case VT_NULL: // = 0x0001,
      break;
    case VT_I2: // = 0x0002,
    case VT_UI2: // = 0x0012,
      out.pack_dw(var.uiVal);
      break;
    case VT_I4: // = 0x0003,
    case VT_UI4: // = 0x0013,
      out.pack_dd(var.ulVal);
      break;
    case VT_R4: // = 0x0004,
      out.pack_dd(*(uint32*)&var.fltVal);
      break;
    case VT_R8: // = 0x0005,
      out.pack_dq(*(uint64*)&var.dblVal);
      break;
    case VT_CY: // = 0x0006,
    case VT_DATE: // = 0x0007,
      break;
    case VT_BSTR: // = 0x0008,
      {
        uint8 *ptr = (uint8*) var.bstrVal;
        ptr -= 4;
        uint32 bcnt = * (uint32*) ptr;
        out.pack_buf(ptr + 4, bcnt);
      }
      break;
    case VT_DISPATCH: // = 0x0009,
    case VT_ERROR: // = 0x000A,
    case VT_BOOL: // = 0x000B,
    case VT_VARIANT: // = 0x000C,
    case VT_UNKNOWN: // = 0x000D,
    case VT_DECIMAL: // = 0x000E,
    case VT_I1: // = 0x0010,
    case VT_UI1: // = 0x0011,
      out.pack_db(var.bVal);
      break;
    case VT_I8: // = 0x0014,
    case VT_UI8: // = 0x0015,
      out.pack_dq(var.ullVal);
      break;
    case VT_INT: // = 0x0016,
    case VT_UINT: // = 0x0017,
    case VT_HRESULT: // = 0x0019,
      out.pack_dd(var.uintVal);
      break;
    case VT_VOID: // = 0x0018,
    case VT_PTR: // = 0x001A,
    case VT_SAFEARRAY: // = 0x001B,
    case VT_CARRAY: // = 0x001C,
    case VT_USERDEFINED: // = 0x001D,
    case VT_LPSTR: // = 0x001E,
    case VT_LPWSTR: // = 0x001F,
    case VT_RECORD: // = 0x0024,
    case VT_INT_PTR: // = 0x0025,
    case VT_UINT_PTR: // = 0x0026,
      break;
    default: break;
  }
  return out.size() > sz_before;
}
#else
//-------------------------------------------------------------------------
bool varser_t::deserialize(VARIANT &var, const uchar **in, const uchar *const end)
{
  var.vt = unpack_dw(in, end);
  if ( (var.vt & VT_BYREF) == VT_BYREF
    || (var.vt & VT_ARRAY) == VT_ARRAY )
  {
    return false;
  }

  bool ok = false;
  switch ( var.vt )
  {
    case VT_EMPTY: // = 0x0000,
    case VT_NULL: // = 0x0001,
      break;
    case VT_I2: // = 0x0002,
    case VT_UI2: // = 0x0012,
      var.uiVal = unpack_dw(in, end);
      ok = true;
      break;
    case VT_I4: // = 0x0003,
    case VT_UI4: // = 0x0013,
      var.ulVal = unpack_dd(in, end);
      ok = true;
      break;
    case VT_R4: // = 0x0004,
      {
        uint32 res = unpack_dd(in, end);
        var.fltVal = *(FLOAT*)&res;
        ok = true;
      }
      break;
    case VT_R8: // = 0x0005,
      {
        uint64 res = unpack_dq(in, end);
        var.dblVal = *(DOUBLE*)&res;
        ok = true;
      }
      break;
    case VT_CY: // = 0x0006,
    case VT_DATE: // = 0x0007,
      break;
    case VT_BSTR: // = 0x0008,
      {
        uint32 bcnt = unpack_dd(in, end);
        uint32 nbytes = bcnt + 4 + 2; // +2 for terminating null character
        QASSERT(30472, nbytes > bcnt); // check for integer overflow
        uint8 *raw = (uint8 *)qalloc(nbytes);
        if ( raw != nullptr )
        {
          *(uint32*)raw = bcnt;
          raw += 4;
          unpack_obj(raw, bcnt, in, end);
          raw[bcnt] = '\0';
          raw[bcnt+1] = '\0';
          var.bstrVal = raw;
          ok = true;
        }
      }
      break;
    case VT_LPSTR: // = 0x001E,
    case VT_LPWSTR: // = 0x001F,
      {
        char *tmp = qstrdup(unpack_str(in, end));
        var.byref = tmp;
        ok = true;
      }
      break;
    case VT_DISPATCH: // = 0x0009,
    case VT_ERROR: // = 0x000A,
    case VT_BOOL: // = 0x000B,
    case VT_VARIANT: // = 0x000C,
    case VT_UNKNOWN: // = 0x000D,
    case VT_DECIMAL: // = 0x000E,
    case VT_I1: // = 0x0010,
    case VT_UI1: // = 0x0011,
      var.bVal = unpack_db(in, end);
      ok = true;
      break;
    case VT_I8: // = 0x0014,
    case VT_UI8: // = 0x0015,
      var.ullVal = unpack_dq(in, end);
      ok = true;
      break;
    case VT_INT: // = 0x0016,
    case VT_UINT: // = 0x0017,
    case VT_HRESULT: // = 0x0019,
      var.uintVal = unpack_dd(in, end);
      ok = true;
      break;
    case VT_VOID: // = 0x0018,
    case VT_PTR: // = 0x001A,
    case VT_SAFEARRAY: // = 0x001B,
    case VT_CARRAY: // = 0x001C,
    case VT_USERDEFINED: // = 0x001D,
    case VT_RECORD: // = 0x0024,
    case VT_INT_PTR: // = 0x0025,
    case VT_UINT_PTR: // = 0x0026,
      break;
    default: break;
  }
  return ok;
}
#endif // __NT__

#endif // VARSER_HPP
