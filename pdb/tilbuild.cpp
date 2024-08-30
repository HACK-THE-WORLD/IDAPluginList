
#include "tilbuild.hpp"
#include "misc.cpp"

//#define PDEB
//#define PDEBSYM
#ifdef PDEB
#define ddeb(x) _ddeb x
AS_PRINTF(1, 2) inline void _ddeb(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vmsg(format, va);
  va_end(va);
}

void dump_pdb_udt(const pdb_udt_type_data_t &udt, const char *udt_name)
{
  static size_t udt_counter = 0;
  ++udt_counter;
  msg("PDEB: %" FMT_Z " struct '%s' total_size %" FMT_Z " taudt_bits 0x%X is_union %s\n",
      udt_counter,
      udt_name != nullptr ? udt_name : "",
      udt.total_size,
      udt.taudt_bits,
      udt.is_union ? "Yes" : "No");
  for ( int i=0; i < udt.size(); i++ )
  {
    const pdb_udm_t &zudm = udt[i];
    msg("  %d. offset 0x%" FMT_64 "X size 0x%" FMT_64 "X '%s' type '%s' effalign %d tafld_bits 0x%X fda %d bit_offset %u\n",
        i,
        zudm.offset,
        zudm.size,
        zudm.name.c_str(),
        zudm.type.dstr(),
        zudm.effalign,
        zudm.tafld_bits,
        zudm.fda,
        zudm.bit_offset);
  }
}
#else
#define ddeb(x) (void)0
void dump_pdb_udt(const pdb_udt_type_data_t &, const char *) {}
#endif

static const char fake_vtable_type[] = "$vt";

//----------------------------------------------------------------------------
void til_builder_t::remove_anonymous_namespaces(qstring &buf)
{
  char *p = buf.begin();
  while ( true )
  {             // 1234567890
    p = strstr(p, "`anonymous");
    if ( p == nullptr )
      break;
    const char *q = p + 10;
    if ( *q != '-' && *q != ' ' )
      break;
    if ( strncmp(q+1, "namespace'::", 12) != 0 )
      break;      // 123456789012
    size_t idx = p - buf.begin();
    buf.remove(idx, 10+1+12);
    p = buf.begin() + idx;
  }
}

//-------------------------------------------------------------------------
static inline bool ident_char(char c)
{
  return c == '_' || qisalnum(c);
}

//----------------------------------------------------------------------------
bool til_builder_t::get_symbol_name(pdb_sym_t &sym, qstring &buf)
{
  bool is_unnamed = false;
  sym.get_name(&buf);
  if ( buf.empty() )
  {
    is_unnamed = true;
  }
  else
  {
    //
    remove_anonymous_namespaces(buf);

    // <unnamed-tag>  => <unnamed_tag>
    // <unnamed-type-xxx> => <unnamed_type_xxx>
    char *p = buf.begin();
    while ( true )
    {
      //             012345678
      p = strstr(p, "<unnamed");
      if ( p == nullptr )
        break;
      if ( p == buf.begin() )
        is_unnamed = true;
      p += 8;
      while ( *p != '\0' )
      {
        if ( *p == '>' )
        {
          p++;
          break;
        }
        else if ( *p == '-' )
        {
          *p = '_';
        }
        p++;
      }
    }
    if ( !is_unnamed )
    {
      const char *marker = strstr(buf.begin(), "__unnamed");
      if ( marker != nullptr
        // Is prev char not a valid identifier char?
        && (marker == buf.begin() || !ident_char(marker[-1]))
        // Is next char not a valid identifier char?
        && !ident_char(marker[9]) )
      {
        is_unnamed = true;
      }
    }
  }
  return is_unnamed;
}

//----------------------------------------------------------------------------
bool til_builder_t::get_symbol_type(tpinfo_t *out, pdb_sym_t &sym, uint32 *p_ord)
{
#ifdef PDEBSYM
  static int zz=0; ++zz;
  int zzz = zz;
  qstring sym_name;
  sym.get_name(&sym_name);
  DWORD sym_id = 0;
  sym.get_symIndexId(&sym_id);
  msg("PDEB: %d: get_symbol_type sym_id=%d '%s'\n", zzz, sym_id, sym_name.c_str());
#endif
  pdb_sym_t *pType = pdb_access->create_sym();
  pdb_sym_janitor_t janitor_pType(pType);
  if ( sym.get_type(pType) != S_OK )
    return false;
  bool ok = retrieve_type(out, *pType, nullptr, p_ord);
#ifdef PDEBSYM
  DWORD typsym_id = 0;
  pType->get_symIndexId(&typsym_id);
  msg("PDEB: %d: get_symbol_type typsym_id=%d tif='%s' ok=%d\n", zzz, typsym_id, out->type.dstr(), ok);
#endif
  return ok;
}

//----------------------------------------------------------------------------
size_t til_builder_t::get_symbol_type_length(pdb_sym_t &sym) const
{
  DWORD64 size = 0;
  DWORD tag = 0;

  sym.get_symTag(&tag);
  if ( tag == SymTagData )
  {
    pdb_sym_t *pType = pdb_access->create_sym();
    pdb_sym_janitor_t janitor_pType(pType);
    if ( sym.get_type(pType) == S_OK )
      pType->get_length(&size);
  }
  else
  {
    sym.get_length(&size);
  }
  return size_t(size);
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::convert_basetype(
        tpinfo_t *out,
        DWORD baseType,
        int size) const
{
  type_t bt = BTF_TYPEDEF;
  const char *name = nullptr;
  switch ( baseType )
  {
    case btNoType:
      out->is_notype = true;
      // Fallthrough.
    default:
    case 0x12c304:                      // "impdir_entry" (guessed)
    case btBCD:
    case btBit:
      return cvt_failed;
    case btVoid:
      bt = BTF_VOID;
      break;
    case btChar:
      bt = BT_INT8|BTMT_CHAR;
      break;
    case btBool:
      bt = BT_BOOL;
      if ( size != inf_get_cc_size_b() )
      {
        switch ( size )
        {
          case 1:
            bt |= BTMT_BOOL1;
            break;
          case 2:
            if ( inf_is_64bit() )
              goto MAKE_INT; // 64bit apps do not have BOOL2
            bt |= BTMT_BOOL2;
            break;
          case 4:
            bt |= BTMT_BOOL4;
            break;
          case 8:
            if ( !inf_is_64bit() )
              goto MAKE_INT; // 32bit apps do not have BOOL8
            bt |= BTMT_BOOL8;
            break;
          default:
            // can't make this bool size; make an int
            goto MAKE_INT;
        }
      }
      break;
MAKE_INT:
    case btInt:
    case btLong:
      bt = get_scalar_bt(size);
      if ( bt == BT_UNK )
        return cvt_failed;
      break;
    case btUInt:
    case btULong:
      if ( size == 1 )
      {
        bt = BTF_UCHAR; // get_scalar_bt returns 'char', or'ing it with BTMT_USIGNED
                        // does not help
      }
      else
      {
        bt = get_scalar_bt(size);
        if ( bt == BT_UNK )
          return cvt_failed;
        bt |= BTMT_USIGNED;
      }
      break;
    case btFloat:
      if ( size == pv.ph.sizeof_ldbl() )
      {
        bt = BTMT_LNGDBL;
      }
      else
      {
        switch ( size )
        {
          case 4:  bt = BTMT_FLOAT;   break;
          default:
          case 8:  bt = BTMT_DOUBLE;  break;
          case 10: bt = BTMT_SPECFLT; break;
        }
      }
      bt |= BT_FLOAT;
      break;
    case btWChar:    name = "wchar_t";                         break;
    case btBSTR:     name = "BSTR";                            break;
    case btHresult:  name = "HRESULT";                         break;
    case btCurrency: name = "CURRENCY";                        break;
    case btVariant:  name = "VARIANT";                         break;
    case btComplex:  name = "complex";                         break;
    case btDate:     name = "DATE";                            break;
  }
  if ( name != nullptr )
  {
    out->type.create_typedef(ti, name);
    return cvt_typedef;
  }
  else
  {
    out->type = tinfo_t(bt);
    return cvt_ok;
  }
}

//----------------------------------------------------------------------
bool til_builder_t::retrieve_arguments(
        pdb_sym_t &_sym,
        func_type_data_t &fi,
        pdb_sym_t *funcSym)
{
  struct type_name_collector_t : public pdb_access_t::children_visitor_t
  {
    func_type_data_t &fi;
    til_builder_t *tb;
    til_t *ti;
    HRESULT visit_child(pdb_sym_t &sym) override
    {
      // check that it's a parameter
      DWORD dwDataKind;
      if ( sym.get_dataKind(&dwDataKind) == S_OK
        && dwDataKind != DataIsParam
        && dwDataKind != DataIsObjectPtr )
      {
        return S_OK;
      }
      tpinfo_t tpi;
      bool cvt_succeeded = tb->retrieve_type(&tpi, sym, parent);
      if ( cvt_succeeded || tpi.is_notype )
      {
        funcarg_t &arg = fi.push_back();
        arg.type = tpi.type;
        sym.get_name(&arg.name);
      }
      return S_OK;
    }
    type_name_collector_t(til_t *_ti, til_builder_t *_tb, func_type_data_t &_fi)
      : fi(_fi), tb(_tb), ti(_ti) {}
  };
  fi.clear();
  type_name_collector_t pp(ti, this, fi);
  HRESULT hr = pdb_access->iterate_children(_sym, SymTagNull, pp);
  if ( hr == S_OK && funcSym != nullptr )
  {
    // get parameter names from the function symbol
    func_type_data_t args;
    args.flags = 0;
    enum_function_args(*funcSym, args);
//    QASSERT(497, args.empty() || args.size() == fi.size() );
    bool custom_cc = false;
    for ( int i = 0; i < fi.size(); i++ )
    {
      if ( i < args.size() )
      {
        if ( fi[i].name.empty() )
          fi[i].name = args[i].name;
        argloc_t &cur_argloc = args[i].argloc;
        fi[i].argloc = cur_argloc;
        if ( !custom_cc && cur_argloc.is_reg1() )
        {
          if ( is_intel386(pdb_access->get_machine_type()) )
          {
            if ( (fi.cc == CM_CC_FASTCALL
               || fi.cc == CM_CC_SWIFT) // FIXME
              && cur_argloc.regoff() == 0
              && (cur_argloc.reg1() == R_cx && i == 0
               || cur_argloc.reg1() == R_dx && i == 1) )
            {
              // ignore ecx and edx for fastcall
            }
            else if ( fi.cc == CM_CC_THISCALL
                   && cur_argloc.regoff() == 0
                   && cur_argloc.reg1() == R_cx && i == 0 )
            {
              // ignore ecx for thiscall
            }
            else
            {
              custom_cc = true;
            }
          }
        }
        //ask_for_feedback("pdb: register arguments are not supported for machine type %d", machine_type);
      }
    }
    if ( custom_cc )
    {
      // we have some register params; need to convert function to custom cc
      CASSERT(is_purging_cc(CM_CC_THISCALL));
      CASSERT(is_purging_cc(CM_CC_FASTCALL));
      fi.cc = is_purging_cc(fi.cc) ? CM_CC_SPECIALP : CM_CC_SPECIAL;
    }
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
cm_t til_builder_t::convert_cc(DWORD cc0) const
{
  switch ( cc0 )
  {
    case CV_CALL_GENERIC    :
    case CV_CALL_NEAR_C     :
    case CV_CALL_FAR_C      :
      return inf_is_64bit() ? CM_CC_FASTCALL : CM_CC_CDECL;
    case CV_CALL_NEAR_PASCAL:
    case CV_CALL_FAR_PASCAL : return CM_CC_PASCAL;
    case CV_CALL_NEAR_FAST  :
    case CV_CALL_FAR_FAST   : return CM_CC_FASTCALL;
//    case CV_CALL_SKIPPED    :
    case CV_CALL_NEAR_STD   :
    case CV_CALL_FAR_STD    :
    case CV_CALL_ARMCALL    : return CM_CC_STDCALL;
    case CV_CALL_THISCALL   : return CM_CC_THISCALL;
//    case CV_CALL_NEAR_SYS   :
//    case CV_CALL_FAR_SYS    :
//    case CV_CALL_MIPSCALL   :
//    case CV_CALL_ALPHACALL  :
//    case CV_CALL_PPCCALL    :
//    case CV_CALL_SHCALL     :
//    case CV_CALL_ARMCALL    :
//    case CV_CALL_AM33CALL   :
//    case CV_CALL_TRICALL    :
//    case CV_CALL_SH5CALL    :
//    case CV_CALL_M32RCALL   :
  }
  return CM_CC_UNKNOWN;
}

//----------------------------------------------------------------------
bool til_builder_t::get_variant_string_value(qstring *out, pdb_sym_t &sym) const
{
  bool ok = false;
  VARIANT value;
  VariantInit(&value);
  if ( sym.get_value(&value) == S_OK )
  {
    if ( value.vt == VT_BSTR )
    {
      utf16_utf8(out, (wchar16_t*) value.bstrVal);
      ok = true;
    }
    else if ( value.vt == VT_LPSTR )
    {
      qstring str((const char *)value.byref);
      out->swap(str);
      ok = true;
    }
  }
  VariantClear(&value);
  return ok;
}

//----------------------------------------------------------------------
uint32 til_builder_t::get_variant_long_value(pdb_sym_t &sym) const
{
  uint32 v = 0;
  VARIANT value;
  VariantInit(&value);
  if ( sym.get_value(&value) == S_OK )
  {
    switch ( value.vt )
    {
      case VT_I1:   v = value.cVal; break;
      case VT_I2:   v = value.iVal; break;
      case VT_I4:   v = value.lVal; break;
      case VT_I8:   v = value.llVal; break;
      case VT_INT:  v = value.intVal; break;
      case VT_UI1:  v = value.bVal; break;
      case VT_UI2:  v = value.uiVal; break;
      case VT_UI4:  v = value.ulVal; break;
      case VT_UI8:  v = value.ullVal; break;
      case VT_UINT: v = value.uintVal; break;
      default:
        ask_for_feedback("pdb: unsupported VARIANT type %d", value.vt);
        break;
    }
  }
  VariantClear(&value);
  return v;
}

//----------------------------------------------------------------------
// funcSym is Function, typeSym is FunctionType
bool til_builder_t::is_member_func(tinfo_t *class_type, pdb_sym_t &typeSym, pdb_sym_t *funcSym)
{
  // make sure we retrieve class type first
  pdb_sym_t *pParent = pdb_access->create_sym();
  pdb_sym_janitor_t janitor_pParent(pParent);
  if ( typeSym.get_classParent(pParent) != S_OK || pParent->empty() )
    return false;

  tpinfo_t tpi;
  if ( !retrieve_type(&tpi, *pParent, nullptr) )
    return false; // failed to retrieve the parent's type

  class_type->swap(tpi.type);

  // then check if it's static
  if ( funcSym != nullptr
    && pdb_access->get_dia_version() >= 800 )
  {
    BOOL bIsStatic = false;
    HRESULT hr = funcSym->get_isStatic(&bIsStatic);
    if ( hr == S_OK )
      return !bIsStatic;
  }
  return true;
}

//----------------------------------------------------------------------
bool til_builder_t::is_stack_reg(int reg) const
{
  return reg == get_stack_reg(pdb_access->get_machine_type());
}

//----------------------------------------------------------------------
bool til_builder_t::is_frame_reg(int reg) const
{
  if (pdb_access->get_dia_version() >= 1400 && is_intel386(pdb_access->get_machine_type()))
  {
    return reg == CV_ALLREG_VFRAME;
  }
  return reg == get_frame_reg(pdb_access->get_machine_type());
}

//----------------------------------------------------------------------------
int til_builder_t::get_symbol_funcarg_info(
        funcarg_t *out,
        pdb_sym_t &sym,
        DWORD /*dwDataKind*/,
        DWORD locType,
        int stack_off)
{
  sym.get_name(&out->name);
  tpinfo_t tpi;
  get_symbol_type(&tpi, sym);
  out->type = tpi.type;
  if ( locType == LocIsEnregistered )
  {
    DWORD dwReg;
    if ( sym.get_registerId(&dwReg) == S_OK )
    {
      if ( enregistered_bug && dwReg > 0 )
        dwReg--;
      qstring regname;
      print_pdb_register(&regname, pdb_access->get_machine_type(), dwReg);
      out->argloc._set_reg1(str2reg(regname.c_str()));
    }
  }
  else if ( locType == LocIsRegRel )
  {
    DWORD dwReg;
    LONG lOffset;
    if ( sym.get_registerId(&dwReg) == S_OK
      && sym.get_offset(&lOffset) == S_OK
      && (is_frame_reg(dwReg) || is_stack_reg(dwReg)) )
    {
      uint32 align;
      out->argloc._set_stkoff(stack_off);
      size_t argsz = out->type.get_size(&align);
      if ( align > argsz )
        argsz = align;
      stack_off += argsz;
    }
  }
  else
  {
    ask_for_feedback("pdb: unsupported location type %d", locType);
  }
  return stack_off;
}

//----------------------------------------------------------------------
void til_builder_t::enum_function_args(pdb_sym_t &_sym, func_type_data_t &args)
{
  // enumerate all function parameters and gather their names
  struct param_enumerator_t : public pdb_access_t::children_visitor_t
  {
    func_type_data_t &args;
    til_builder_t *tb;
    int stack_off;
    virtual HRESULT visit_child(pdb_sym_t &sym) override
    {
      DWORD tag = 0;
      HRESULT hr = sym.get_symTag(&tag);
      if ( FAILED(hr) )
        return hr;

      switch ( tag )
      {
        case SymTagBlock: // nested blocks
          return tb->pdb_access->iterate_children(sym, SymTagNull, *this);
        case SymTagFuncDebugStart:
        case SymTagFuncDebugEnd:
          return S_OK;    // ignore these for the moment
      }

      DWORD dwDataKind, locType;
      if ( sym.get_dataKind(&dwDataKind) == S_OK
        && dwDataKind == DataIsParam
        && sym.get_locationType(&locType) == S_OK )
      {
        funcarg_t &fa = args.push_back();
        stack_off = tb->get_symbol_funcarg_info(&fa, sym, dwDataKind, locType, stack_off);
      }
      return S_OK; // continue enumeration
    }
    param_enumerator_t(func_type_data_t &_args, til_builder_t *_tb)
      : args(_args), tb(_tb), stack_off(0) {}
  };
  param_enumerator_t pen(args, this);
  pdb_access->iterate_children(_sym, SymTagData, pen);
}

//----------------------------------------------------------------------
// corrupted PDB may produce the strange results
cvt_code_t til_builder_t::verify_struct(pdb_udt_type_data_t &udt) const
{
  for ( auto &udm : udt )
  {
    if ( !udm.is_bitfield() && (udm.offset % 8) != 0 )
      return cvt_failed;
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
bool til_builder_t::verify_union_stem(pdb_udt_type_data_t &udt) const
{
  bool udt_fixed = false;
  // at the moment there is an issue with structure with bit fields only
  if ( udt.size() < 2 )
    return udt_fixed;
  for ( const pdb_udm_t &udm : udt )
  {
    if ( !udm.is_bitfield() )
      return udt_fixed;
  }

  // stem like:
  // 0 unsigned __int8 : 7 ZZ1 bit_offset 0
  // 8 unsigned __int32 : 24 AllFlags bit_offset 8
  // is collected wrongly and should be fixed.
  // There is a bit_offset 8 inside the bitfield group,
  // so we need to expand the type of field ZZ1

  dump_pdb_udt(udt, "verify_union_stem");
  bool udm_fixed;
  do
  {
    udm_fixed = false;
    for ( size_t i=0; i < udt.size()-1; ++i )
    {
      pdb_udm_t &udm0 = udt[i];
      const pdb_udm_t &udm1 = udt[i+1];

      size_t typsz0 = udm0.type.get_size();
      size_t typsz1 = udm1.type.get_size();
      if ( udm0.bit_offset < udm1.bit_offset
        && udm0.offset + udm0.size <= udm1.offset
        && typsz0 < typsz1 )
      {
        bitfield_type_data_t bi;
        udm0.type.get_bitfield_details(&bi);
        bi.nbytes = typsz1;
        udm0.type.create_bitfield(bi);
        udt_fixed = true;
        udm_fixed = true;
      }
    }
  } while ( udm_fixed );
  if ( udt_fixed )
    dump_pdb_udt(udt, "verify_union_stem FIXED");

  return udt_fixed;
}

//----------------------------------------------------------------------
// verify unions that would be created out of [p1, p2) members.
// The [p1, p2) members are spoiled by the function.
// Create substructures if necessary. Returns the result in out (can be the same
// vector as [p1, p2)
cvt_code_t til_builder_t::verify_union(
        pdb_udt_type_data_t *out,
        pdb_udt_type_data_t::iterator p1,
        pdb_udt_type_data_t::const_iterator p2) const
{
  if ( p1 == p2 )
    return cvt_ok;

  QASSERT(498, p2 > p1);
  uint64 off = p1->offset;
  typedef qvector<pdb_udt_type_data_t> stems_t;
  stems_t stems; // each stem is a member of the future union
  for ( pdb_udt_type_data_t::iterator q=p1; q != p2; ++q )
  {
    pdb_udt_type_data_t *best = nullptr;
    q->offset -= off;
    if ( q->offset != 0 )
    { // find best suited stem: the one with end() closest to our offset
      uint64 bestend = 0;
      for ( stems_t::iterator s=stems.begin(); s != stems.end(); ++s )
      {
        pdb_udt_type_data_t &sm = *s;
        pdb_udm_t &lastmem = sm.back();
        uint64 smend = lastmem.end();
        if ( (lastmem.is_bitfield() == q->is_bitfield() || q->bit_offset == 0)
          && smend <= q->begin()
          && (best == nullptr || bestend < smend) )
        {
          best = &sm;
          bestend = smend;
        }
      }
    }
    if ( best == nullptr )
      best = &stems.push_back();
    uint64 qend;
    if ( q->is_bitfield() )
    {
      bitfield_type_data_t bi;
      q->type.get_bitfield_details(&bi);
      size_t size = bi.nbytes * 8;
      QASSERT(30385, size == 8 || size == 16 || size == 32 || size == 64);
      qend = q->offset - q->bit_offset + size;
    }
    else
    {
      qend = q->offset + q->size + 7;
    }
    qend /= 8;
    if ( best->total_size < qend )
      best->total_size = qend;
    qswap(best->push_back(), *q);
  }

  // the stems are created artificially
  // and some of them need to be fixed
  // to prevent structure alignment issues
  for ( stems_t::iterator s=stems.begin(); s != stems.end(); ++s )
  {
    if ( s->size() == 1 && s->begin()->offset == 0 && !s->begin()->is_bitfield() )
      continue;
    verify_union_stem(*s);
  }

  // all non-trivial stems must be converted to structures
  for ( stems_t::iterator s=stems.begin(); s != stems.end(); ++s )
  {
    if ( s->size() == 1 && s->begin()->offset == 0 && !s->begin()->is_bitfield() )
      continue;
#ifdef PDEB
    msg("CREATE STEM total_size %" FMT_Z "\n", s->total_size);
    for ( pdb_udt_type_data_t::iterator p=s->begin(); p != s->end(); ++p )
      msg("  %" FMT_64 "x %s %s bit_offset %u\n", p->offset, p->type.dstr(), p->name.c_str(), p->bit_offset);
#endif
    if ( verify_struct(*s) != cvt_ok )
      return cvt_failed;
    tinfo_t tif;
    int total_size = s->total_size;
    cvt_code_t code = create_udt_ref(&tif, s, UdtStruct);
    if ( code != cvt_ok )
      return code;
    s->resize(1);
    pdb_udm_t &sm = s->front();
    sm.offset = 0;
    sm.size = uint64(total_size) * 8;
    sm.name.sprnt("__s%u", uint(s-stems.begin()));
    sm.type = tif;
  }

  // collect the results
  out->resize(stems.size());
  for ( int i=0; i < stems.size(); i++ )
  {
    QASSERT(499, stems[i].size() == 1);
    qswap(out->at(i), *stems[i].begin());
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
// create a union out of [p1, p2) members. they are spoiled by the function.
// returns type of the new union and its fields
// this function also creates substructures if necessary
cvt_code_t til_builder_t::create_union(
        tinfo_t *out,
        size_t *p_total_size,
        pdb_udt_type_data_t::iterator p1,
        pdb_udt_type_data_t::const_iterator p2) const
{
#ifdef PDEB
  msg("CREATE UNION\n");
  for ( pdb_udt_type_data_t::iterator p=p1; p != p2; ++p )
    msg("  %" FMT_64 "x %s %s bit_offset %u\n", p->offset, p->type.dstr(), p->name.c_str(), p->bit_offset);
#endif
  pdb_udt_type_data_t unimems;
  cvt_code_t code = verify_union(&unimems, p1, p2);
  if ( code != cvt_ok )
    return code;
  // calculate the total size
  for ( int i=0; i < unimems.size(); i++ )
  {
    pdb_udm_t &udm = unimems[i];
    size_t nbytes = (udm.end() + 7) / 8;
    if ( nbytes > unimems.total_size )
      unimems.total_size = nbytes;
  }
  if ( p_total_size != nullptr )
    *p_total_size = unimems.total_size;
  return create_udt_ref(out, &unimems, UdtUnion);
}

//----------------------------------------------------------------------
inline void ida_vft_name(qstring *vftn, const char *ns, uint32_t offset=0)
{
  qstring new_vft_name(ns);
  if ( offset != 0 )
    new_vft_name.cat_sprnt("_%04X", offset);
  new_vft_name.append(VTBL_SUFFIX);
  vftn->swap(new_vft_name);
}

//----------------------------------------------------------------------
#define MS_VTBL_SUFFIX "Vtbl"
inline void ms_vft_name(qstring *vftn, const char *ns)
{
  qstring new_vft_name(ns);
  new_vft_name.append(MS_VTBL_SUFFIX);
  vftn->swap(new_vft_name);
}

//----------------------------------------------------------------------
inline bool is_ms_vft_name(const qstring &udt_name)
{
  size_t len = udt_name.length();
  return len > sizeof(MS_VTBL_SUFFIX)
      && streq(udt_name.begin() + (len - sizeof(MS_VTBL_SUFFIX) + 1), MS_VTBL_SUFFIX);
}

//----------------------------------------------------------------------
inline void ida_vft_name_from_ms(qstring *ivftnm, const qstring &msvftnm)
{
  qstring tmp(msvftnm);
  if ( is_ms_vft_name(msvftnm) )
    tmp.remove(tmp.length()-4, 4);
  ida_vft_name(ivftnm, tmp.c_str());
}

//----------------------------------------------------------------------
bool til_builder_t::get_vft_name(qstring *vftn, uint32 *p_ord, const char *ns, uint32_t offset)
{
  bool vft_creating = false;
  qstring new_vft_name;
  // check for MS vftable
  ms_vft_name(&new_vft_name, ns);
  uint32 ord = get_type_ordinal(ti, new_vft_name.c_str());
  if ( ord == 0 )
  {
    // maybe creating?
    vft_creating = creating.find(new_vft_name.c_str()) != creating.end();
    if ( !vft_creating )
    {
      ida_vft_name(&new_vft_name, ns, offset);
      ord = get_type_ordinal(ti, new_vft_name.c_str());
    }
  }
  vftn->swap(new_vft_name);
  if ( p_ord != nullptr )
    *p_ord = ord;
  return vft_creating;
}

//----------------------------------------------------------------------
void pdb_udt_type_data_t::convert_to_tinfo_udt(udt_type_data_t *out)
{
  out->total_size = total_size;
  out->taudt_bits = taudt_bits;
  out->is_union = is_union;
  out->reserve(size());
  for ( size_t i = 0; i < size(); i++ )
  {
    udm_t &udm = at(i);
#ifdef PDEB
    out->push_back() = udm;
#else
    out->push_back().swap(udm);
#endif
  }
}

//----------------------------------------------------------------------
// insert si into the destination type
inline void merge_vft_udm(int *j, udt_type_data_t *dst_udt, const udm_t &si, bool replace)
{
  bool insert_src = true;
  for ( ; *j < dst_udt->size(); (*j)++ )
  {
    udm_t &dj = (*dst_udt)[*j];
    if ( dj.offset + dj.size <= si.offset )
      continue;
    if ( dj.offset >= si.offset + si.size )
      break;  // should insert before dj
    // Looks like an overlap,
    // fields may differ in type and name only.
    // Ignore "__vecDelDtor",
    // this often happens when virtual class::~class
    // is later redefined as __vecDelDtor()
    if ( replace && si.name != "__vecDelDtor"
      || dj.name == "__vecDelDtor" )
    {
      dj.type = si.type;
      dj.name = si.name;
    }
    insert_src = false;
    break;
  }
  if ( insert_src )
    dst_udt->insert(dst_udt->begin()+*j, si);
}

//----------------------------------------------------------------------
// merge two vftables into one
// dst_udt gets all fields of srctype in addition to its own fields.
// dst_udt preserves or overrides the coinciding field.
static void merge_vftables(udt_type_data_t *dst_udt, const tinfo_t &srcvft, bool replace)
{
  udt_type_data_t src_udt;
  if ( !srcvft.get_udt_details(&src_udt) )
  {
    deb(IDA_DEBUG_DBGINFO, "PDB: failed to merge type '%s' to vftable\n", srcvft.dstr());
#if defined(TESTABLE_BUILD) && !defined(__FUZZER__)
    INTERR(30585);
#else
    return;
#endif
  }

  int j(0);
  for ( const auto &si : src_udt )
    merge_vft_udm(&j, dst_udt, si, replace);
  dst_udt->total_size = (dst_udt->back().end() + 7) / 8;
}

//----------------------------------------------------------------------
static void add_vftable_member(
        udt_type_data_t *dst_udt,
        const tinfo_t &member,
        const char *name,
        DWORD vfptr_offset)
{
  tinfo_t ptr_member;
  ptr_member.create_ptr(member);    // the field is a pointer to function
  asize_t size = ptr_member.get_size();

  udm_t udm;
  udm.offset = uint64(vfptr_offset) * 8;
  udm.size = uint64(size) * 8;
  udm.type = ptr_member;
  udm.effalign = size;
  udm.name = name;

  int j(0);
  merge_vft_udm(&j, dst_udt, udm, true);
  dst_udt->total_size = (dst_udt->back().end() + 7) / 8;
}

//----------------------------------------------------------------------
inline bool get_vfptr_offset(DWORD *vfptr_offset, pdb_sym_t &sym)
{
  BOOL is_virtual;
  return sym.get_virtual(&is_virtual) == S_OK
      && is_virtual
      && sym.get_virtualBaseOffset(vfptr_offset) == S_OK;
}

//----------------------------------------------------------------------
// enumerate virtual functions of class sym and create a vtable structure
// with function pointers
cvt_code_t til_builder_t::make_vtable_struct(tinfo_t *out, pdb_sym_t &_sym)
{
  struct virtual_func_visitor_t : public pdb_access_t::children_visitor_t
  {
    til_builder_t *tb;
    vft_info_t *vftinfo;        // vftable info
    virtual HRESULT visit_child(pdb_sym_t &sym) override
    {
      qstring name;
      sym.get_name(&name);

      // is introducing virtual?
      DWORD vfptr_offset = -1;
      bool is_intro_virtual = get_vfptr_offset(&vfptr_offset, sym);

      tpinfo_t tpi;
      if ( is_intro_virtual && tb->retrieve_type(&tpi, sym, parent) )
      {
        ddeb(("PDEB:   make_vtable_struct add '%s' vptr offset %u\n", tpi.type.dstr(), vfptr_offset));
        add_vftable_member(&vftinfo->udt, tpi.type, name.c_str(), vfptr_offset);
      }
      return S_OK;
    }
    virtual_func_visitor_t(til_builder_t *_tb, vft_info_t *_vftinfo)
      : tb(_tb),
        vftinfo(_vftinfo)
    {}
  };

  qstring udt_name;
  _sym.get_name(&udt_name);
  // FIXME: should we remove classprefix (name + "::") ?
  #ifdef PDEB
  static int zzlevel = 0;
  msg("PDEB: %d{ make_vtable_struct '%s'\n", ++zzlevel, udt_name.c_str());
  #endif
  vft_info_t vftinfo;
  virtual_func_visitor_t pp(this, &vftinfo);
  pdb_access->iterate_children(_sym, SymTagFunction, pp);

  bool ok = false;
  if ( !vftinfo.udt.empty() )
  {
    out->create_udt(vftinfo.udt, BTF_STRUCT);
    ddeb(("PDEB: %d make_vtable_struct collected vftable '%s'\n", zzlevel, out->dstr()));
    ok = out->calc_udt_aligns();
  }
  #ifdef PDEB
  if ( !ok )
    msg("PDEB: make_vtable_struct failed to create vftable\n");
  msg("PDEB: %d} make_vtable_struct '%s'\n", zzlevel--, udt_name.c_str());
  #endif
  return ok ? cvt_ok : cvt_failed;
}

//----------------------------------------------------------------------
inline bool is_fake_vftable(tinfo_t vft_tif)
{
  qstring tname;
  return vft_tif.get_final_type_name(&tname) && tname == fake_vtable_type;
}

//----------------------------------------------------------------------
static bool is_forbidden_name(const char *name)
{
  static const char *const forbidden_names[] = { "QueryInterface" };

  for ( size_t i = 0; i < qnumber(forbidden_names); i++ )
  {
    if ( strcmp(name, forbidden_names[i]) == 0 )
      return true;
  }

  return false;
}

//----------------------------------------------------------------------
// In some cases the type of 'this' is wrong for derived virtual methods,
// it uses the type of the base class instead of the derived class.
// Also, the destructor name may use the base class as well, which is wrong.
//
// For example we have a derived class:
//   class std::numpunct<char> : public _Facet_base
//   [...]
//
// Then its VFT should be like this:
//   struct /*VFT*/ std::numpunct<char>_vtbl
//   {
//     void (__cdecl *~std::numpunct<char>)(struct std::numpunct<char> *this);
//     void (__cdecl *_Incref)(struct std::numpunct<char> *this);
//   [...]
//
// Not like this:
//   struct /*VFT*/ std::numpunct<char>_vtbl
//   {
//     void (__fastcall *~_Facet_base)(std::_Facet_base *this);
//     void (__fastcall *_Incref)(std::_Facet_base *this);
//   [...]
void til_builder_t::fix_thisarg_type(const qstring &udt_name)
{
  uint32 udt_vft_ord = 0;
  qstring udt_vft_name;
  get_vft_name(&udt_vft_name, &udt_vft_ord, udt_name.c_str());

  tinfo_t tinfo;
  tinfo.get_named_type(nullptr, udt_vft_name.c_str(), BTF_STRUCT);
  udt_type_data_t udt;
  tinfo.get_udt_details(&udt);

  tinfo_t base_tif;
  base_tif.get_named_type(nullptr, udt_name.c_str(), BTF_STRUCT);

  tinfo_t base_tif_p;
  base_tif_p.create_ptr(base_tif);

  bool changed = false;

  for ( auto &udm : udt )
  {
    if ( is_forbidden_name(udm.name.c_str()) )
      return;

    tinfo_t tif_no_ptr = udm.type.get_pointed_object();
    func_type_data_t ftd;
    if ( !tif_no_ptr.get_func_details(&ftd, GTD_NO_ARGLOCS)
      || ftd.empty()
      || !ftd[0].type.is_ptr() )
    {
      continue;
    }

    // Fix destructor
    if ( udm.name[0] == '~' )
    {
      changed = true;
      qstring old_name = udm.name;
      udm.name = qstring("~") + udt_name;
      ddeb(("PDEB: Changed destructor in '%s' from '%s' to '%s'\n", udt_vft_name.c_str(), old_name.c_str(), udm.name.c_str()));
    }

    // Fix argument of functions if it doesn't match to real name
    if ( !base_tif.compare_with(remove_pointer(ftd[0].type), TCMP_IGNMODS) )
    {
      changed = true;

      ftd[0].type = tinfo_t(base_tif_p);
      qstring old_type_str;
      udm.type.print(&old_type_str);

      tinfo_t t;
      t.create_func(ftd);
      t.create_ptr(t);

      udm.type.clear();
      udm.type = t;

      qstring new_type_str;
      udm.type.print(&new_type_str);

      ddeb(("PDEB: Changed type in '%s' from '%s' to '%s'\n", udt_vft_name.c_str(), old_type_str.c_str(), new_type_str.c_str()));
    }
  }

  if ( changed )
  {
    tinfo.create_udt(udt, BTF_STRUCT);
    tinfo.set_named_type(nullptr, udt_vft_name.c_str(), NTF_REPLACE);
  }
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::convert_udt(
        tinfo_t *out,
        pdb_sym_t &_sym,
        DWORD64 size)
{
  DWORD udtKind;
  if ( _sym.get_udtKind(&udtKind) != S_OK )
    return cvt_failed;

  // retrieve member names, types, offsets
  struct type_name_collector_t : public pdb_access_t::children_visitor_t
  {
    til_builder_t *tb;
    pdb_udt_type_data_t &udt;
    const char *vftname;        // vftable name
    vft_info_t *vftinfo;        // vftable info, maybe nullptr if we don't want
                                // to collect vftable
    bool mark_lpVtbl;           // mark "lpVtbl" as pointer to vftable
    bool has_virtbases;
    HRESULT visit_child(pdb_sym_t &sym) override
    {
      qstring name;
      sym.get_name(&name);
      ddeb(("PDEB:   convert_udt adding member '%s'\n", name.c_str()));

      // is introducing virtual?
      DWORD vfptr_offset = -1;
      bool is_intro_virtual = get_vfptr_offset(&vfptr_offset, sym);

      LONG offset = 0;
      if ( !is_intro_virtual && sym.get_offset(&offset) != S_OK )
        return S_OK;
      // assert: intro virtual or data member

      tpinfo_t tpi;
      if ( !tb->retrieve_type(&tpi, sym, parent) )
        return S_OK;

      if ( is_intro_virtual )
      {
        if ( vftinfo != nullptr )
        {
          ddeb(("PDEB:   convert_udt vtable %s add '%s' of '%s' vptr offset %u\n", vftname, name.c_str(), tpi.type.dstr(), vfptr_offset));
          add_vftable_member(&vftinfo->udt, tpi.type, name.c_str(), vfptr_offset);
        }
        return S_OK;
      }

      ddeb(("PDEB:   convert_udt adding member '%s' of type '%s'\n", name.c_str(), tpi.type.dstr()));
      asize_t memsize = tb->get_symbol_type_length(sym);

      pdb_udm_t &udm = udt.push_back();

      DWORD tag = SymTagNull;
      sym.get_symTag(&tag);
      if ( tag == SymTagBaseClass )
      {
        udm.set_baseclass();
        // determine if the base is virtual
        BOOL is_virtbase = false;
        sym.get_isVirtualBaseClass(&is_virtbase);
        if ( is_virtbase )
        {
          udm.set_virtbase();
          has_virtbases = true;
        }

        // we are interested only in baseclass at offset 0
        if ( offset == 0 && vftinfo != nullptr )
        {
          // get baseclass vftable
          qstring bcvft_name;
          uint32 bcvft_ord;
          tb->get_vft_name(&bcvft_name, &bcvft_ord, name.c_str());
          if ( bcvft_ord != 0 )
          {
            tinfo_t bcvft_tif;
            bcvft_tif.get_numbered_type(tb->ti, bcvft_ord);
            if ( !is_fake_vftable(bcvft_tif) )
            {
              ddeb(("PDEB:   convert_udt vtable %s add baseclass %s vtable '%s'\n", vftname, bcvft_name.c_str(), bcvft_tif.dstr()));
              merge_vftables(&vftinfo->udt, bcvft_tif, false);
            }
            else
            {
              ddeb(("PDEB:   convert_udt vtable %s baseclass %s vtable is fake\n", vftname, bcvft_name.c_str()));
            }
          }
          else
          {
            ddeb(("PDEB:   convert_udt vtable %s baseclass %s vtable not found\n", vftname, bcvft_name.c_str()));
            vftinfo->base0.swap(bcvft_name);
          }
        }
        name.clear();   // no name for baseclass member
      }
      else if ( tag == SymTagVTable )
      {
        ddeb(("PDEB:   convert_udt our vtable '%s'\n", tpi.type.dstr()));
        if ( is_fake_vftable(tpi.type) )
        {
          tpi.type = tinfo_t::get_stock(STI_PVOID);
        }
        else
        {
          if ( vftinfo != nullptr )
            merge_vftables(&vftinfo->udt, tpi.type, true);
          // type is a structure, while the field is a pointer to it
          tpi.type.create_ptr(tpi.type);
        }
        name = VTBL_MEMNAME;    // we need only this name
        memsize = tpi.type.get_size();
        udm.set_vftable();
      }
      // mark MS vftable pointer
      if ( mark_lpVtbl && tpi.type.is_ptr() && name == "lpVtbl" )
      { // no need to rename it
        udm.set_vftable();
      }
      mark_lpVtbl = false;    // pointer to vftable maybe the first field only

      DWORD64 ulLen = DWORD64(memsize) * 8;
      DWORD dwBitPos = 0;
      DWORD dwLocType = LocIsNull;
      sym.get_locationType(&dwLocType); // may fail, just ignore
      if ( dwLocType == LocIsBitField )
      {
        sym.get_bitPosition(&dwBitPos);
        sym.get_length(&ulLen);
        if ( dwBitPos + ulLen > DWORD64(memsize) * 8 )
          return E_FAIL;
        bool is_unsigned = tpi.type.is_unsigned();
        udm.type.create_bitfield(memsize, ulLen, is_unsigned);
      }
      else
      {
        udm.type = tpi.type;
      }
      udm.size = ulLen;
      udm.offset = uint64(offset) * 8 + dwBitPos;
      udm.bit_offset = dwBitPos;
      udm.name.swap(name);
      ddeb(("PDEB:   convert_udt adding member size %" FMT_64 "u offset %" FMT_64 "u bit_offset %u\n", udm.size, udm.offset, udm.bit_offset));
      return S_OK;
    }
    type_name_collector_t(
            til_builder_t *_tb,
            pdb_udt_type_data_t &m,
            const char *_vftname,
            vft_info_t *_vftinfo)
      : tb(_tb),
        udt(m),
        vftname(_vftname),
        vftinfo(_vftinfo),
        mark_lpVtbl(true),
        has_virtbases(false)
    {}
  };

  qstring udt_name;
  _sym.get_name(&udt_name);

  bool is_vtbl_udt = is_ms_vft_name(udt_name);
  qstring udt_vft_name;
  uint32 udt_vft_ord = 0;
  bool vft_creating = false;
  if ( !is_vtbl_udt )
    vft_creating = get_vft_name(&udt_vft_name, &udt_vft_ord, udt_name.c_str());
  bool collect_vft = !vft_creating && !is_vtbl_udt && udt_vft_ord == 0;

  #ifdef PDEB
  static size_t entry_counter = 0;
  ++entry_counter;
  static int zzlevel = 0;
  msg("PDEB: %d{ convert_udt '%s' assuming vftable '%s' ENTRY %" FMT_Z "\n", ++zzlevel, udt_name.c_str(), udt_vft_name.c_str(), entry_counter);
  #endif
  pdb_udt_type_data_t udt;
  if ( is_vtbl_udt )
    udt.taudt_bits |= TAUDT_VFTABLE;
  vft_info_t vtinfo;
  type_name_collector_t pp(
          this,
          udt,
          udt_vft_name.c_str(),
          collect_vft ? &vtinfo : nullptr);
  pdb_access->iterate_children(_sym, SymTagNull, pp);

  bool is_cppobj = false;
  if ( collect_vft && !vtinfo.udt.empty() )
  {
    if ( vtinfo.base0.empty() )
    {
      tinfo_t vft_tif;
      if ( vft_tif.create_udt(vtinfo.udt, BTF_STRUCT)
        && vft_tif.calc_udt_aligns() )
      {
        ddeb(("PDEB: convert_udt %d collected vftable '%s' '%s'\n", zzlevel, udt_vft_name.c_str(), vft_tif.dstr()));
        uint32 id = get_type_ordinal(ti, udt_vft_name.c_str());
        if ( id == 0 )
          vft_tif.set_named_type(ti, udt_vft_name.c_str(), NTF_NOBASE);
        else
          ddeb(("PDEB: convert_udt '%s' exists\n", udt_vft_name.c_str()));
        is_cppobj = true;   // there is a vftable, so it is a C++ object
      }
      else
      { // ignore failure, continue w/o vftable
        ddeb(("PDEB: convert_udt failed to create vftable\n"));
      }
    }
    else
    {
      vftmap.emplace(std::make_pair(udt_vft_name.c_str(), vtinfo));
    }
  }
  #ifdef PDEB
  msg("PDEB: %d} convert_udt '%s'\n", zzlevel--, udt_name.c_str());
  #endif

  // if we will use MS Vtbl then create IDA synonym
  if ( is_vtbl_udt )
  {
    tinfo_t tif;
    tif.create_typedef(ti, udt_name.c_str());
    qstring ivftnm;
    ida_vft_name_from_ms(&ivftnm, udt_name.c_str());
    tif.set_named_type(ti, ivftnm.c_str(), NTF_NOBASE);
  }

  // if we inherit from c++ object, we are too a c++ object
  if ( size > 0 )
  {
    if ( udt.empty() )
      is_cppobj = true;
    if ( udt.size() == 1
      && udt[0].is_baseclass()
      && udt[0].type.is_empty_udt() )
    {
      is_cppobj = true;
    }
  }
  if ( is_cppobj )
  {
    udt.taudt_bits |= TAUDT_CPPOBJ;
  }
  else if ( udt.empty() )
  { // create forward ref
    qstring name;
    get_symbol_name(_sym, name);
    type_t bt = udtKind == UdtUnion ? BTF_UNION : BTF_STRUCT;
    out->create_typedef(ti, name.c_str(), bt);
    return cvt_typedef;
  }
  udt.total_size = size;
  std::stable_sort(udt.begin(), udt.end());
  BOOL cppobj;
  if ( _sym.get_constructor(&cppobj) == S_OK && cppobj > 0 )
    udt.taudt_bits |= TAUDT_CPPOBJ;
  cvt_code_t res = create_udt(out, &udt, udtKind, udt_name.c_str());

  if ( res == cvt_ok )
    fix_thisarg_type(udt_name);

  return res;
}

//----------------------------------------------------------------------
inline void get_empty_vft_tif(tinfo_t *vtif)
{
  udt_type_data_t empty_udt;
  empty_udt.taudt_bits |= TAUDT_VFTABLE;
  vtif->create_udt(empty_udt, BTF_STRUCT);
}

//----------------------------------------------------------------------
// fill the empty start slots of vftable,
// the holes will be filled latter, see SUDT_GAPS
static void fill_vft_empty_splots(udt_type_data_t *udt)
{
  if ( udt->empty() )
    return;

  uint64 offset = udt->begin()->offset;
  if ( offset == 0 )
    return;
  uint32 nbytes = offset / 8;

  udm_t gap;
  gap.type.create_array(tinfo_t(BTF_BYTE), nbytes);
  gap.offset = 0;
  gap.size = offset;
  gap.effalign = 1;
  gap.name = "gap0";
  udt->insert(udt->begin(), gap);
  // assert: no need to fix udt->total_size
}

//----------------------------------------------------------------------
void til_builder_t::create_vftables()
{
  while ( !vftmap.empty() )
  {
    bool changed = false;
    for ( auto p=vftmap.begin(); p != vftmap.end(); )
    {
      auto &name = p->first;
      auto &info = p->second;
      ddeb(("PDB: create_vftables checking %s base0 %s\n", name.c_str(), info.base0.c_str()));
      const char *b0name = info.base0.c_str();
      uint32 id = get_type_ordinal(ti, b0name);
      if ( id != 0 )
      { // merge the known base class vftable
        ddeb(("PDB:   merge %s to %s\n", b0name, name.c_str()));
        tinfo_t btif;
        btif.get_numbered_type(ti, id);
        merge_vftables(&info.udt, btif, false);
        info.base0.clear();
        changed = true;
      }
      else
      {
        auto r = vftmap.find(b0name);
        if ( r == vftmap.end() || r->second.empty() )
        { // ordinary class
          ddeb(("PDB:   ignore %s for %s\n", b0name, name.c_str()));
          info.base0.clear();
          changed = true;
        }
        else
        {
          ddeb(("PDB:   skip %s for %s\n", b0name, name.c_str()));
        }
      }
      if ( info.base0.empty() )
      { // all base classes references are resolved, create vftable
        ddeb(("PDB: create_vftables creating %s\n", name.c_str()));
        tinfo_t vtif;
        if ( !vtif.create_udt(info.udt, BTF_STRUCT)
          || !vtif.calc_udt_aligns() )
        { // something wrong with vftable udt,
          // create an empty vftable
          ddeb(("PDEB: create_vftables failed to create vftable %s\n", name.c_str()));
          get_empty_vft_tif(&vtif);
        }
        ddeb(("PDB: create_vftables created %s '%s'\n", name.c_str(), vtif.dstr()));
        vtif.set_named_type(ti, name.c_str(), NTF_NOBASE);
        p = vftmap.erase(p);
        changed = true;
      }
      else
      {
        ++p;
      }
    }
    if ( !changed )
      break;
  }

  if ( !vftmap.empty() )
  { // Something wrong or not:
    // base class w/o virtual functions
    // cyclic references,
    // missed types
    // Create the vftables ASIS
    for ( auto p : vftmap )
    {
      auto &name = p.first;
      auto &info = p.second;
      ddeb(("PDEB: create_vftables create vftable %s ASIS, base0 %s\n", name.c_str(), info.base0.c_str()));
      fill_vft_empty_splots(&info.udt);
      tinfo_t vtif;
      vtif.create_udt(info.udt, BTF_STRUCT);
      vtif.calc_udt_aligns();
      ddeb(("PDB: create_vftables created %s '%s'\n", name.c_str(), vtif.dstr()));
      vtif.set_named_type(ti, name.c_str(), NTF_NOBASE);
    }
    vftmap.clear();
  }
}

//----------------------------------------------------------------------
static bool set_array_type(pdb_udm_t *udm, int nbytes)
{
  bool ok = udm->type.create_array(tinfo_t(BT_UNK_BYTE), nbytes);
  if ( ok )
    udm->size = nbytes * 8;
  return ok;
}

//----------------------------------------------------------------------
// the real UDT should have non-zero size,
// detect a forward reference to a UDT without a real definition
inline bool is_fwdref_baseclass(pdb_udm_t &udm)
{
  return udm.is_baseclass() && udm.size == 0;
}

//----------------------------------------------------------------------
// The sparsed bit field union needs to be fixed, for example:
// 0x15e8 : LF_BITFIELD, bits = 4, starting position = 12, Type = T_ULONG(0022)
// 0x19b8 : LF_BITFIELD, bits = 1, starting position = 11, Type = T_ULONG(0022)
// 0x304f : LF_FIELDLIST
//   list[0] = LF_MEMBER, public, type = 0x19B8, offset = 4, member name = 'AbsoluteAddressing'
//   list[1] = LF_MEMBER, public, type = 0x15E8, offset = 4, member name = 'Op'
// 0x3050 : LF_UNION
//   # members = 2,  field list type 0x304f, SEALED, Size = 8, class name = GPUFLOW_RETURN
// We need:
// - add starting gap, others will be handled by SUDT_GAPS
// - change member field type
// - fix bit_offset
cvt_code_t til_builder_t::fix_bit_union(pdb_udt_type_data_t *udt) const
{
  if ( udt->empty() )
    return cvt_ok;
  // interested in bitfield union only
  for ( const pdb_udm_t &um : *udt )
  {
    if ( !um.is_bitfield() )
      return cvt_ok;
  }
  // starting gap?
  if ( udt->begin()->offset == 0 )
    return cvt_ok;
  // union size
  size_t union_sz = udt->begin()->type.get_size();
  union_sz = qmax(udt->total_size, union_sz);
  bool is_unsigned = udt->begin()->type.is_unsigned();
  // fill gap
  pdb_udm_t gap;
  gap.bit_offset = 0;
  gap.offset = 0;
  gap.size = udt->begin()->offset;
  gap.name = "gap0";
  // gap.type will be fixed later
  udt->insert(udt->begin(), gap);
  // fix member type
  udt->total_size = union_sz;
  for ( pdb_udm_t &um : *udt )
  {
    um.type.create_bitfield(union_sz, um.size, is_unsigned);
    um.bit_offset = um.offset;
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::create_udt(tinfo_t *out, pdb_udt_type_data_t *udt, int udtKind, const char *udt_name) const
{
#ifdef PDEB
  static size_t entry_counter = 0;
  ++entry_counter;
  _ddeb("PDEB: til_builder_t::create_udt ENTRY %" FMT_Z "\n", entry_counter);
  dump_pdb_udt(*udt, udt_name);
#endif
  cvt_code_t code;
  if ( udtKind == UdtUnion )
  {
    udt->is_union = true;
    fix_bit_union(udt);
    code = verify_union(udt, udt->begin(), udt->end());
  }
  else
  {
    // find overlapping members and convert into subunions (anonymous union would be great)
    udt->is_union = false;
    code = handle_overlapping_members(udt);
  }
  if ( code != cvt_ok )
    return code;

  // validate the type sizes, for the following reasons:
  //   - pdb information may be misleading (see pc_pdb_redefined_type.pe)
  //   - the same type name can be used for different types
  //   - invalid arrays happen (pc_pdb_wow.pe)
  for ( int i=0; i < udt->size(); i++ )
  {
    pdb_udm_t &udm = udt->at(i);
    if ( udm.is_bitfield() )
      continue;
    int gts_code = GTS_NESTED | (udm.is_baseclass() ? GTS_BASECLASS : 0);
    size_t nbytes = udm.type.get_size(nullptr, gts_code);
    if ( nbytes == BADSIZE && !is_fwdref_baseclass(udm) )
      continue; // cannot verify, the type is not ready yet
    if ( uint64(nbytes)*8 != udm.size )
    {
      if ( nbytes != 0 )
      {
        if ( !set_array_type(&udm, udm.size/8) )
          return cvt_failed;
        udm.clr_baseclass();
      }
      else if ( udm.is_baseclass() || udm.type.is_array() )
      { // nbytes==0
        udm.size = 0; // correct the base class size
      }
    }
  }

  if ( udt->total_size == 0 && !udt->empty() )
  { // msdia did not provide the udt size. use the end of the last element
    pdb_udm_t &udm = udt->back();
    udt->total_size = (udm.end() + 7) / 8;
  }

  // the kernel cannot handle virtual base classes yet, so we remove them
  // also check for overlapping members and members that go past the udt end
  uint64 last = 0;
  uint64 total_bits = uint64(udt->total_size) * 8;
  for ( int i=0; i < udt->size(); i++ )
  {
    pdb_udm_t &udm = udt->at(i);
    if ( udm.offset < last || udm.end() > total_bits )
    {
      if ( udm.end() > total_bits )
        udm.size = total_bits - udm.offset;
      if ( udm.offset > last )
        last = udm.offset;
      int nbytes = (udm.end() + 7 - last) / 8;
      if ( nbytes > 0 )
      { // replace with byte array
        if ( !set_array_type(&udm, nbytes) )
          return cvt_failed;
        if ( udm.name.empty() )
          udm.name.sprnt("_bytes_%" FMT_64 "x", last/8);
        udm.offset = last;
        udm.clr_baseclass();
        udm.clr_virtbase();
      }
      else
      { // we do not need this member
        udt->erase(udt->begin()+i);
        --i;
        continue;
      }
    }
    if ( udtKind != UdtUnion )
      last = udm.end();
  }

  type_t bt = udt->is_union ? BTF_UNION : BTF_STRUCT;
  udt_type_data_t tinfo_udt;
  udt->convert_to_tinfo_udt(&tinfo_udt);
  if ( !out->create_udt(tinfo_udt, bt) )
    return cvt_failed;
  if ( !out->calc_udt_aligns(SUDT_GAPS|SUDT_UNEX) )
  {
    dump_pdb_udt(*udt, udt_name);
    deb(IDA_DEBUG_DBGINFO, "PDB: Failed to calculate struct '%s' member alignments\n", udt_name != nullptr ? udt_name : "");
#if defined(TESTABLE_BUILD) && !defined(__FUZZER__)
    QASSERT(30380, !inf_test_mode() && out->get_size() == BADSIZE);
#endif
    ask_for_feedback("Failed to calculate struct member alignments");
  }
  return cvt_ok;
}

//----------------------------------------------------------------------
// is the return type complex?
// if so, a pointer to return value will be passed as a hidden parameter
bool til_builder_t::is_complex_return(pdb_sym_t &sym) const
{
  pdb_sym_t *pType = pdb_access->create_sym();
  pdb_sym_janitor_t janitor_pType(pType);
  bool complex = false;
  if ( sym.get_type(pType) == S_OK )
  {
    DWORD tag = 0;
    complex = pType->get_symTag(&tag) == S_OK && tag == SymTagUDT;
    if ( complex )
    {
      ULONGLONG size;
      complex = pType->get_length(&size) == S_OK && size > 8;
    }
    if ( !complex && tag == SymTagUDT )
    {
      // we've got a small UDT which possibly fits into a register (or two)
      // but it has to be a POD for that, i.e. should have no constructor or assignment operators
      BOOL b;
      if ( (pType->get_constructor          (&b) == S_OK) && b
        || (pType->get_hasAssignmentOperator(&b) == S_OK) && b
        || (pType->get_hasCastOperator      (&b) == S_OK) && b )
        complex = true;
    }
  }
  return complex;
}


//----------------------------------------------------------------------------
bool til_builder_t::is_unnamed_tag_typedef(const tinfo_t &tif) const
{
  uint32 id = tif.get_ordinal();
  if ( id == 0 )
    return false;

  return unnamed_types.find(id) != unnamed_types.end();
}


//----------------------------------------------------------------------
// borland does not like this structure to be defined inside a function.
// this is the only reason why it is in the file scope.
struct this_seeker_t : public pdb_access_t::children_visitor_t
{
  funcarg_t thisarg;
  til_builder_t *tb;
  bool found;
  virtual HRESULT visit_child(pdb_sym_t &sym) override
  {
    DWORD dwDataKind, locType;
    if ( sym.get_dataKind(&dwDataKind) == S_OK
      && dwDataKind == DataIsObjectPtr
      && sym.get_locationType(&locType) == S_OK )
    {
      tb->get_symbol_funcarg_info(&thisarg, sym, dwDataKind, locType, 0);
      found = true;
      return S_FALSE; // Stop enum.
    }
    return S_OK;
  }
  this_seeker_t(til_builder_t *_tb) : thisarg(), tb(_tb), found(false) {}
};

//----------------------------------------------------------------------------
inline type_t get_sym_modifiers(pdb_sym_t &sym)
{
  type_t type_mod = 0;
  BOOL sym_mod;
  if ( sym.get_constType(&sym_mod) == S_OK && sym_mod )
    type_mod |= BTM_CONST;
  if ( sym.get_volatileType(&sym_mod) == S_OK && sym_mod )
    type_mod |= BTM_VOLATILE;
  return type_mod;
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::really_convert_type(
        tpinfo_t *out,
        pdb_sym_t &sym,
        pdb_sym_t *parent,
        DWORD tag)
{
  // retrieve type modifiers
  type_t mods = get_sym_modifiers(sym);

  DWORD64 size = 0;
  sym.get_length(&size);
  DWORD bt, count;
  cvt_code_t code = cvt_ok;
  switch ( tag )
  {
    default:
    case SymTagNull:
      deb(IDA_DEBUG_DBGINFO, "PDB: unsupported tag %s\n", symtag_to_string(tag));
      code = cvt_failed;
      break;

    case SymTagBaseType:
      if ( sym.get_baseType(&bt) != S_OK )
        code = cvt_failed;
      else
        code = convert_basetype(out, bt, int(size));
      break;

    case SymTagPointerType:
      {
        tpinfo_t obj;
        if ( !get_symbol_type(&obj, sym) )
        {
          code = cvt_failed;
          break;
        }
        tinfo_t tif;
        tif.create_ptr(obj.type);
        int s2 = tif.get_size();
        if ( size != s2 )
        {
          if ( size == 4 || size == 8 )
          { // use __ptr32 or __ptr64
            ptr_type_data_t pi;
            pi.obj_type = obj.type;
            pi.taptr_bits = size == 4 ? TAPTR_PTR32 : TAPTR_PTR64;
            tif.create_ptr(pi);
          }
          else
          { // revert to int
            type_t inttype = get_scalar_bt(size);
            if ( inttype == BT_UNK )
            {
              code = cvt_failed;
              break;
            }
            tif = tinfo_t(inttype);
          }
        }
        out->type.swap(tif);
      }
      break;

    case SymTagArrayType:
      {
        tpinfo_t el;
        if ( !get_symbol_type(&el, sym) )
        {
FAILED_ARRAY:
          code = cvt_failed;
          break;
        }
        if ( sym.get_count(&count) != S_OK )
          goto FAILED_ARRAY;
        mods |= el.type.get_modifiers(); // propagate element type to array
        if ( !out->type.create_array(el.type, count) )
          goto FAILED_ARRAY;
      }
      break;

    case SymTagFunctionType:
      {
        tpinfo_t itp2;
        if ( !get_symbol_type(&itp2, sym) ) // return type
        {
          code = cvt_failed;
          break;
        }
        func_type_data_t fi;
        fi.rettype = itp2.type;
        if ( fi.rettype.is_array() )
        {
          code = cvt_failed; // arrays cannot be returned
          break;
        }
        DWORD cc0;
        fi.cc = CM_CC_UNKNOWN;
        if ( sym.get_callingConvention(&cc0) == S_OK )
          fi.cc = convert_cc(cc0);

        if ( get_cc(fi.cc) != CM_CC_VOIDARG )
        {
          retrieve_arguments(sym, fi, parent);
          // if arg has unknown/invalid argument => convert to ellipsis
          for ( func_type_data_t::iterator i = fi.begin(); i != fi.end(); i++ )
          {
            if ( i->type.empty() )
            {
              // If the CC is cdecl, empty arguments represent an ellipsis.
              // Otherwise, it's likely to be a C-type function
              // with unknown number of arguments, such as 'foo()'
              // (as opposed to 'foo(void)'), and which might not have a cdecl
              // calling convention. E.g., pc_win32_appcall.pe's 'FARPROC':
              // "int (FAR WINAPI * FARPROC) ()", which is a stdcall.
              cm_t cc = get_cc(fi.cc);
              if ( cc == CM_CC_CDECL || inf_is_64bit() && cc == CM_CC_FASTCALL )
                fi.cc = CM_CC_ELLIPSIS;
              // remove the ellipsis and any trailing arguments
              fi.erase(i, fi.end());
              break;
            }
          }
          // is there an implicit "result" pointer passed?
          if ( is_complex_return(sym) )
          {
            // complex return type: what's returned is actually a pointer
            fi.rettype.create_ptr(fi.rettype);
            funcarg_t retarg;
            retarg.type = fi.rettype;
            retarg.name = "result";
            fi.insert(fi.begin(), retarg);
          }
          // is there an implicit "this" passed?
          // N.B.: 'this' is passed before the implicit result, if both are present
          tinfo_t class_type;
          if ( is_member_func(&class_type, sym, parent) )
          {
            class_type.create_ptr(class_type);
            funcarg_t thisarg;
            thisarg.type = class_type;
            thisarg.name = "this";
            // due to MSDIA error sometimes it is failed to answer correctly
            // for the get_isStatic() request (S_FALSE).
            // So we need to check does 'this' pointer present in the function parameters.
            bool add_this = true;
            if ( parent != nullptr )
            {
              this_seeker_t ts(this);
              pdb_access->iterate_children(*parent, SymTagData, ts);
              thisarg.argloc = ts.thisarg.argloc;
              if ( thisarg.argloc.is_stkoff() )
              { // shift the remaining stkargs
                int delta = thisarg.type.get_size();
                for ( int i=0; i < fi.size(); i++ )
                {
                  funcarg_t &fa = fi[i];
                  if ( fa.argloc.is_stkoff() )
                    fa.argloc.set_stkoff(fa.argloc.stkoff()+delta);
                }
              }
              add_this = ts.found;
            }
            if ( add_this )
              fi.insert(fi.begin(), thisarg);
          }
          if ( is_user_cc(fi.cc) )
          {
            // specify argloc for the return value
            size_t retsize = fi.rettype.get_size();
            if ( retsize <= 1 )
              fi.retloc._set_reg1(R_al);
            else if ( retsize <= 4 )
              fi.retloc._set_reg1(R_ax);
            else
              fi.retloc._set_reg2(R_ax, R_dx);

            // __usercall must have all its arguments location
            // specified.
            // It happens that some PDB information,
            // generated at compile-time, does _not_ hold info
            // about all the parameters. For example,
            // a function declared as:
            //   void BlockOpVPSDec(char *p, uint32 dwLength, char btXorKey, char /*foo*/)
            // will end up having only its first three arguments
            // properly defined in the PDB (because the fourth is
            // not used, its location is not defined.)
            // Still, in order for 'build_func_type2()' to work,
            // it requires all valid argloc_t instances. Thus,
            // we remove invalid ones completely.
            for ( int i = fi.size() - 1; i >= 0; --i )
              if ( fi[i].argloc.is_badloc() )
                fi.erase(fi.begin() + i);
          }
          out->type.create_func(fi);
        }
      }
      break;

    case SymTagUDT:
    case SymTagBaseClass:
      code = convert_udt(&out->type, sym, size);
      break;
    case SymTagEnum:
      {
        struct name_value_collector_t : public pdb_access_t::children_visitor_t
        {
          const til_builder_t *tb;
          enum_type_data_t ei;
          const type_t *idatype;
          HRESULT visit_child(pdb_sym_t &child) override
          {
            edm_t &em = ei.push_back();
            child.get_name(&em.name);
            em.value = tb->get_variant_long_value(child);
            if ( em.name.empty()
              || get_named_type(tb->ti, em.name.c_str(), NTF_SYMM, &idatype) == 1 )
            {
              return E_FAIL;
            }
            return S_OK;
          }
          name_value_collector_t(const til_builder_t *_tb)
            : tb(_tb), idatype(nullptr) {}
        };
        name_value_collector_t nvc(this);
        if ( size != 0 && size <= 64 )
          ((enum_type_data_t_84&)nvc.ei).set_nbytes(size);
        HRESULT hr = pdb_access->iterate_children(sym, SymTagNull, nvc);
        if ( FAILED(hr) )
        { // symbol already exists or
          // corrupted name or
          // iterate_children failed to read any child
          if ( nvc.ei.empty() || nvc.ei.back().name.empty() )
          {
            code = cvt_failed;
            break;
          }
          // just reuse the existing enum
          if ( !out->type.deserialize(ti, &nvc.idatype) ) // this is not quite correct
            INTERR(30407);
          qstring n1;
          if ( out->type.get_type_name(&n1) )
          {
            qstring nm;
            get_symbol_name(sym, nm);
            if ( nm == n1 )
              code = cvt_typedef;       // avoid circular dependencies
          }
        }
        else
        {
          out->type.create_enum(nvc.ei);
        }
      }
      break;

    case SymTagTypedef:
    case SymTagFunctionArgType:
    case SymTagFunction:
    case SymTagData:
      if ( !get_symbol_type(out, sym) )
        code = cvt_failed;
      else if ( out->type.is_decl_typedef() )
        code = cvt_typedef; // signal that this is a typedef
      break;

    case SymTagVTable:
      if ( parent == nullptr || make_vtable_struct(&out->type, *parent) != cvt_ok )
        out->type.create_typedef(ti, fake_vtable_type);
      break;
  }
  if ( code != cvt_failed && mods != 0 )
    out->type.set_modifiers(mods);
  // todo: check that the type has the expected size
  return code;
}

//----------------------------------------------------------------------
cvt_code_t til_builder_t::convert_type(
        tpinfo_t *out,
        pdb_sym_t &sym,
        pdb_sym_t *parent,
        DWORD type,
        DWORD tag)
{
  if ( level == 1000 )
  {
    deb(IDA_DEBUG_DBGINFO, "PDB: the maximum recursion level was reached\n");
    return cvt_failed;
  }
  ddeb(("PDEB: convert_type tag %d sym_id %d\n", tag, type));
  level++;
  typemap_t::iterator p = typemap.find(type);
  if ( p == typemap.end() )
  {
    tpinfo_t tpi;
    tpi.cvt_code = really_convert_type(&tpi, sym, parent, tag);
    p = typemap.insert(std::make_pair(type, tpi)).first;
  }
  tpinfo_t &tpi = p->second;
  *out = tpi;
  level--;
  return tpi.cvt_code;
}

//----------------------------------------------------------------------
bool til_builder_t::begin_creation(DWORD tag, const qstring &name, uint32 *p_ord)
{
  if ( tag != SymTagFunction )
  {
    uint32 ord = *p_ord;
    creating_t::iterator c = creating.find(name);
    if ( c != creating.end() ) // recursive call
    {
      if ( c->second == 0 ) // allocated?
      {
        if ( ord == 0 )
          ord = alloc_type_ordinal(ti); // have to create the type ord immediately
        c->second = ord;
        QASSERT(490, ord != 0);
        ddeb(("PDEB: '%s' prematurely mapped to %u\n", name.c_str(), ord));
      }
      *p_ord = c->second;
      return false;
    }
    creating.insert(std::make_pair(name, ord)); // add to the 'creating' list
  }
  return true;
}

//----------------------------------------------------------------------------
uint32 til_builder_t::end_creation(const qstring &name)
{
  uint32 ord = 0;
  creating_t::iterator c = creating.find(name);
  if ( c != creating.end() )
  {
    ord = c->second;
    creating.erase(c);
  }
  if ( ord == 0 )
  {
    ord = alloc_type_ordinal(ti); // have to create the type ord immediately
    QASSERT(491, ord != 0);
    ddeb(("PDEB: '%s' prematurely mapped to %u\n", name.c_str(), ord));
  }
  return ord;
}


//----------------------------------------------------------------------------
cvt_code_t til_builder_t::handle_overlapping_members(pdb_udt_type_data_t *udt) const
{
  qstack<qstring> union_names;
  pdb_udt_type_data_t::iterator end = udt->end();
  pdb_udt_type_data_t::iterator first = end; // !=end => collecting union members
  pdb_udt_type_data_t::iterator last = end;  // member with highest ending offset so far
  for ( pdb_udt_type_data_t::iterator p=udt->begin(); ; ++p )
  {
    if ( p != udt->end() )
    {
      if ( is_unnamed_tag_typedef(p->type) )
        handle_unnamed_overlapping_member(udt, &union_names, &p->name);
      if ( last == end )
      {
        last = p;
        continue;
      }
      if ( last->end() > p->begin() )
      { // found an overlap. however, we ignore base classes, in order
        // not to convert them into unions
        if ( first == end && !last->is_baseclass() )
          first = last;
        goto NEXT;
      }
    }
    if ( first != end )
    {
      int fidx = first - udt->begin();
      uval_t off = first->offset;
      // if we have a bitfield, include the adjacent bitfields in the new type
      int bf_typesize = 0;
      for ( pdb_udt_type_data_t::iterator q=first; q != p; ++q )
      {
        if ( q->is_bitfield() )
        {
          bf_typesize = q->type.get_size();
          break;
        }
      }
      if ( bf_typesize != 0 )
      {
        while ( fidx > 0
             && (first-1)->is_bitfield()
             && (first-1)->type.get_size() == bf_typesize )
        {
          --fidx;
          --first;
          off = first->offset;
        }
        while ( p != end
             && p->is_bitfield()
             && p->type.get_size() == bf_typesize )
        {
          ++p;
        }
      }
      // range [first, p) is overlapping, create a new type for it
      tinfo_t unitif;
      size_t union_size;
      cvt_code_t code = create_union(&unitif, &union_size, first, p);
      if ( code != cvt_ok )
        return code;
      udt->erase(first+1, p);
      end = udt->end();
      first = end;
      last = end;
      p = udt->begin() + fidx;
      p->offset = off & ~7;
      p->size = uint64(union_size) * 8;
      if ( union_names.empty() )
        p->name.sprnt("___u%d", fidx);
      else
        p->name = union_names.pop();
      p->type = unitif;
    }
    if ( p == end )
      break;
NEXT:
    if ( last->end() < p->end() )
      last = p;
  }
  return cvt_ok;
}


//----------------------------------------------------------------------------
void til_builder_t::handle_function_type(pdb_sym_t &fun_sym, ea_t ea)
{
  struct local_data_creator_t : public pdb_access_t::children_visitor_t
  {
    virtual HRESULT visit_child(pdb_sym_t &sym) override
    {
      DWORD tag = 0;
      HRESULT hr = sym.get_symTag(&tag);
      if ( FAILED(hr) )
        return hr;

      switch ( tag )
      {
        case SymTagBlock: // nested blocks
          return tb->pdb_access->iterate_children(sym, SymTagNull, *this);
        case SymTagFuncDebugStart:
        case SymTagFuncDebugEnd:
          return S_OK;    // ignore these for the moment
      }

      DWORD loc_type;
      if ( sym.get_locationType(&loc_type) != S_OK )
        return S_OK; // optimized away?

      return tb->handle_function_child(fun_sym, ea, sym, tag, loc_type);
    }
    local_data_creator_t(til_builder_t *_tb, pdb_sym_t &_fun_sym, ea_t _ea) :
      tb(_tb), fun_sym(_fun_sym), ea(_ea) {}
    til_builder_t *tb;
    pdb_sym_t &fun_sym;
    ea_t ea;
  };
  local_data_creator_t ldc(this, fun_sym, ea);
  pdb_access->iterate_children(fun_sym, SymTagNull, ldc);
}


//----------------------------------------------------------------------------
void til_builder_t::type_created(
        ea_t /*ea*/,
        int /*id*/,
        const char * /*name*/,
        const tinfo_t & /*ptr*/) const
{
}


//----------------------------------------------------------------------------
HRESULT til_builder_t::handle_function_child(
        pdb_sym_t & /*fun_sym*/,
        ea_t ea,
        pdb_sym_t &child_sym,
        DWORD child_tag,
        DWORD child_loc_type)
{
  switch ( child_loc_type )
  {
    case LocIsConstant:
      break; // we ignore function level constants

    case LocIsStatic:
    case LocIsTLS:              // not tested
      handle_symbol(child_sym);
      break;

    case LocIsEnregistered:
    case LocIsRegRel:
      break;

    default:
      ask_for_feedback("pdb: unsupported location type %d, tag %d at %a", child_loc_type, child_tag, ea);
      break;
  }
  return S_OK;
}


//----------------------------------------------------------------------------
cvt_code_t til_builder_t::create_udt_ref(tinfo_t *out, pdb_udt_type_data_t *udt, int udt_kind) const
{
  tinfo_t tif;
  cvt_code_t code = create_udt(&tif, udt, udt_kind, nullptr);
  if ( code != cvt_ok )
    return code;

  qtype type, fields;
  tif.serialize(&type, &fields);

  qstring name;
  build_anon_type_name(&name, type.begin(), fields.begin());
  uint32 ord = get_type_ordinal(ti, name.c_str());
  if ( ord == 0 )
  {
    ord = alloc_type_ordinal(ti);
    if ( tif.set_numbered_type(ti, ord, NTF_NOBASE|NTF_FIXNAME, name.c_str()) != TERR_OK )
      return cvt_failed;
    type_created(BADADDR, ord, nullptr, tif);
  }

  out->create_typedef(ti, ord);
  return cvt_ok;
}

//----------------------------------------------------------------------------
bool til_builder_t::retrieve_type(
        tpinfo_t *out,
        pdb_sym_t &sym,
        pdb_sym_t *parent,
        uint32 *p_ord)
{
  if ( p_ord != nullptr )
    *p_ord = 0;

  // id -> unknown typedef?
  DWORD sym_id = 0;
  sym.get_symIndexId(&sym_id);
  tpdefs_t::iterator q = tpdefs.find(sym_id);
  if ( q != tpdefs.end() )
  {
    out->type = q->second;
    return true;
  }

  DWORD tag = 0;
  HRESULT hr = sym.get_symTag(&tag);
  if ( FAILED(hr) )
    return false;

  qstring ns;
  bool is_unnamed = get_symbol_name(sym, ns);
  //msg("ID: %d -> %s\n", sym_id, ns.begin());
  uint32 ord = 0;
  bool ord_set = false;
  if ( tag == SymTagVTable && ns.empty() )
  {
    if ( parent != nullptr )
      get_symbol_name(*parent, ns);
    LONG offset = 0;
    sym.get_offset(&offset);
    get_vft_name(&ns, &ord, ns.c_str(), offset);

    is_unnamed = false;
    ord_set = true;
  }

  // udt fields and simple types are converted without allocating
  // an ordinal number
  if ( tag == SymTagData || ns.empty() )
    return convert_type(out, sym, parent, sym_id, tag) != cvt_failed;

  // give a unique name to unnamed types so they can be told apart
  // this is a temporary name, it will be replaced by $hex..
  if ( is_unnamed )
    ns.sprnt("unnamed-%d", unnamed_idx++);
  else
    validate_name(&ns, VNT_TYPE);

  // some types can be defined multiple times. check if the name is already defined
  bool defined_correctly = false;
  bool defined_wrongly = false;
  type_t tif_mod = 0;
  if ( !ord_set )
    ord = get_type_ordinal(ti, ns.c_str());
  if ( ord != 0 )
  {
    tinfo_t tif;
    tif.create_typedef(ti, ord);
    tif_mod = get_sym_modifiers(sym);
    if ( tif.get_realtype() == BT_UNK )
      defined_wrongly = true;
    else
      defined_correctly = true;
  }
  if ( !defined_correctly )
  {
    if ( begin_creation(tag, ns, &ord) )
    {
      // now convert the type information, recursive types won't bomb
      tpinfo_t tpi2;
      cvt_code_t cc = convert_type(&tpi2, sym, parent, sym_id, tag);
      if ( cc != cvt_ok ) // failed or typedef
      {
        creating.erase(ns);
        if ( cc == cvt_failed )
          return false;
        // cvt_typedef
        {
          tinfo_t tif;
          tif.create_typedef(ti, ns.c_str());
          tif.set_modifiers(tpi2.type.get_modifiers());
          tpdefs[sym_id] = tif;   // reference to unknown typedef
          if ( tpi2.type.present() && tpi2.type.is_decl_typedef() )
          { // do not put a lot of garbage to types: forward declarations etc
            if ( !tpi2.type.set_named_type(nullptr, ns.c_str(), NTF_TYPE|NTF_REPLACE) )
              return false;
            type_created(BADADDR, 0, ns.c_str(), tpi2.type);
          }
        }
        out->type = tpi2.type;
        return true;
      }

      qtype type, fields;
      if ( !tpi2.type.serialize(&type, &fields) )
        INTERR(30408);

      // Function types are saved as symbols
      if ( tag == SymTagFunction )
      {
        // the following may fail because of c++ overloaded functions
        // do not check the error code - we cannot help it
        tpi2.type.set_symbol_type(ti, ns.c_str(), NTF_SYMM);
        type_created(BADADDR, 0, ns.c_str(), tpi2.type);
        out->type = tpi2.type;
        return true;
      }

      bool reuse_anon_type = false;
      if ( is_unnamed ) // this type will be referenced, so create a name for it
      {
        build_anon_type_name(&ns, type.begin(), fields.begin());
        ord = get_type_ordinal(ti, ns.c_str());
        if ( ord != 0 ) // this type already exists, just reuse it
        {
          creating.erase(ns);
          reuse_anon_type = true;
        }
        tif_mod = get_sym_modifiers(sym);
      }
      if ( !reuse_anon_type )
      {
        ord = end_creation(ns);
        int ntf_flags = NTF_NOBASE|NTF_FIXNAME;
        if ( defined_wrongly )
          ntf_flags |= NTF_REPLACE;
        tinfo_t tif;
        tinfo_code_t code = tif.deserialize(ti, &type, &fields)
                          ? tif.set_numbered_type(ti, ord, ntf_flags, ns.empty() ? nullptr : ns.c_str())
                          : TERR_BAD_TYPE;
        if ( code != TERR_OK )
        {
          ddeb(("PDEB: set_numbered_type(%u, %s) : %s\n", ord, ns.c_str(), tinfo_errstr(code)));
          return false;
        }
        tif_mod = tpi2.type.get_modifiers();
      }
      if ( is_unnamed )
        unnamed_types.insert(ord);
      // msg("%d: %s\n  name: %s\n", ord, tpi2.dstr(), ns.c_str());
      type_created(BADADDR, ord, nullptr, tpi2.type);
    }
    else
    { // in case of recursive call we need to preserve modifiers
      tif_mod = get_sym_modifiers(sym);
    }
  }
  if ( p_ord != nullptr )
    *p_ord = ord;
  out->type.create_typedef(ti, ord);
  if ( tif_mod != 0 )
    out->type.set_modifiers(tif_mod);
  return true;
}


//----------------------------------------------------------------------------
bool til_builder_t::handle_symbol_at_ea(pdb_sym_t &/*sym*/, DWORD /*tag*/, ea_t /*ea*/, qstring & /*name*/)
{
  return true;
}


//----------------------------------------------------------------------------
HRESULT til_builder_t::handle_symbol(pdb_sym_t &sym)
{
  DWORD id;
  HRESULT hr = sym.get_symIndexId(&id);
  if ( FAILED(hr) )
    return hr;

  if ( handled.find(id) != handled.end() )
    return S_OK;
  handled.insert(id);

  DWORD tag = 0;
  hr = sym.get_symTag(&tag);
  if ( FAILED(hr) )
    return hr;

  switch ( tag )
  {
    case SymTagNull:
    case SymTagExe:
    case SymTagCompiland:
    case SymTagCompilandEnv:
    case SymTagCustom:
    case SymTagCustomType:
    case SymTagManagedType:
    case SymTagUDT:
    case SymTagEnum:
    case SymTagFunctionType:
    case SymTagPointerType:
    case SymTagArrayType:
    case SymTagBaseType:
    case SymTagTypedef:
    case SymTagBaseClass:
    case SymTagFunctionArgType:
    case SymTagUsingNamespace:
    case SymTagVTableShape:
    case SymTagDimension:
      return S_OK;
    case SymTagCompilandDetails:
      {
        DWORD backEndVer;
        if ( is_intel386(pdb_access->get_machine_type()) && sym.get_backEndMajor(&backEndVer) == S_OK )
          enregistered_bug = backEndVer <= 13;
      }
      return S_OK;
    // new tags for msdia140
    case SymTagCoffGroup:
      return S_OK;
    default:
      break;
  }

  DWORD off = 0;
  hr = sym.get_relativeVirtualAddress(&off);
  if ( hr == S_OK )
  {
    ea_t ea = get_load_address() + off;
    qstring name;
    sym.get_name(&name);
    handle_symbol_at_ea(sym, tag, ea, name);
  }
  return S_OK;
}


//----------------------------------------------------------------------
// Each time we encounter a toplevel type/func/whatever, we want to make
// sure the UI has had a chance to refresh itself.
struct toplevel_children_visitor_t : public pdb_access_t::children_visitor_t
{
  virtual HRESULT visit_child(pdb_sym_t &sym) override
  {
    user_cancelled();
    return do_visit_child(sym);
  }

  virtual HRESULT do_visit_child(pdb_sym_t &sym) = 0;
};

//-------------------------------------------------------------------------
struct symbol_handler_t : public toplevel_children_visitor_t
{
  virtual HRESULT do_visit_child(pdb_sym_t &sym) override
  {
    return tb->handle_symbol(sym);
  }
  symbol_handler_t(til_builder_t *_tb) : tb(_tb) {}
  til_builder_t *tb;
};

//-------------------------------------------------------------------------
HRESULT til_builder_t::handle_symbols(pdb_sym_t &global_sym)
{
  symbol_handler_t cp(this);
  HRESULT hr;
  while ( true )
  {
    hr = pdb_access->iterate_subtags(global_sym, SymTagNull, cp);
    if ( FAILED(hr) )
      break;
    if ( !iterate_symbols_once_more(global_sym) )
      break;
  }
  return hr;
}

//-------------------------------------------------------------------------
HRESULT til_builder_t::handle_publics(pdb_sym_t &global_sym)
{
  symbol_handler_t cp(this);
  return pdb_access->iterate_children(global_sym, SymTagPublicSymbol, cp);
}

//-------------------------------------------------------------------------
HRESULT til_builder_t::handle_globals(pdb_sym_t &global_sym)
{
  symbol_handler_t cp(this);
  return pdb_access->iterate_children(global_sym, SymTagData, cp);
}


//----------------------------------------------------------------------
HRESULT til_builder_t::handle_types(pdb_sym_t &global_sym)
{
  struct type_importer_t : public toplevel_children_visitor_t
  {
    til_builder_t *tb;
    int counter;
    virtual HRESULT do_visit_child(pdb_sym_t &sym) override
    {
      tpinfo_t tpi;
      if ( tb->retrieve_type(&tpi, sym, parent) )
        counter++;
      return S_OK;
    }
    type_importer_t(til_builder_t *_tb) : tb(_tb), counter(0) {}
  };
  type_importer_t timp(this);
  HRESULT hr = pdb_access->iterate_children(global_sym, SymTagEnum, timp);
  if ( hr == S_OK )
    hr = pdb_access->iterate_children(global_sym, SymTagUDT, timp);
  if ( hr == S_OK )
    hr = pdb_access->iterate_children(global_sym, SymTagTypedef, timp);
  msg("PDB: loaded %d type%s\n", timp.counter, timp.counter != 1 ? "s" : "");
  return hr;
}


//----------------------------------------------------------------------------
HRESULT til_builder_t::before_iterating(pdb_sym_t &)
{
  return S_OK;
}


//----------------------------------------------------------------------------
HRESULT til_builder_t::after_iterating(pdb_sym_t &)
{
  return S_OK;
}

//----------------------------------------------------------------------------
HRESULT til_builder_t::build(pdb_sym_t &global_sym)
{
  HRESULT hr = before_iterating(global_sym);
  if ( hr == S_OK && (pdb_access->pdbargs.flags & PDBFLG_LOAD_TYPES) != 0 )
  {
      if ((pdb_access->pdbargs.flags & PDBFLG_IS_MINIPDB) == 0)
      {
          hr = handle_types(global_sym);
      }
  }
  if ( (pdb_access->pdbargs.flags & PDBFLG_LOAD_NAMES) != 0 )
  {
      if ((pdb_access->pdbargs.flags & PDBFLG_IS_MINIPDB) == 0)
      {
          if (hr == S_OK)
              hr = handle_symbols(global_sym);
          if (hr == S_OK)
              hr = handle_globals(global_sym);
      }
    // handle_globals() will set the type and undecorated name for globals,
    // and handle_publics() will set the decorated name for public symbols.
    // We want both the type (from handle_globals()) and the decorated symbol
    // name (from handle_publics()), since that gives the user more information
    // about the variable and enables FLIRT to match rulefuncs based on the
    // symbol name.
    // For example, @__security_check_cookie@4 is used as a rulefunc by FLIRT,
    // and that won't match with the undecorated name __security_check_cookie.
    // Therefore, handle_publics() must be called *after* handle_globals().
    if ( hr == S_OK )
      hr = handle_publics(global_sym);
  }
  if ( hr == S_OK )
  {
    create_vftables();
    hr = after_iterating(global_sym);
  }
  return hr;
}
