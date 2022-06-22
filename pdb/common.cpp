
#include "pdbaccess.hpp"

//----------------------------------------------------------------------------
static const char g_spath_prefix[] = "srv*";
static const char g_spath_suffix[] = "*http://msdl.microsoft.com/download/symbols";

//----------------------------------------------------------------------------
HRESULT pdb_access_t::iterate_subtags(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  struct subtag_helper_t : children_visitor_t
  {
    pdb_access_t *tb;
    enum SymTagEnum type;
    children_visitor_t &visitor;
    virtual HRESULT visit_child(pdb_sym_t &_sym) override
    {
      return tb->iterate_children(_sym, type, visitor);
    }
    subtag_helper_t(pdb_access_t *_tb, enum SymTagEnum t, children_visitor_t &_visitor)
      : tb(_tb),
        type(t),
        visitor(_visitor) {}
  };
  subtag_helper_t helper(this, type, visitor);
  return iterate_children(sym, SymTagCompiland, helper);
}

//----------------------------------------------------------------------------
HRESULT pdb_access_t::iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  visitor.parent = &sym;
  return do_iterate_children(sym, type, visitor);
}

//----------------------------------------------------------------------
void print_pdb_register(qstring *out, int machine, int reg)
{
  // Register subset shared by all processor types,
  switch ( reg )
  {
    case CV_ALLREG_ERR:    *out = "[*err*]"; return;
    case CV_ALLREG_TEB:    *out = "[*teb*]"; return;
    case CV_ALLREG_TIMER:  *out = "[*timer*]"; return;
    case CV_ALLREG_EFAD1:  *out = "[*efad1*]"; return;
    case CV_ALLREG_EFAD2:  *out = "[*efad2*]"; return;
    case CV_ALLREG_EFAD3:  *out = "[*efad3*]"; return;
    case CV_ALLREG_VFRAME: *out = "[*vframe*]"; return;
    case CV_ALLREG_HANDLE: *out = "[*handle*]"; return;
    case CV_ALLREG_PARAMS: *out = "[*params*]"; return;
    case CV_ALLREG_LOCALS: *out = "[*locals*]"; return;
    case CV_ALLREG_TID:    *out = "[*tid*]"; return;
    case CV_ALLREG_ENV:    *out = "[*env*]"; return;
    case CV_ALLREG_CMDLN:  *out = "[*cmdln*]"; return;
  }

  // Processor specific subsets
  switch ( machine )
  {
    case CV_CFL_8080:
    case CV_CFL_8086:
    case CV_CFL_80286:
    case CV_CFL_80386:
    case CV_CFL_80486:
    case CV_CFL_PENTIUM:
    case CV_CFL_PENTIUMII:
    case CV_CFL_PENTIUMIII:
      //  Register set for the Intel 80x86 and ix86 processor series
      //  (plus PCODE registers)
      switch ( reg )
      {
        case CV_REG_NONE:    *out = "none"; return;
        case CV_REG_AL:      *out = "al"; return;
        case CV_REG_CL:      *out = "cl"; return;
        case CV_REG_DL:      *out = "dl"; return;
        case CV_REG_BL:      *out = "bl"; return;
        case CV_REG_AH:      *out = "ah"; return;
        case CV_REG_CH:      *out = "ch"; return;
        case CV_REG_DH:      *out = "dh"; return;
        case CV_REG_BH:      *out = "bh"; return;
        case CV_REG_AX:      *out = "ax"; return;
        case CV_REG_CX:      *out = "cx"; return;
        case CV_REG_DX:      *out = "dx"; return;
        case CV_REG_BX:      *out = "bx"; return;
        case CV_REG_SP:      *out = "sp"; return;
        case CV_REG_BP:      *out = "bp"; return;
        case CV_REG_SI:      *out = "si"; return;
        case CV_REG_DI:      *out = "di"; return;
        case CV_REG_EAX:     *out = "eax"; return;
        case CV_REG_ECX:     *out = "ecx"; return;
        case CV_REG_EDX:     *out = "edx"; return;
        case CV_REG_EBX:     *out = "ebx"; return;
        case CV_REG_ESP:     *out = "esp"; return;
        case CV_REG_EBP:     *out = "ebp"; return;
        case CV_REG_ESI:     *out = "esi"; return;
        case CV_REG_EDI:     *out = "edi"; return;
        case CV_REG_ES:      *out = "es"; return;
        case CV_REG_CS:      *out = "cs"; return;
        case CV_REG_SS:      *out = "ss"; return;
        case CV_REG_DS:      *out = "ds"; return;
        case CV_REG_FS:      *out = "fs"; return;
        case CV_REG_GS:      *out = "gs"; return;
        case CV_REG_IP:      *out = "ip"; return;
        case CV_REG_FLAGS:   *out = "flags"; return;
        case CV_REG_EIP:     *out = "eip"; return;
        case CV_REG_EFLAGS:  *out = "eflags"; return;
        case CV_REG_TEMP:    *out = "temp"; return;          // PCODE Temp return;
        case CV_REG_TEMPH:   *out = "temph"; return;         // PCODE TempH return;
        case CV_REG_QUOTE:   *out = "quote"; return;         // PCODE Quote return;
        case CV_REG_PCDR3:   *out = "pcdr3"; return;         // PCODE reserved return;
        case CV_REG_PCDR4:   *out = "pcdr4"; return;         // PCODE reserved return;
        case CV_REG_PCDR5:   *out = "pcdr5"; return;         // PCODE reserved return;
        case CV_REG_PCDR6:   *out = "pcdr6"; return;         // PCODE reserved return;
        case CV_REG_PCDR7:   *out = "pcdr7"; return;         // PCODE reserved return;
        case CV_REG_CR0:     *out = "cr0"; return;           // CR0 -- control registers return;
        case CV_REG_CR1:     *out = "cr1"; return;
        case CV_REG_CR2:     *out = "cr2"; return;
        case CV_REG_CR3:     *out = "cr3"; return;
        case CV_REG_CR4:     *out = "cr4"; return;           // Pentium return;
        case CV_REG_DR0:     *out = "dr0"; return;           // Debug register return;
        case CV_REG_DR1:     *out = "dr1"; return;
        case CV_REG_DR2:     *out = "dr2"; return;
        case CV_REG_DR3:     *out = "dr3"; return;
        case CV_REG_DR4:     *out = "dr4"; return;
        case CV_REG_DR5:     *out = "dr5"; return;
        case CV_REG_DR6:     *out = "dr6"; return;
        case CV_REG_DR7:     *out = "dr7"; return;
        case CV_REG_GDTR:    *out = "gdtr"; return;
        case CV_REG_GDTL:    *out = "gdtl"; return;
        case CV_REG_IDTR:    *out = "idtr"; return;
        case CV_REG_IDTL:    *out = "idtl"; return;
        case CV_REG_LDTR:    *out = "ldtr"; return;
        case CV_REG_TR:      *out = "tr"; return;

        case CV_REG_PSEUDO1: *out = "pseudo1"; return;
        case CV_REG_PSEUDO2: *out = "pseudo2"; return;
        case CV_REG_PSEUDO3: *out = "pseudo3"; return;
        case CV_REG_PSEUDO4: *out = "pseudo4"; return;
        case CV_REG_PSEUDO5: *out = "pseudo5"; return;
        case CV_REG_PSEUDO6: *out = "pseudo6"; return;
        case CV_REG_PSEUDO7: *out = "pseudo7"; return;
        case CV_REG_PSEUDO8: *out = "pseudo8"; return;
        case CV_REG_PSEUDO9: *out = "pseudo9"; return;

        case CV_REG_ST0:     *out = "st0"; return;
        case CV_REG_ST1:     *out = "st1"; return;
        case CV_REG_ST2:     *out = "st2"; return;
        case CV_REG_ST3:     *out = "st3"; return;
        case CV_REG_ST4:     *out = "st4"; return;
        case CV_REG_ST5:     *out = "st5"; return;
        case CV_REG_ST6:     *out = "st6"; return;
        case CV_REG_ST7:     *out = "st7"; return;
        case CV_REG_CTRL:    *out = "ctrl"; return;
        case CV_REG_STAT:    *out = "stat"; return;
        case CV_REG_TAG:     *out = "tag"; return;
        case CV_REG_FPIP:    *out = "fpip"; return;
        case CV_REG_FPCS:    *out = "fpcs"; return;
        case CV_REG_FPDO:    *out = "fpdo"; return;
        case CV_REG_FPDS:    *out = "fpds"; return;
        case CV_REG_ISEM:    *out = "isem"; return;
        case CV_REG_FPEIP:   *out = "fpeip"; return;
        case CV_REG_FPEDO:   *out = "fpedo"; return;

        case CV_REG_MM0:     *out = "mm0"; return;
        case CV_REG_MM1:     *out = "mm1"; return;
        case CV_REG_MM2:     *out = "mm2"; return;
        case CV_REG_MM3:     *out = "mm3"; return;
        case CV_REG_MM4:     *out = "mm4"; return;
        case CV_REG_MM5:     *out = "mm5"; return;
        case CV_REG_MM6:     *out = "mm6"; return;
        case CV_REG_MM7:     *out = "mm7"; return;

        case CV_REG_XMM0:    *out = "xmm0"; return; // KATMAI registers return;
        case CV_REG_XMM1:    *out = "xmm1"; return;
        case CV_REG_XMM2:    *out = "xmm2"; return;
        case CV_REG_XMM3:    *out = "xmm3"; return;
        case CV_REG_XMM4:    *out = "xmm4"; return;
        case CV_REG_XMM5:    *out = "xmm5"; return;
        case CV_REG_XMM6:    *out = "xmm6"; return;
        case CV_REG_XMM7:    *out = "xmm7"; return;

        case CV_REG_XMM00:   *out = "xmm00"; return; // KATMAI sub-registers return;
        case CV_REG_XMM01:   *out = "xmm01"; return;
        case CV_REG_XMM02:   *out = "xmm02"; return;
        case CV_REG_XMM03:   *out = "xmm03"; return;
        case CV_REG_XMM10:   *out = "xmm10"; return;
        case CV_REG_XMM11:   *out = "xmm11"; return;
        case CV_REG_XMM12:   *out = "xmm12"; return;
        case CV_REG_XMM13:   *out = "xmm13"; return;
        case CV_REG_XMM20:   *out = "xmm20"; return;
        case CV_REG_XMM21:   *out = "xmm21"; return;
        case CV_REG_XMM22:   *out = "xmm22"; return;
        case CV_REG_XMM23:   *out = "xmm23"; return;
        case CV_REG_XMM30:   *out = "xmm30"; return;
        case CV_REG_XMM31:   *out = "xmm31"; return;
        case CV_REG_XMM32:   *out = "xmm32"; return;
        case CV_REG_XMM33:   *out = "xmm33"; return;
        case CV_REG_XMM40:   *out = "xmm40"; return;
        case CV_REG_XMM41:   *out = "xmm41"; return;
        case CV_REG_XMM42:   *out = "xmm42"; return;
        case CV_REG_XMM43:   *out = "xmm43"; return;
        case CV_REG_XMM50:   *out = "xmm50"; return;
        case CV_REG_XMM51:   *out = "xmm51"; return;
        case CV_REG_XMM52:   *out = "xmm52"; return;
        case CV_REG_XMM53:   *out = "xmm53"; return;
        case CV_REG_XMM60:   *out = "xmm60"; return;
        case CV_REG_XMM61:   *out = "xmm61"; return;
        case CV_REG_XMM62:   *out = "xmm62"; return;
        case CV_REG_XMM63:   *out = "xmm63"; return;
        case CV_REG_XMM70:   *out = "xmm70"; return;
        case CV_REG_XMM71:   *out = "xmm71"; return;
        case CV_REG_XMM72:   *out = "xmm72"; return;
        case CV_REG_XMM73:   *out = "xmm73"; return;

        case CV_REG_XMM0L:   *out = "xmm0l"; return;
        case CV_REG_XMM1L:   *out = "xmm1l"; return;
        case CV_REG_XMM2L:   *out = "xmm2l"; return;
        case CV_REG_XMM3L:   *out = "xmm3l"; return;
        case CV_REG_XMM4L:   *out = "xmm4l"; return;
        case CV_REG_XMM5L:   *out = "xmm5l"; return;
        case CV_REG_XMM6L:   *out = "xmm6l"; return;
        case CV_REG_XMM7L:   *out = "xmm7l"; return;

        case CV_REG_XMM0H:   *out = "xmm0h"; return;
        case CV_REG_XMM1H:   *out = "xmm1h"; return;
        case CV_REG_XMM2H:   *out = "xmm2h"; return;
        case CV_REG_XMM3H:   *out = "xmm3h"; return;
        case CV_REG_XMM4H:   *out = "xmm4h"; return;
        case CV_REG_XMM5H:   *out = "xmm5h"; return;
        case CV_REG_XMM6H:   *out = "xmm6h"; return;
        case CV_REG_XMM7H:   *out = "xmm7h"; return;

        case CV_REG_MXCSR:   *out = "mxcsr"; return; // XMM status register

        case CV_REG_EDXEAX:  *out = "edxeax"; return; // EDX";EAX pair

        case CV_REG_EMM0L:   *out = "emm0l"; return;  // XMM sub-registers (WNI integer)
        case CV_REG_EMM1L:   *out = "emm1l"; return;
        case CV_REG_EMM2L:   *out = "emm2l"; return;
        case CV_REG_EMM3L:   *out = "emm3l"; return;
        case CV_REG_EMM4L:   *out = "emm4l"; return;
        case CV_REG_EMM5L:   *out = "emm5l"; return;
        case CV_REG_EMM6L:   *out = "emm6l"; return;
        case CV_REG_EMM7L:   *out = "emm7l"; return;

        case CV_REG_EMM0H:   *out = "emm0h"; return;
        case CV_REG_EMM1H:   *out = "emm1h"; return;
        case CV_REG_EMM2H:   *out = "emm2h"; return;
        case CV_REG_EMM3H:   *out = "emm3h"; return;
        case CV_REG_EMM4H:   *out = "emm4h"; return;
        case CV_REG_EMM5H:   *out = "emm5h"; return;
        case CV_REG_EMM6H:   *out = "emm6h"; return;
        case CV_REG_EMM7H:   *out = "emm7h"; return;


        case CV_REG_MM00:    *out = "mm00"; return; // do not change the order of these regs, first one must be even too
        case CV_REG_MM01:    *out = "mm01"; return;
        case CV_REG_MM10:    *out = "mm10"; return;
        case CV_REG_MM11:    *out = "mm11"; return;
        case CV_REG_MM20:    *out = "mm20"; return;
        case CV_REG_MM21:    *out = "mm21"; return;
        case CV_REG_MM30:    *out = "mm30"; return;
        case CV_REG_MM31:    *out = "mm31"; return;
        case CV_REG_MM40:    *out = "mm40"; return;
        case CV_REG_MM41:    *out = "mm41"; return;
        case CV_REG_MM50:    *out = "mm50"; return;
        case CV_REG_MM51:    *out = "mm51"; return;
        case CV_REG_MM60:    *out = "mm60"; return;
        case CV_REG_MM61:    *out = "mm61"; return;
        case CV_REG_MM70:    *out = "mm70"; return;
        case CV_REG_MM71:    *out = "mm71"; return;
      }
      break;

      // registers for the 68K processors
    case CV_CFL_M68000:
    case CV_CFL_M68010:
    case CV_CFL_M68020:
    case CV_CFL_M68030:
    case CV_CFL_M68040:
      switch ( reg )
      {
        case CV_R68_D0:      *out = "D0"; return;
        case CV_R68_D1:      *out = "D1"; return;
        case CV_R68_D2:      *out = "D2"; return;
        case CV_R68_D3:      *out = "D3"; return;
        case CV_R68_D4:      *out = "D4"; return;
        case CV_R68_D5:      *out = "D5"; return;
        case CV_R68_D6:      *out = "D6"; return;
        case CV_R68_D7:      *out = "D7"; return;
        case CV_R68_A0:      *out = "A0"; return;
        case CV_R68_A1:      *out = "A1"; return;
        case CV_R68_A2:      *out = "A2"; return;
        case CV_R68_A3:      *out = "A3"; return;
        case CV_R68_A4:      *out = "A4"; return;
        case CV_R68_A5:      *out = "A5"; return;
        case CV_R68_A6:      *out = "A6"; return;
        case CV_R68_A7:      *out = "A7"; return;
        case CV_R68_CCR:     *out = "CCR"; return;
        case CV_R68_SR:      *out = "SR"; return;
        case CV_R68_USP:     *out = "USP"; return;
        case CV_R68_MSP:     *out = "MSP"; return;
        case CV_R68_SFC:     *out = "SFC"; return;
        case CV_R68_DFC:     *out = "DFC"; return;
        case CV_R68_CACR:    *out = "CACR"; return;
        case CV_R68_VBR:     *out = "VBR"; return;
        case CV_R68_CAAR:    *out = "CAAR"; return;
        case CV_R68_ISP:     *out = "ISP"; return;
        case CV_R68_PC:      *out = "PC"; return;
        // reserved  27
        case CV_R68_FPCR:    *out = "FPCR"; return;
        case CV_R68_FPSR:    *out = "FPSR"; return;
        case CV_R68_FPIAR:   *out = "FPIAR"; return;
        // reserved  31
        case CV_R68_FP0:     *out = "FP0"; return;
        case CV_R68_FP1:     *out = "FP1"; return;
        case CV_R68_FP2:     *out = "FP2"; return;
        case CV_R68_FP3:     *out = "FP3"; return;
        case CV_R68_FP4:     *out = "FP4"; return;
        case CV_R68_FP5:     *out = "FP5"; return;
        case CV_R68_FP6:     *out = "FP6"; return;
        case CV_R68_FP7:     *out = "FP7"; return;
        // reserved  40
        case CV_R68_MMUSR030:*out = "MMUSR030"; return;
        case CV_R68_MMUSR:   *out = "MMUSR"; return;
        case CV_R68_URP:     *out = "URP"; return;
        case CV_R68_DTT0:    *out = "DTT0"; return;
        case CV_R68_DTT1:    *out = "DTT1"; return;
        case CV_R68_ITT0:    *out = "ITT0"; return;
        case CV_R68_ITT1:    *out = "ITT1"; return;
        // reserved  50
        case CV_R68_PSR:     *out = "PSR"; return;
        case CV_R68_PCSR:    *out = "PCSR"; return;
        case CV_R68_VAL:     *out = "VAL"; return;
        case CV_R68_CRP:     *out = "CRP"; return;
        case CV_R68_SRP:     *out = "SRP"; return;
        case CV_R68_DRP:     *out = "DRP"; return;
        case CV_R68_TC:      *out = "TC"; return;
        case CV_R68_AC:      *out = "AC"; return;
        case CV_R68_SCC:     *out = "SCC"; return;
        case CV_R68_CAL:     *out = "CAL"; return;
        case CV_R68_TT0:     *out = "TT0"; return;
        case CV_R68_TT1:     *out = "TT1"; return;
        // reserved  63
        case CV_R68_BAD0:    *out = "BAD0"; return;
        case CV_R68_BAD1:    *out = "BAD1"; return;
        case CV_R68_BAD2:    *out = "BAD2"; return;
        case CV_R68_BAD3:    *out = "BAD3"; return;
        case CV_R68_BAD4:    *out = "BAD4"; return;
        case CV_R68_BAD5:    *out = "BAD5"; return;
        case CV_R68_BAD6:    *out = "BAD6"; return;
        case CV_R68_BAD7:    *out = "BAD7"; return;
        case CV_R68_BAC0:    *out = "BAC0"; return;
        case CV_R68_BAC1:    *out = "BAC1"; return;
        case CV_R68_BAC2:    *out = "BAC2"; return;
        case CV_R68_BAC3:    *out = "BAC3"; return;
        case CV_R68_BAC4:    *out = "BAC4"; return;
        case CV_R68_BAC5:    *out = "BAC5"; return;
        case CV_R68_BAC6:    *out = "BAC6"; return;
        case CV_R68_BAC7:    *out = "BAC7"; return;
      }
      break;

    case CV_CFL_MIPS:
    case CV_CFL_MIPS16:
    case CV_CFL_MIPS32:
    case CV_CFL_MIPS64:
    case CV_CFL_MIPSI:
    case CV_CFL_MIPSII:
    case CV_CFL_MIPSIII:
    case CV_CFL_MIPSIV:
    case CV_CFL_MIPSV:
      switch ( reg )
      {
        // Register set for the MIPS 4000
        case CV_M4_NOREG:    *out = "NOREG"; return;
        case CV_M4_IntZERO:  *out = "IntZERO"; return;    /* CPU REGISTER */
        case CV_M4_IntAT:    *out = "IntAT"; return;
        case CV_M4_IntV0:    *out = "IntV0"; return;
        case CV_M4_IntV1:    *out = "IntV1"; return;
        case CV_M4_IntA0:    *out = "IntA0"; return;
        case CV_M4_IntA1:    *out = "IntA1"; return;
        case CV_M4_IntA2:    *out = "IntA2"; return;
        case CV_M4_IntA3:    *out = "IntA3"; return;
        case CV_M4_IntT0:    *out = "IntT0"; return;
        case CV_M4_IntT1:    *out = "IntT1"; return;
        case CV_M4_IntT2:    *out = "IntT2"; return;
        case CV_M4_IntT3:    *out = "IntT3"; return;
        case CV_M4_IntT4:    *out = "IntT4"; return;
        case CV_M4_IntT5:    *out = "IntT5"; return;
        case CV_M4_IntT6:    *out = "IntT6"; return;
        case CV_M4_IntT7:    *out = "IntT7"; return;
        case CV_M4_IntS0:    *out = "IntS0"; return;
        case CV_M4_IntS1:    *out = "IntS1"; return;
        case CV_M4_IntS2:    *out = "IntS2"; return;
        case CV_M4_IntS3:    *out = "IntS3"; return;
        case CV_M4_IntS4:    *out = "IntS4"; return;
        case CV_M4_IntS5:    *out = "IntS5"; return;
        case CV_M4_IntS6:    *out = "IntS6"; return;
        case CV_M4_IntS7:    *out = "IntS7"; return;
        case CV_M4_IntT8:    *out = "IntT8"; return;
        case CV_M4_IntT9:    *out = "IntT9"; return;
        case CV_M4_IntKT0:   *out = "IntKT0"; return;
        case CV_M4_IntKT1:   *out = "IntKT1"; return;
        case CV_M4_IntGP:    *out = "IntGP"; return;
        case CV_M4_IntSP:    *out = "IntSP"; return;
        case CV_M4_IntS8:    *out = "IntS8"; return;
        case CV_M4_IntRA:    *out = "IntRA"; return;
        case CV_M4_IntLO:    *out = "IntLO"; return;
        case CV_M4_IntHI:    *out = "IntHI"; return;

        case CV_M4_Fir:
        case CV_M4_Psr:

        case CV_M4_FltF0:    *out = "FltF0"; return; /* Floating point registers */
        case CV_M4_FltF1:    *out = "FltF1"; return;
        case CV_M4_FltF2:    *out = "FltF2"; return;
        case CV_M4_FltF3:    *out = "FltF3"; return;
        case CV_M4_FltF4:    *out = "FltF4"; return;
        case CV_M4_FltF5:    *out = "FltF5"; return;
        case CV_M4_FltF6:    *out = "FltF6"; return;
        case CV_M4_FltF7:    *out = "FltF7"; return;
        case CV_M4_FltF8:    *out = "FltF8"; return;
        case CV_M4_FltF9:    *out = "FltF9"; return;
        case CV_M4_FltF10:   *out = "FltF10"; return;
        case CV_M4_FltF11:   *out = "FltF11"; return;
        case CV_M4_FltF12:   *out = "FltF12"; return;
        case CV_M4_FltF13:   *out = "FltF13"; return;
        case CV_M4_FltF14:   *out = "FltF14"; return;
        case CV_M4_FltF15:   *out = "FltF15"; return;
        case CV_M4_FltF16:   *out = "FltF16"; return;
        case CV_M4_FltF17:   *out = "FltF17"; return;
        case CV_M4_FltF18:   *out = "FltF18"; return;
        case CV_M4_FltF19:   *out = "FltF19"; return;
        case CV_M4_FltF20:   *out = "FltF20"; return;
        case CV_M4_FltF21:   *out = "FltF21"; return;
        case CV_M4_FltF22:   *out = "FltF22"; return;
        case CV_M4_FltF23:   *out = "FltF23"; return;
        case CV_M4_FltF24:   *out = "FltF24"; return;
        case CV_M4_FltF25:   *out = "FltF25"; return;
        case CV_M4_FltF26:   *out = "FltF26"; return;
        case CV_M4_FltF27:   *out = "FltF27"; return;
        case CV_M4_FltF28:   *out = "FltF28"; return;
        case CV_M4_FltF29:   *out = "FltF29"; return;
        case CV_M4_FltF30:   *out = "FltF30"; return;
        case CV_M4_FltF31:   *out = "FltF31"; return;
        case CV_M4_FltFsr:   *out = "FltFsr"; return;
      }
      break;

    case CV_CFL_ALPHA:
//    case CV_CFL_ALPHA_21064:
    case CV_CFL_ALPHA_21164:
    case CV_CFL_ALPHA_21164A:
    case CV_CFL_ALPHA_21264:
    case CV_CFL_ALPHA_21364:
      // Register set for the ALPHA AXP
      switch ( reg )
      {
        case CV_ALPHA_NOREG: *out = "NOREG"; return;
        case CV_ALPHA_FltF0: *out = "FltF0"; return; // Floating point registers
        case CV_ALPHA_FltF1: *out = "FltF1"; return;
        case CV_ALPHA_FltF2: *out = "FltF2"; return;
        case CV_ALPHA_FltF3: *out = "FltF3"; return;
        case CV_ALPHA_FltF4: *out = "FltF4"; return;
        case CV_ALPHA_FltF5: *out = "FltF5"; return;
        case CV_ALPHA_FltF6: *out = "FltF6"; return;
        case CV_ALPHA_FltF7: *out = "FltF7"; return;
        case CV_ALPHA_FltF8: *out = "FltF8"; return;
        case CV_ALPHA_FltF9: *out = "FltF9"; return;
        case CV_ALPHA_FltF10:*out = "FltF10"; return;
        case CV_ALPHA_FltF11:*out = "FltF11"; return;
        case CV_ALPHA_FltF12:*out = "FltF12"; return;
        case CV_ALPHA_FltF13:*out = "FltF13"; return;
        case CV_ALPHA_FltF14:*out = "FltF14"; return;
        case CV_ALPHA_FltF15:*out = "FltF15"; return;
        case CV_ALPHA_FltF16:*out = "FltF16"; return;
        case CV_ALPHA_FltF17:*out = "FltF17"; return;
        case CV_ALPHA_FltF18:*out = "FltF18"; return;
        case CV_ALPHA_FltF19:*out = "FltF19"; return;
        case CV_ALPHA_FltF20:*out = "FltF20"; return;
        case CV_ALPHA_FltF21:*out = "FltF21"; return;
        case CV_ALPHA_FltF22:*out = "FltF22"; return;
        case CV_ALPHA_FltF23:*out = "FltF23"; return;
        case CV_ALPHA_FltF24:*out = "FltF24"; return;
        case CV_ALPHA_FltF25:*out = "FltF25"; return;
        case CV_ALPHA_FltF26:*out = "FltF26"; return;
        case CV_ALPHA_FltF27:*out = "FltF27"; return;
        case CV_ALPHA_FltF28:*out = "FltF28"; return;
        case CV_ALPHA_FltF29:*out = "FltF29"; return;
        case CV_ALPHA_FltF30:*out = "FltF30"; return;
        case CV_ALPHA_FltF31:*out = "FltF31"; return;

        case CV_ALPHA_IntV0: *out = "IntV0"; return; // Integer registers
        case CV_ALPHA_IntT0: *out = "IntT0"; return;
        case CV_ALPHA_IntT1: *out = "IntT1"; return;
        case CV_ALPHA_IntT2: *out = "IntT2"; return;
        case CV_ALPHA_IntT3: *out = "IntT3"; return;
        case CV_ALPHA_IntT4: *out = "IntT4"; return;
        case CV_ALPHA_IntT5: *out = "IntT5"; return;
        case CV_ALPHA_IntT6: *out = "IntT6"; return;
        case CV_ALPHA_IntT7: *out = "IntT7"; return;
        case CV_ALPHA_IntS0: *out = "IntS0"; return;
        case CV_ALPHA_IntS1: *out = "IntS1"; return;
        case CV_ALPHA_IntS2: *out = "IntS2"; return;
        case CV_ALPHA_IntS3: *out = "IntS3"; return;
        case CV_ALPHA_IntS4: *out = "IntS4"; return;
        case CV_ALPHA_IntS5: *out = "IntS5"; return;
        case CV_ALPHA_IntFP: *out = "IntFP"; return;
        case CV_ALPHA_IntA0: *out = "IntA0"; return;
        case CV_ALPHA_IntA1: *out = "IntA1"; return;
        case CV_ALPHA_IntA2: *out = "IntA2"; return;
        case CV_ALPHA_IntA3: *out = "IntA3"; return;
        case CV_ALPHA_IntA4: *out = "IntA4"; return;
        case CV_ALPHA_IntA5: *out = "IntA5"; return;
        case CV_ALPHA_IntT8: *out = "IntT8"; return;
        case CV_ALPHA_IntT9: *out = "IntT9"; return;
        case CV_ALPHA_IntT10:*out = "IntT10"; return;
        case CV_ALPHA_IntT11:*out = "IntT11"; return;
        case CV_ALPHA_IntRA: *out = "IntRA"; return;
        case CV_ALPHA_IntT12:*out = "IntT12"; return;
        case CV_ALPHA_IntAT: *out = "IntAT"; return;
        case CV_ALPHA_IntGP: *out = "IntGP"; return;
        case CV_ALPHA_IntSP: *out = "IntSP"; return;
        case CV_ALPHA_IntZERO:*out = "IntZERO"; return;

        case CV_ALPHA_Fpcr:  *out = "Fpcr"; return; // Control registers
        case CV_ALPHA_Fir:   *out = "Fir"; return;
        case CV_ALPHA_Psr:   *out = "Psr"; return;
        case CV_ALPHA_FltFsr:*out = "FltFsr"; return;
        case CV_ALPHA_SoftFpcr:*out = "SoftFpcr"; return;
      }
      break;

    case CV_CFL_PPC601:
    case CV_CFL_PPC603:
    case CV_CFL_PPC604:
    case CV_CFL_PPC620:
    case CV_CFL_PPCFP:
    case CV_CFL_PPCBE:
      // Register Set for Motorola/IBM PowerPC
      switch ( reg )
      {
        /*
        ** PowerPC General Registers ( User Level )
        */
        case CV_PPC_GPR0:    *out = "gpr0"; return;
        case CV_PPC_GPR1:    *out = "gpr1"; return;
        case CV_PPC_GPR2:    *out = "gpr2"; return;
        case CV_PPC_GPR3:    *out = "gpr3"; return;
        case CV_PPC_GPR4:    *out = "gpr4"; return;
        case CV_PPC_GPR5:    *out = "gpr5"; return;
        case CV_PPC_GPR6:    *out = "gpr6"; return;
        case CV_PPC_GPR7:    *out = "gpr7"; return;
        case CV_PPC_GPR8:    *out = "gpr8"; return;
        case CV_PPC_GPR9:    *out = "gpr9"; return;
        case CV_PPC_GPR10:   *out = "gpr10"; return;
        case CV_PPC_GPR11:   *out = "gpr11"; return;
        case CV_PPC_GPR12:   *out = "gpr12"; return;
        case CV_PPC_GPR13:   *out = "gpr13"; return;
        case CV_PPC_GPR14:   *out = "gpr14"; return;
        case CV_PPC_GPR15:   *out = "gpr15"; return;
        case CV_PPC_GPR16:   *out = "gpr16"; return;
        case CV_PPC_GPR17:   *out = "gpr17"; return;
        case CV_PPC_GPR18:   *out = "gpr18"; return;
        case CV_PPC_GPR19:   *out = "gpr19"; return;
        case CV_PPC_GPR20:   *out = "gpr20"; return;
        case CV_PPC_GPR21:   *out = "gpr21"; return;
        case CV_PPC_GPR22:   *out = "gpr22"; return;
        case CV_PPC_GPR23:   *out = "gpr23"; return;
        case CV_PPC_GPR24:   *out = "gpr24"; return;
        case CV_PPC_GPR25:   *out = "gpr25"; return;
        case CV_PPC_GPR26:   *out = "gpr26"; return;
        case CV_PPC_GPR27:   *out = "gpr27"; return;
        case CV_PPC_GPR28:   *out = "gpr28"; return;
        case CV_PPC_GPR29:   *out = "gpr29"; return;
        case CV_PPC_GPR30:   *out = "gpr30"; return;
        case CV_PPC_GPR31:   *out = "gpr31"; return;

        /*
        ** PowerPC Condition Register ( user level )
        */
        case CV_PPC_CR:      *out = "cr"; return;
        case CV_PPC_CR0:     *out = "cr0"; return;
        case CV_PPC_CR1:     *out = "cr1"; return;
        case CV_PPC_CR2:     *out = "cr2"; return;
        case CV_PPC_CR3:     *out = "cr3"; return;
        case CV_PPC_CR4:     *out = "cr4"; return;
        case CV_PPC_CR5:     *out = "cr5"; return;
        case CV_PPC_CR6:     *out = "cr6"; return;
        case CV_PPC_CR7:     *out = "cr7"; return;

        /*
        ** PowerPC Floating Point Registers ( user Level )
        */
        case CV_PPC_FPR0:    *out = "fpr0"; return;
        case CV_PPC_FPR1:    *out = "fpr1"; return;
        case CV_PPC_FPR2:    *out = "fpr2"; return;
        case CV_PPC_FPR3:    *out = "fpr3"; return;
        case CV_PPC_FPR4:    *out = "fpr4"; return;
        case CV_PPC_FPR5:    *out = "fpr5"; return;
        case CV_PPC_FPR6:    *out = "fpr6"; return;
        case CV_PPC_FPR7:    *out = "fpr7"; return;
        case CV_PPC_FPR8:    *out = "fpr8"; return;
        case CV_PPC_FPR9:    *out = "fpr9"; return;
        case CV_PPC_FPR10:   *out = "fpr10"; return;
        case CV_PPC_FPR11:   *out = "fpr11"; return;
        case CV_PPC_FPR12:   *out = "fpr12"; return;
        case CV_PPC_FPR13:   *out = "fpr13"; return;
        case CV_PPC_FPR14:   *out = "fpr14"; return;
        case CV_PPC_FPR15:   *out = "fpr15"; return;
        case CV_PPC_FPR16:   *out = "fpr16"; return;
        case CV_PPC_FPR17:   *out = "fpr17"; return;
        case CV_PPC_FPR18:   *out = "fpr18"; return;
        case CV_PPC_FPR19:   *out = "fpr19"; return;
        case CV_PPC_FPR20:   *out = "fpr20"; return;
        case CV_PPC_FPR21:   *out = "fpr21"; return;
        case CV_PPC_FPR22:   *out = "fpr22"; return;
        case CV_PPC_FPR23:   *out = "fpr23"; return;
        case CV_PPC_FPR24:   *out = "fpr24"; return;
        case CV_PPC_FPR25:   *out = "fpr25"; return;
        case CV_PPC_FPR26:   *out = "fpr26"; return;
        case CV_PPC_FPR27:   *out = "fpr27"; return;
        case CV_PPC_FPR28:   *out = "fpr28"; return;
        case CV_PPC_FPR29:   *out = "fpr29"; return;
        case CV_PPC_FPR30:   *out = "fpr30"; return;
        case CV_PPC_FPR31:   *out = "fpr31"; return;

        /*
        ** PowerPC Floating Point Status and Control Register ( User Level )
        */
        case CV_PPC_FPSCR:   *out = "FPSCR"; return;

        /*
        ** PowerPC Machine State Register ( Supervisor Level )
        */
        case CV_PPC_MSR:     *out = "msr"; return;

        /*
        ** PowerPC Segment Registers ( Supervisor Level )
        */
        case CV_PPC_SR0:     *out = "sr0"; return;
        case CV_PPC_SR1:     *out = "sr1"; return;
        case CV_PPC_SR2:     *out = "sr2"; return;
        case CV_PPC_SR3:     *out = "sr3"; return;
        case CV_PPC_SR4:     *out = "sr4"; return;
        case CV_PPC_SR5:     *out = "sr5"; return;
        case CV_PPC_SR6:     *out = "sr6"; return;
        case CV_PPC_SR7:     *out = "sr7"; return;
        case CV_PPC_SR8:     *out = "sr8"; return;
        case CV_PPC_SR9:     *out = "sr9"; return;
        case CV_PPC_SR10:    *out = "sr10"; return;
        case CV_PPC_SR11:    *out = "sr11"; return;
        case CV_PPC_SR12:    *out = "sr12"; return;
        case CV_PPC_SR13:    *out = "sr13"; return;
        case CV_PPC_SR14:    *out = "sr14"; return;
        case CV_PPC_SR15:    *out = "sr15"; return;

        /*
        ** For all of the special purpose registers add 100 to the SPR# that the
        ** Motorola/IBM documentation gives with the exception of any imaginary
        ** registers.
        */

        /*
        ** PowerPC Special Purpose Registers ( User Level )
        */
        case CV_PPC_PC:      *out = "pc"; return; // PC (imaginary register)

        case CV_PPC_MQ:      *out = "mq"; return; // MPC601
        case CV_PPC_XER:     *out = "xer"; return;
        case CV_PPC_RTCU:    *out = "rtcu"; return; // MPC601
        case CV_PPC_RTCL:    *out = "rtcl"; return; // MPC601
        case CV_PPC_LR:      *out = "lr"; return;
        case CV_PPC_CTR:     *out = "ctr"; return;

        case CV_PPC_COMPARE: *out = "compare"; return;// part of XER (internal to the debugger only)
        case CV_PPC_COUNT:   *out = "count"; return;// part of XER (internal to the debugger only)

        /*
        ** PowerPC Special Purpose Registers ( supervisor Level )
        */
        case CV_PPC_DSISR:   *out = "dsisr"; return;
        case CV_PPC_DAR:     *out = "dar"; return;
        case CV_PPC_DEC:     *out = "dec"; return;
        case CV_PPC_SDR1:    *out = "sdr1"; return;
        case CV_PPC_SRR0:    *out = "srr0"; return;
        case CV_PPC_SRR1:    *out = "srr1"; return;
        case CV_PPC_SPRG0:   *out = "sprg0"; return;
        case CV_PPC_SPRG1:   *out = "sprg1"; return;
        case CV_PPC_SPRG2:   *out = "sprg2"; return;
        case CV_PPC_SPRG3:   *out = "sprg3"; return;
        case CV_PPC_ASR:     *out = "asr"; return;// 64-bit implementations only
        case CV_PPC_EAR:     *out = "ear"; return;
        case CV_PPC_PVR:     *out = "pvr"; return;
        case CV_PPC_BAT0U:   *out = "bat0u"; return;
        case CV_PPC_BAT0L:   *out = "bat0l"; return;
        case CV_PPC_BAT1U:   *out = "bat1u"; return;
        case CV_PPC_BAT1L:   *out = "bat1l"; return;
        case CV_PPC_BAT2U:   *out = "bat2u"; return;
        case CV_PPC_BAT2L:   *out = "bat2l"; return;
        case CV_PPC_BAT3U:   *out = "bat3u"; return;
        case CV_PPC_BAT3L:   *out = "bat3l"; return;
        case CV_PPC_DBAT0U:  *out = "dbat0u"; return;
        case CV_PPC_DBAT0L:  *out = "dbat0l"; return;
        case CV_PPC_DBAT1U:  *out = "dbat1u"; return;
        case CV_PPC_DBAT1L:  *out = "dbat1l"; return;
        case CV_PPC_DBAT2U:  *out = "dbat2u"; return;
        case CV_PPC_DBAT2L:  *out = "dbat2l"; return;
        case CV_PPC_DBAT3U:  *out = "dbat3u"; return;
        case CV_PPC_DBAT3L:  *out = "dbat3l"; return;

        /*
        ** PowerPC Special Purpose Registers implementation Dependent ( Supervisor Level )
        */

        /*
        ** Doesn't appear that IBM/Motorola has finished defining these.
        */

        case CV_PPC_PMR0:    *out = "pmr0"; return;// MPC620,
        case CV_PPC_PMR1:    *out = "pmr1"; return;// MPC620,
        case CV_PPC_PMR2:    *out = "pmr2"; return;// MPC620,
        case CV_PPC_PMR3:    *out = "pmr3"; return;// MPC620,
        case CV_PPC_PMR4:    *out = "pmr4"; return;// MPC620,
        case CV_PPC_PMR5:    *out = "pmr5"; return;// MPC620,
        case CV_PPC_PMR6:    *out = "pmr6"; return;// MPC620,
        case CV_PPC_PMR7:    *out = "pmr7"; return;// MPC620,
        case CV_PPC_PMR8:    *out = "pmr8"; return;// MPC620,
        case CV_PPC_PMR9:    *out = "pmr9"; return;// MPC620,
        case CV_PPC_PMR10:   *out = "pmr10"; return;// MPC620,
        case CV_PPC_PMR11:   *out = "pmr11"; return;// MPC620,
        case CV_PPC_PMR12:   *out = "pmr12"; return;// MPC620,
        case CV_PPC_PMR13:   *out = "pmr13"; return;// MPC620,
        case CV_PPC_PMR14:   *out = "pmr14"; return;// MPC620,
        case CV_PPC_PMR15:   *out = "pmr15"; return;// MPC620,

        case CV_PPC_DMISS:   *out = "dmiss"; return;// MPC603
        case CV_PPC_DCMP:    *out = "dcmp"; return;// MPC603
        case CV_PPC_HASH1:   *out = "hash1"; return;// MPC603
        case CV_PPC_HASH2:   *out = "hash2"; return;// MPC603
        case CV_PPC_IMISS:   *out = "imiss"; return;// MPC603
        case CV_PPC_ICMP:    *out = "icmp"; return;// MPC603
        case CV_PPC_RPA:     *out = "rpa"; return;// MPC603

        case CV_PPC_HID0:    *out = "hid0"; return;// MPC601, MPC603, MPC620
        case CV_PPC_HID1:    *out = "hid1"; return;// MPC601
        case CV_PPC_HID2:    *out = "hid2"; return;// MPC601, MPC603, MPC620 ( IABR )
        case CV_PPC_HID3:    *out = "hid3"; return;// Not Defined
        case CV_PPC_HID4:    *out = "hid4"; return;// Not Defined
        case CV_PPC_HID5:    *out = "hid5"; return;// MPC601, MPC604, MPC620 ( DABR )
        case CV_PPC_HID6:    *out = "hid6"; return;// Not Defined
        case CV_PPC_HID7:    *out = "hid7"; return;// Not Defined
        case CV_PPC_HID8:    *out = "hid8"; return;// MPC620 ( BUSCSR )
        case CV_PPC_HID9:    *out = "hid9"; return;// MPC620 ( L2CSR )
        case CV_PPC_HID10:   *out = "hid10"; return;// Not Defined
        case CV_PPC_HID11:   *out = "hid11"; return;// Not Defined
        case CV_PPC_HID12:   *out = "hid12"; return;// Not Defined
        case CV_PPC_HID13:   *out = "hid13"; return;// MPC604 ( HCR )
        case CV_PPC_HID14:   *out = "hid14"; return;// Not Defined
        case CV_PPC_HID15:   *out = "hid15"; return;// MPC601, MPC604, MPC620 ( PIR )
      }
      break;

    //
    // JAVA VM registers
    //

    //    case CV_JAVA_PC:     *out = "PC"; return;

    case CV_CFL_SH3:
    case CV_CFL_SH3E:
    case CV_CFL_SH3DSP:
    case CV_CFL_SH4:
      //
      // Register set for the Hitachi SH3
      //
      switch ( reg )
      {
        case CV_SH3_NOREG:   *out = "NOREG"; return;

        case CV_SH3_IntR0:   *out = "IntR0"; return;// CPU REGISTER
        case CV_SH3_IntR1:   *out = "IntR1"; return;
        case CV_SH3_IntR2:   *out = "IntR2"; return;
        case CV_SH3_IntR3:   *out = "IntR3"; return;
        case CV_SH3_IntR4:   *out = "IntR4"; return;
        case CV_SH3_IntR5:   *out = "IntR5"; return;
        case CV_SH3_IntR6:   *out = "IntR6"; return;
        case CV_SH3_IntR7:   *out = "IntR7"; return;
        case CV_SH3_IntR8:   *out = "IntR8"; return;
        case CV_SH3_IntR9:   *out = "IntR9"; return;
        case CV_SH3_IntR10:  *out = "IntR10"; return;
        case CV_SH3_IntR11:  *out = "IntR11"; return;
        case CV_SH3_IntR12:  *out = "IntR12"; return;
        case CV_SH3_IntR13:  *out = "IntR13"; return;
        case CV_SH3_IntFp:   *out = "IntFp"; return;
        case CV_SH3_IntSp:   *out = "IntSp"; return;
        case CV_SH3_Gbr:     *out = "Gbr"; return;
        case CV_SH3_Pr:      *out = "Pr"; return;
        case CV_SH3_Mach:    *out = "Mach"; return;
        case CV_SH3_Macl:    *out = "Macl"; return;

        case CV_SH3_Pc:      *out = "Pc"; return;
        case CV_SH3_Sr:      *out = "Sr"; return;

        case CV_SH3_BarA:    *out = "BarA"; return;
        case CV_SH3_BasrA:   *out = "BasrA"; return;
        case CV_SH3_BamrA:   *out = "BamrA"; return;
        case CV_SH3_BbrA:    *out = "BbrA"; return;
        case CV_SH3_BarB:    *out = "BarB"; return;
        case CV_SH3_BasrB:   *out = "BasrB"; return;
        case CV_SH3_BamrB:   *out = "BamrB"; return;
        case CV_SH3_BbrB:    *out = "BbrB"; return;
        case CV_SH3_BdrB:    *out = "BdrB"; return;
        case CV_SH3_BdmrB:   *out = "BdmrB"; return;
        case CV_SH3_Brcr:    *out = "Brcr"; return;

        //
        // Additional registers for Hitachi SH processors
        //

        case CV_SH_Fpscr:    *out = "Fpscr"; return;// floating point status/control register
        case CV_SH_Fpul:     *out = "Fpul"; return;// floating point communication register

        case CV_SH_FpR0:     *out = "FpR0"; return;// Floating point registers
        case CV_SH_FpR1:     *out = "FpR1"; return;
        case CV_SH_FpR2:     *out = "FpR2"; return;
        case CV_SH_FpR3:     *out = "FpR3"; return;
        case CV_SH_FpR4:     *out = "FpR4"; return;
        case CV_SH_FpR5:     *out = "FpR5"; return;
        case CV_SH_FpR6:     *out = "FpR6"; return;
        case CV_SH_FpR7:     *out = "FpR7"; return;
        case CV_SH_FpR8:     *out = "FpR8"; return;
        case CV_SH_FpR9:     *out = "FpR9"; return;
        case CV_SH_FpR10:    *out = "FpR10"; return;
        case CV_SH_FpR11:    *out = "FpR11"; return;
        case CV_SH_FpR12:    *out = "FpR12"; return;
        case CV_SH_FpR13:    *out = "FpR13"; return;
        case CV_SH_FpR14:    *out = "FpR14"; return;
        case CV_SH_FpR15:    *out = "FpR15"; return;

        case CV_SH_XFpR0:    *out = "XFpR0"; return;
        case CV_SH_XFpR1:    *out = "XFpR1"; return;
        case CV_SH_XFpR2:    *out = "XFpR2"; return;
        case CV_SH_XFpR3:    *out = "XFpR3"; return;
        case CV_SH_XFpR4:    *out = "XFpR4"; return;
        case CV_SH_XFpR5:    *out = "XFpR5"; return;
        case CV_SH_XFpR6:    *out = "XFpR6"; return;
        case CV_SH_XFpR7:    *out = "XFpR7"; return;
        case CV_SH_XFpR8:    *out = "XFpR8"; return;
        case CV_SH_XFpR9:    *out = "XFpR9"; return;
        case CV_SH_XFpR10:   *out = "XFpR10"; return;
        case CV_SH_XFpR11:   *out = "XFpR11"; return;
        case CV_SH_XFpR12:   *out = "XFpR12"; return;
        case CV_SH_XFpR13:   *out = "XFpR13"; return;
        case CV_SH_XFpR14:   *out = "XFpR14"; return;
        case CV_SH_XFpR15:   *out = "XFpR15"; return;
      }
      break;

    case CV_CFL_ARM3:
    case CV_CFL_ARM4:
    case CV_CFL_ARM4T:
    case CV_CFL_ARM5:
    case CV_CFL_ARM5T:
    case CV_CFL_ARM6:
    case CV_CFL_ARM_XMAC:
    case CV_CFL_ARM_WMMX:
    case CV_CFL_THUMB:
    case CV_CFL_ARMNT:
      //
      // Register set for the ARM processor.
      //
      switch ( reg )
      {
        case CV_ARM_NOREG:   *out = "noreg"; return;
        case CV_ARM_R0:      *out = "r0"; return;
        case CV_ARM_R1:      *out = "r1"; return;
        case CV_ARM_R2:      *out = "r2"; return;
        case CV_ARM_R3:      *out = "r3"; return;
        case CV_ARM_R4:      *out = "r4"; return;
        case CV_ARM_R5:      *out = "r5"; return;
        case CV_ARM_R6:      *out = "r6"; return;
        case CV_ARM_R7:      *out = "r7"; return;
        case CV_ARM_R8:      *out = "r8"; return;
        case CV_ARM_R9:      *out = "r9"; return;
        case CV_ARM_R10:     *out = "r10"; return;
        case CV_ARM_R11:     *out = "r11"; return;// Frame pointer, if allocated
        case CV_ARM_R12:     *out = "r12"; return;
        case CV_ARM_SP:      *out = "sp"; return;// Stack pointer
        case CV_ARM_LR:      *out = "lr"; return;// Link Register
        case CV_ARM_PC:      *out = "pc"; return;// Program counter
        case CV_ARM_CPSR:    *out = "cpsr"; return;// Current program status register
      }
      break;

    case CV_CFL_IA64:
//    case CV_CFL_IA64_1:
    case CV_CFL_IA64_2:
      //
      // Register set for Intel IA64
      //
      switch ( reg )
      {
        case CV_IA64_NOREG:  *out = "noreg"; return;

        // Branch Registers

        case CV_IA64_Br0:    *out = "br0"; return;
        case CV_IA64_Br1:    *out = "br1"; return;
        case CV_IA64_Br2:    *out = "br2"; return;
        case CV_IA64_Br3:    *out = "br3"; return;
        case CV_IA64_Br4:    *out = "br4"; return;
        case CV_IA64_Br5:    *out = "br5"; return;
        case CV_IA64_Br6:    *out = "br6"; return;
        case CV_IA64_Br7:    *out = "br7"; return;

        // Predicate Registers

        case CV_IA64_P0:     *out = "p0"; return;
        case CV_IA64_P1:     *out = "p1"; return;
        case CV_IA64_P2:     *out = "p2"; return;
        case CV_IA64_P3:     *out = "p3"; return;
        case CV_IA64_P4:     *out = "p4"; return;
        case CV_IA64_P5:     *out = "p5"; return;
        case CV_IA64_P6:     *out = "p6"; return;
        case CV_IA64_P7:     *out = "p7"; return;
        case CV_IA64_P8:     *out = "p8"; return;
        case CV_IA64_P9:     *out = "p9"; return;
        case CV_IA64_P10:    *out = "p10"; return;
        case CV_IA64_P11:    *out = "p11"; return;
        case CV_IA64_P12:    *out = "p12"; return;
        case CV_IA64_P13:    *out = "p13"; return;
        case CV_IA64_P14:    *out = "p14"; return;
        case CV_IA64_P15:    *out = "p15"; return;
        case CV_IA64_P16:    *out = "p16"; return;
        case CV_IA64_P17:    *out = "p17"; return;
        case CV_IA64_P18:    *out = "p18"; return;
        case CV_IA64_P19:    *out = "p19"; return;
        case CV_IA64_P20:    *out = "p20"; return;
        case CV_IA64_P21:    *out = "p21"; return;
        case CV_IA64_P22:    *out = "p22"; return;
        case CV_IA64_P23:    *out = "p23"; return;
        case CV_IA64_P24:    *out = "p24"; return;
        case CV_IA64_P25:    *out = "p25"; return;
        case CV_IA64_P26:    *out = "p26"; return;
        case CV_IA64_P27:    *out = "p27"; return;
        case CV_IA64_P28:    *out = "p28"; return;
        case CV_IA64_P29:    *out = "p29"; return;
        case CV_IA64_P30:    *out = "p30"; return;
        case CV_IA64_P31:    *out = "p31"; return;
        case CV_IA64_P32:    *out = "p32"; return;
        case CV_IA64_P33:    *out = "p33"; return;
        case CV_IA64_P34:    *out = "p34"; return;
        case CV_IA64_P35:    *out = "p35"; return;
        case CV_IA64_P36:    *out = "p36"; return;
        case CV_IA64_P37:    *out = "p37"; return;
        case CV_IA64_P38:    *out = "p38"; return;
        case CV_IA64_P39:    *out = "p39"; return;
        case CV_IA64_P40:    *out = "p40"; return;
        case CV_IA64_P41:    *out = "p41"; return;
        case CV_IA64_P42:    *out = "p42"; return;
        case CV_IA64_P43:    *out = "p43"; return;
        case CV_IA64_P44:    *out = "p44"; return;
        case CV_IA64_P45:    *out = "p45"; return;
        case CV_IA64_P46:    *out = "p46"; return;
        case CV_IA64_P47:    *out = "p47"; return;
        case CV_IA64_P48:    *out = "p48"; return;
        case CV_IA64_P49:    *out = "p49"; return;
        case CV_IA64_P50:    *out = "p50"; return;
        case CV_IA64_P51:    *out = "p51"; return;
        case CV_IA64_P52:    *out = "p52"; return;
        case CV_IA64_P53:    *out = "p53"; return;
        case CV_IA64_P54:    *out = "p54"; return;
        case CV_IA64_P55:    *out = "p55"; return;
        case CV_IA64_P56:    *out = "p56"; return;
        case CV_IA64_P57:    *out = "p57"; return;
        case CV_IA64_P58:    *out = "p58"; return;
        case CV_IA64_P59:    *out = "p59"; return;
        case CV_IA64_P60:    *out = "p60"; return;
        case CV_IA64_P61:    *out = "p61"; return;
        case CV_IA64_P62:    *out = "p62"; return;
        case CV_IA64_P63:    *out = "p63"; return;

        case CV_IA64_Preds:  *out = "Preds"; return;

        // Banked General Registers

        case CV_IA64_IntH0:  *out = "IntH0"; return;
        case CV_IA64_IntH1:  *out = "IntH1"; return;
        case CV_IA64_IntH2:  *out = "IntH2"; return;
        case CV_IA64_IntH3:  *out = "IntH3"; return;
        case CV_IA64_IntH4:  *out = "IntH4"; return;
        case CV_IA64_IntH5:  *out = "IntH5"; return;
        case CV_IA64_IntH6:  *out = "IntH6"; return;
        case CV_IA64_IntH7:  *out = "IntH7"; return;
        case CV_IA64_IntH8:  *out = "IntH8"; return;
        case CV_IA64_IntH9:  *out = "IntH9"; return;
        case CV_IA64_IntH10: *out = "IntH10"; return;
        case CV_IA64_IntH11: *out = "IntH11"; return;
        case CV_IA64_IntH12: *out = "IntH12"; return;
        case CV_IA64_IntH13: *out = "IntH13"; return;
        case CV_IA64_IntH14: *out = "IntH14"; return;
        case CV_IA64_IntH15: *out = "IntH15"; return;

        // Special Registers

        case CV_IA64_Ip:     *out = "Ip"; return;
        case CV_IA64_Umask:  *out = "Umask"; return;
        case CV_IA64_Cfm:    *out = "Cfm"; return;
        case CV_IA64_Psr:    *out = "Psr"; return;

        // Banked General Registers

        case CV_IA64_Nats:   *out = "Nats"; return;
        case CV_IA64_Nats2:  *out = "Nats2"; return;
        case CV_IA64_Nats3:  *out = "Nats3"; return;

        // General-Purpose Registers

        // Integer registers
        case CV_IA64_IntR0:  *out = "IntR0"; return;
        case CV_IA64_IntR1:  *out = "IntR1"; return;
        case CV_IA64_IntR2:  *out = "IntR2"; return;
        case CV_IA64_IntR3:  *out = "IntR3"; return;
        case CV_IA64_IntR4:  *out = "IntR4"; return;
        case CV_IA64_IntR5:  *out = "IntR5"; return;
        case CV_IA64_IntR6:  *out = "IntR6"; return;
        case CV_IA64_IntR7:  *out = "IntR7"; return;
        case CV_IA64_IntR8:  *out = "IntR8"; return;
        case CV_IA64_IntR9:  *out = "IntR9"; return;
        case CV_IA64_IntR10: *out = "IntR10"; return;
        case CV_IA64_IntR11: *out = "IntR11"; return;
        case CV_IA64_IntR12: *out = "IntR12"; return;
        case CV_IA64_IntR13: *out = "IntR13"; return;
        case CV_IA64_IntR14: *out = "IntR14"; return;
        case CV_IA64_IntR15: *out = "IntR15"; return;
        case CV_IA64_IntR16: *out = "IntR16"; return;
        case CV_IA64_IntR17: *out = "IntR17"; return;
        case CV_IA64_IntR18: *out = "IntR18"; return;
        case CV_IA64_IntR19: *out = "IntR19"; return;
        case CV_IA64_IntR20: *out = "IntR20"; return;
        case CV_IA64_IntR21: *out = "IntR21"; return;
        case CV_IA64_IntR22: *out = "IntR22"; return;
        case CV_IA64_IntR23: *out = "IntR23"; return;
        case CV_IA64_IntR24: *out = "IntR24"; return;
        case CV_IA64_IntR25: *out = "IntR25"; return;
        case CV_IA64_IntR26: *out = "IntR26"; return;
        case CV_IA64_IntR27: *out = "IntR27"; return;
        case CV_IA64_IntR28: *out = "IntR28"; return;
        case CV_IA64_IntR29: *out = "IntR29"; return;
        case CV_IA64_IntR30: *out = "IntR30"; return;
        case CV_IA64_IntR31: *out = "IntR31"; return;

        // Register Stack
        case CV_IA64_IntR32: *out = "IntR32"; return;
        case CV_IA64_IntR33: *out = "IntR33"; return;
        case CV_IA64_IntR34: *out = "IntR34"; return;
        case CV_IA64_IntR35: *out = "IntR35"; return;
        case CV_IA64_IntR36: *out = "IntR36"; return;
        case CV_IA64_IntR37: *out = "IntR37"; return;
        case CV_IA64_IntR38: *out = "IntR38"; return;
        case CV_IA64_IntR39: *out = "IntR39"; return;
        case CV_IA64_IntR40: *out = "IntR40"; return;
        case CV_IA64_IntR41: *out = "IntR41"; return;
        case CV_IA64_IntR42: *out = "IntR42"; return;
        case CV_IA64_IntR43: *out = "IntR43"; return;
        case CV_IA64_IntR44: *out = "IntR44"; return;
        case CV_IA64_IntR45: *out = "IntR45"; return;
        case CV_IA64_IntR46: *out = "IntR46"; return;
        case CV_IA64_IntR47: *out = "IntR47"; return;
        case CV_IA64_IntR48: *out = "IntR48"; return;
        case CV_IA64_IntR49: *out = "IntR49"; return;
        case CV_IA64_IntR50: *out = "IntR50"; return;
        case CV_IA64_IntR51: *out = "IntR51"; return;
        case CV_IA64_IntR52: *out = "IntR52"; return;
        case CV_IA64_IntR53: *out = "IntR53"; return;
        case CV_IA64_IntR54: *out = "IntR54"; return;
        case CV_IA64_IntR55: *out = "IntR55"; return;
        case CV_IA64_IntR56: *out = "IntR56"; return;
        case CV_IA64_IntR57: *out = "IntR57"; return;
        case CV_IA64_IntR58: *out = "IntR58"; return;
        case CV_IA64_IntR59: *out = "IntR59"; return;
        case CV_IA64_IntR60: *out = "IntR60"; return;
        case CV_IA64_IntR61: *out = "IntR61"; return;
        case CV_IA64_IntR62: *out = "IntR62"; return;
        case CV_IA64_IntR63: *out = "IntR63"; return;
        case CV_IA64_IntR64: *out = "IntR64"; return;
        case CV_IA64_IntR65: *out = "IntR65"; return;
        case CV_IA64_IntR66: *out = "IntR66"; return;
        case CV_IA64_IntR67: *out = "IntR67"; return;
        case CV_IA64_IntR68: *out = "IntR68"; return;
        case CV_IA64_IntR69: *out = "IntR69"; return;
        case CV_IA64_IntR70: *out = "IntR70"; return;
        case CV_IA64_IntR71: *out = "IntR71"; return;
        case CV_IA64_IntR72: *out = "IntR72"; return;
        case CV_IA64_IntR73: *out = "IntR73"; return;
        case CV_IA64_IntR74: *out = "IntR74"; return;
        case CV_IA64_IntR75: *out = "IntR75"; return;
        case CV_IA64_IntR76: *out = "IntR76"; return;
        case CV_IA64_IntR77: *out = "IntR77"; return;
        case CV_IA64_IntR78: *out = "IntR78"; return;
        case CV_IA64_IntR79: *out = "IntR79"; return;
        case CV_IA64_IntR80: *out = "IntR80"; return;
        case CV_IA64_IntR81: *out = "IntR81"; return;
        case CV_IA64_IntR82: *out = "IntR82"; return;
        case CV_IA64_IntR83: *out = "IntR83"; return;
        case CV_IA64_IntR84: *out = "IntR84"; return;
        case CV_IA64_IntR85: *out = "IntR85"; return;
        case CV_IA64_IntR86: *out = "IntR86"; return;
        case CV_IA64_IntR87: *out = "IntR87"; return;
        case CV_IA64_IntR88: *out = "IntR88"; return;
        case CV_IA64_IntR89: *out = "IntR89"; return;
        case CV_IA64_IntR90: *out = "IntR90"; return;
        case CV_IA64_IntR91: *out = "IntR91"; return;
        case CV_IA64_IntR92: *out = "IntR92"; return;
        case CV_IA64_IntR93: *out = "IntR93"; return;
        case CV_IA64_IntR94: *out = "IntR94"; return;
        case CV_IA64_IntR95: *out = "IntR95"; return;
        case CV_IA64_IntR96: *out = "IntR96"; return;
        case CV_IA64_IntR97: *out = "IntR97"; return;
        case CV_IA64_IntR98: *out = "IntR98"; return;
        case CV_IA64_IntR99: *out = "IntR99"; return;
        case CV_IA64_IntR100:*out = "IntR100"; return;
        case CV_IA64_IntR101:*out = "IntR101"; return;
        case CV_IA64_IntR102:*out = "IntR102"; return;
        case CV_IA64_IntR103:*out = "IntR103"; return;
        case CV_IA64_IntR104:*out = "IntR104"; return;
        case CV_IA64_IntR105:*out = "IntR105"; return;
        case CV_IA64_IntR106:*out = "IntR106"; return;
        case CV_IA64_IntR107:*out = "IntR107"; return;
        case CV_IA64_IntR108:*out = "IntR108"; return;
        case CV_IA64_IntR109:*out = "IntR109"; return;
        case CV_IA64_IntR110:*out = "IntR110"; return;
        case CV_IA64_IntR111:*out = "IntR111"; return;
        case CV_IA64_IntR112:*out = "IntR112"; return;
        case CV_IA64_IntR113:*out = "IntR113"; return;
        case CV_IA64_IntR114:*out = "IntR114"; return;
        case CV_IA64_IntR115:*out = "IntR115"; return;
        case CV_IA64_IntR116:*out = "IntR116"; return;
        case CV_IA64_IntR117:*out = "IntR117"; return;
        case CV_IA64_IntR118:*out = "IntR118"; return;
        case CV_IA64_IntR119:*out = "IntR119"; return;
        case CV_IA64_IntR120:*out = "IntR120"; return;
        case CV_IA64_IntR121:*out = "IntR121"; return;
        case CV_IA64_IntR122:*out = "IntR122"; return;
        case CV_IA64_IntR123:*out = "IntR123"; return;
        case CV_IA64_IntR124:*out = "IntR124"; return;
        case CV_IA64_IntR125:*out = "IntR125"; return;
        case CV_IA64_IntR126:*out = "IntR126"; return;
        case CV_IA64_IntR127:*out = "IntR127"; return;

        // Floating-Point Registers

        // Low Floating Point Registers
        case CV_IA64_FltF0:  *out = "FltF0"; return;
        case CV_IA64_FltF1:  *out = "FltF1"; return;
        case CV_IA64_FltF2:  *out = "FltF2"; return;
        case CV_IA64_FltF3:  *out = "FltF3"; return;
        case CV_IA64_FltF4:  *out = "FltF4"; return;
        case CV_IA64_FltF5:  *out = "FltF5"; return;
        case CV_IA64_FltF6:  *out = "FltF6"; return;
        case CV_IA64_FltF7:  *out = "FltF7"; return;
        case CV_IA64_FltF8:  *out = "FltF8"; return;
        case CV_IA64_FltF9:  *out = "FltF9"; return;
        case CV_IA64_FltF10: *out = "FltF10"; return;
        case CV_IA64_FltF11: *out = "FltF11"; return;
        case CV_IA64_FltF12: *out = "FltF12"; return;
        case CV_IA64_FltF13: *out = "FltF13"; return;
        case CV_IA64_FltF14: *out = "FltF14"; return;
        case CV_IA64_FltF15: *out = "FltF15"; return;
        case CV_IA64_FltF16: *out = "FltF16"; return;
        case CV_IA64_FltF17: *out = "FltF17"; return;
        case CV_IA64_FltF18: *out = "FltF18"; return;
        case CV_IA64_FltF19: *out = "FltF19"; return;
        case CV_IA64_FltF20: *out = "FltF20"; return;
        case CV_IA64_FltF21: *out = "FltF21"; return;
        case CV_IA64_FltF22: *out = "FltF22"; return;
        case CV_IA64_FltF23: *out = "FltF23"; return;
        case CV_IA64_FltF24: *out = "FltF24"; return;
        case CV_IA64_FltF25: *out = "FltF25"; return;
        case CV_IA64_FltF26: *out = "FltF26"; return;
        case CV_IA64_FltF27: *out = "FltF27"; return;
        case CV_IA64_FltF28: *out = "FltF28"; return;
        case CV_IA64_FltF29: *out = "FltF29"; return;
        case CV_IA64_FltF30: *out = "FltF30"; return;
        case CV_IA64_FltF31: *out = "FltF31"; return;

        // High Floating Point Registers
        case CV_IA64_FltF32: *out = "FltF32"; return;
        case CV_IA64_FltF33: *out = "FltF33"; return;
        case CV_IA64_FltF34: *out = "FltF34"; return;
        case CV_IA64_FltF35: *out = "FltF35"; return;
        case CV_IA64_FltF36: *out = "FltF36"; return;
        case CV_IA64_FltF37: *out = "FltF37"; return;
        case CV_IA64_FltF38: *out = "FltF38"; return;
        case CV_IA64_FltF39: *out = "FltF39"; return;
        case CV_IA64_FltF40: *out = "FltF40"; return;
        case CV_IA64_FltF41: *out = "FltF41"; return;
        case CV_IA64_FltF42: *out = "FltF42"; return;
        case CV_IA64_FltF43: *out = "FltF43"; return;
        case CV_IA64_FltF44: *out = "FltF44"; return;
        case CV_IA64_FltF45: *out = "FltF45"; return;
        case CV_IA64_FltF46: *out = "FltF46"; return;
        case CV_IA64_FltF47: *out = "FltF47"; return;
        case CV_IA64_FltF48: *out = "FltF48"; return;
        case CV_IA64_FltF49: *out = "FltF49"; return;
        case CV_IA64_FltF50: *out = "FltF50"; return;
        case CV_IA64_FltF51: *out = "FltF51"; return;
        case CV_IA64_FltF52: *out = "FltF52"; return;
        case CV_IA64_FltF53: *out = "FltF53"; return;
        case CV_IA64_FltF54: *out = "FltF54"; return;
        case CV_IA64_FltF55: *out = "FltF55"; return;
        case CV_IA64_FltF56: *out = "FltF56"; return;
        case CV_IA64_FltF57: *out = "FltF57"; return;
        case CV_IA64_FltF58: *out = "FltF58"; return;
        case CV_IA64_FltF59: *out = "FltF59"; return;
        case CV_IA64_FltF60: *out = "FltF60"; return;
        case CV_IA64_FltF61: *out = "FltF61"; return;
        case CV_IA64_FltF62: *out = "FltF62"; return;
        case CV_IA64_FltF63: *out = "FltF63"; return;
        case CV_IA64_FltF64: *out = "FltF64"; return;
        case CV_IA64_FltF65: *out = "FltF65"; return;
        case CV_IA64_FltF66: *out = "FltF66"; return;
        case CV_IA64_FltF67: *out = "FltF67"; return;
        case CV_IA64_FltF68: *out = "FltF68"; return;
        case CV_IA64_FltF69: *out = "FltF69"; return;
        case CV_IA64_FltF70: *out = "FltF70"; return;
        case CV_IA64_FltF71: *out = "FltF71"; return;
        case CV_IA64_FltF72: *out = "FltF72"; return;
        case CV_IA64_FltF73: *out = "FltF73"; return;
        case CV_IA64_FltF74: *out = "FltF74"; return;
        case CV_IA64_FltF75: *out = "FltF75"; return;
        case CV_IA64_FltF76: *out = "FltF76"; return;
        case CV_IA64_FltF77: *out = "FltF77"; return;
        case CV_IA64_FltF78: *out = "FltF78"; return;
        case CV_IA64_FltF79: *out = "FltF79"; return;
        case CV_IA64_FltF80: *out = "FltF80"; return;
        case CV_IA64_FltF81: *out = "FltF81"; return;
        case CV_IA64_FltF82: *out = "FltF82"; return;
        case CV_IA64_FltF83: *out = "FltF83"; return;
        case CV_IA64_FltF84: *out = "FltF84"; return;
        case CV_IA64_FltF85: *out = "FltF85"; return;
        case CV_IA64_FltF86: *out = "FltF86"; return;
        case CV_IA64_FltF87: *out = "FltF87"; return;
        case CV_IA64_FltF88: *out = "FltF88"; return;
        case CV_IA64_FltF89: *out = "FltF89"; return;
        case CV_IA64_FltF90: *out = "FltF90"; return;
        case CV_IA64_FltF91: *out = "FltF91"; return;
        case CV_IA64_FltF92: *out = "FltF92"; return;
        case CV_IA64_FltF93: *out = "FltF93"; return;
        case CV_IA64_FltF94: *out = "FltF94"; return;
        case CV_IA64_FltF95: *out = "FltF95"; return;
        case CV_IA64_FltF96: *out = "FltF96"; return;
        case CV_IA64_FltF97: *out = "FltF97"; return;
        case CV_IA64_FltF98: *out = "FltF98"; return;
        case CV_IA64_FltF99: *out = "FltF99"; return;
        case CV_IA64_FltF100:*out = "FltF100"; return;
        case CV_IA64_FltF101:*out = "FltF101"; return;
        case CV_IA64_FltF102:*out = "FltF102"; return;
        case CV_IA64_FltF103:*out = "FltF103"; return;
        case CV_IA64_FltF104:*out = "FltF104"; return;
        case CV_IA64_FltF105:*out = "FltF105"; return;
        case CV_IA64_FltF106:*out = "FltF106"; return;
        case CV_IA64_FltF107:*out = "FltF107"; return;
        case CV_IA64_FltF108:*out = "FltF108"; return;
        case CV_IA64_FltF109:*out = "FltF109"; return;
        case CV_IA64_FltF110:*out = "FltF110"; return;
        case CV_IA64_FltF111:*out = "FltF111"; return;
        case CV_IA64_FltF112:*out = "FltF112"; return;
        case CV_IA64_FltF113:*out = "FltF113"; return;
        case CV_IA64_FltF114:*out = "FltF114"; return;
        case CV_IA64_FltF115:*out = "FltF115"; return;
        case CV_IA64_FltF116:*out = "FltF116"; return;
        case CV_IA64_FltF117:*out = "FltF117"; return;
        case CV_IA64_FltF118:*out = "FltF118"; return;
        case CV_IA64_FltF119:*out = "FltF119"; return;
        case CV_IA64_FltF120:*out = "FltF120"; return;
        case CV_IA64_FltF121:*out = "FltF121"; return;
        case CV_IA64_FltF122:*out = "FltF122"; return;
        case CV_IA64_FltF123:*out = "FltF123"; return;
        case CV_IA64_FltF124:*out = "FltF124"; return;
        case CV_IA64_FltF125:*out = "FltF125"; return;
        case CV_IA64_FltF126:*out = "FltF126"; return;
        case CV_IA64_FltF127:*out = "FltF127"; return;

        // Application Registers

        case CV_IA64_ApKR0:  *out = "ApKR0"; return;
        case CV_IA64_ApKR1:  *out = "ApKR1"; return;
        case CV_IA64_ApKR2:  *out = "ApKR2"; return;
        case CV_IA64_ApKR3:  *out = "ApKR3"; return;
        case CV_IA64_ApKR4:  *out = "ApKR4"; return;
        case CV_IA64_ApKR5:  *out = "ApKR5"; return;
        case CV_IA64_ApKR6:  *out = "ApKR6"; return;
        case CV_IA64_ApKR7:  *out = "ApKR7"; return;
        case CV_IA64_AR8:    *out = "AR8"; return;
        case CV_IA64_AR9:    *out = "AR9"; return;
        case CV_IA64_AR10:   *out = "AR10"; return;
        case CV_IA64_AR11:   *out = "AR11"; return;
        case CV_IA64_AR12:   *out = "AR12"; return;
        case CV_IA64_AR13:   *out = "AR13"; return;
        case CV_IA64_AR14:   *out = "AR14"; return;
        case CV_IA64_AR15:   *out = "AR15"; return;
        case CV_IA64_RsRSC:  *out = "RsRSC"; return;
        case CV_IA64_RsBSP:  *out = "RsBSP"; return;
        case CV_IA64_RsBSPSTORE:*out = "RsBSPSTORE"; return;
        case CV_IA64_RsRNAT: *out = "rsrnat"; return;
        case CV_IA64_AR20:   *out = "ar20"; return;
        case CV_IA64_StFCR:  *out = "stfcr"; return;
        case CV_IA64_AR22:   *out = "ar22"; return;
        case CV_IA64_AR23:   *out = "ar23"; return;
        case CV_IA64_EFLAG:  *out = "eflag"; return;
        case CV_IA64_CSD:    *out = "csd"; return;
        case CV_IA64_SSD:    *out = "ssd"; return;
        case CV_IA64_CFLG:   *out = "cflg"; return;
        case CV_IA64_StFSR:  *out = "stfsr"; return;
        case CV_IA64_StFIR:  *out = "stfir"; return;
        case CV_IA64_StFDR:  *out = "stfdr"; return;
        case CV_IA64_AR31:   *out = "ar31"; return;
        case CV_IA64_ApCCV:  *out = "apccv"; return;
        case CV_IA64_AR33:   *out = "ar33"; return;
        case CV_IA64_AR34:   *out = "ar34"; return;
        case CV_IA64_AR35:   *out = "ar35"; return;
        case CV_IA64_ApUNAT: *out = "apunat"; return;
        case CV_IA64_AR37:   *out = "ar37"; return;
        case CV_IA64_AR38:   *out = "ar38"; return;
        case CV_IA64_AR39:   *out = "ar39"; return;
        case CV_IA64_StFPSR: *out = "stfpsr"; return;
        case CV_IA64_AR41:   *out = "ar41"; return;
        case CV_IA64_AR42:   *out = "ar42"; return;
        case CV_IA64_AR43:   *out = "ar43"; return;
        case CV_IA64_ApITC:  *out = "apitc"; return;
        case CV_IA64_AR45:   *out = "ar45"; return;
        case CV_IA64_AR46:   *out = "ar46"; return;
        case CV_IA64_AR47:   *out = "ar47"; return;
        case CV_IA64_AR48:   *out = "ar48"; return;
        case CV_IA64_AR49:   *out = "ar49"; return;
        case CV_IA64_AR50:   *out = "ar50"; return;
        case CV_IA64_AR51:   *out = "ar51"; return;
        case CV_IA64_AR52:   *out = "ar52"; return;
        case CV_IA64_AR53:   *out = "ar53"; return;
        case CV_IA64_AR54:   *out = "ar54"; return;
        case CV_IA64_AR55:   *out = "ar55"; return;
        case CV_IA64_AR56:   *out = "ar56"; return;
        case CV_IA64_AR57:   *out = "ar57"; return;
        case CV_IA64_AR58:   *out = "ar58"; return;
        case CV_IA64_AR59:   *out = "ar59"; return;
        case CV_IA64_AR60:   *out = "ar60"; return;
        case CV_IA64_AR61:   *out = "ar61"; return;
        case CV_IA64_AR62:   *out = "ar62"; return;
        case CV_IA64_AR63:   *out = "ar63"; return;
        case CV_IA64_RsPFS:  *out = "rspfs"; return;
        case CV_IA64_ApLC:   *out = "aplc"; return;
        case CV_IA64_ApEC:   *out = "apec"; return;
        case CV_IA64_AR67:   *out = "ar67"; return;
        case CV_IA64_AR68:   *out = "ar68"; return;
        case CV_IA64_AR69:   *out = "ar69"; return;
        case CV_IA64_AR70:   *out = "ar70"; return;
        case CV_IA64_AR71:   *out = "ar71"; return;
        case CV_IA64_AR72:   *out = "ar72"; return;
        case CV_IA64_AR73:   *out = "ar73"; return;
        case CV_IA64_AR74:   *out = "ar74"; return;
        case CV_IA64_AR75:   *out = "ar75"; return;
        case CV_IA64_AR76:   *out = "ar76"; return;
        case CV_IA64_AR77:   *out = "ar77"; return;
        case CV_IA64_AR78:   *out = "ar78"; return;
        case CV_IA64_AR79:   *out = "ar79"; return;
        case CV_IA64_AR80:   *out = "ar80"; return;
        case CV_IA64_AR81:   *out = "ar81"; return;
        case CV_IA64_AR82:   *out = "ar82"; return;
        case CV_IA64_AR83:   *out = "ar83"; return;
        case CV_IA64_AR84:   *out = "ar84"; return;
        case CV_IA64_AR85:   *out = "ar85"; return;
        case CV_IA64_AR86:   *out = "ar86"; return;
        case CV_IA64_AR87:   *out = "ar87"; return;
        case CV_IA64_AR88:   *out = "ar88"; return;
        case CV_IA64_AR89:   *out = "ar89"; return;
        case CV_IA64_AR90:   *out = "ar90"; return;
        case CV_IA64_AR91:   *out = "ar91"; return;
        case CV_IA64_AR92:   *out = "ar92"; return;
        case CV_IA64_AR93:   *out = "ar93"; return;
        case CV_IA64_AR94:   *out = "ar94"; return;
        case CV_IA64_AR95:   *out = "ar95"; return;
        case CV_IA64_AR96:   *out = "ar96"; return;
        case CV_IA64_AR97:   *out = "ar97"; return;
        case CV_IA64_AR98:   *out = "ar98"; return;
        case CV_IA64_AR99:   *out = "ar99"; return;
        case CV_IA64_AR100:  *out = "ar100"; return;
        case CV_IA64_AR101:  *out = "ar101"; return;
        case CV_IA64_AR102:  *out = "ar102"; return;
        case CV_IA64_AR103:  *out = "ar103"; return;
        case CV_IA64_AR104:  *out = "ar104"; return;
        case CV_IA64_AR105:  *out = "ar105"; return;
        case CV_IA64_AR106:  *out = "ar106"; return;
        case CV_IA64_AR107:  *out = "ar107"; return;
        case CV_IA64_AR108:  *out = "ar108"; return;
        case CV_IA64_AR109:  *out = "ar109"; return;
        case CV_IA64_AR110:  *out = "ar110"; return;
        case CV_IA64_AR111:  *out = "ar111"; return;
        case CV_IA64_AR112:  *out = "ar112"; return;
        case CV_IA64_AR113:  *out = "ar113"; return;
        case CV_IA64_AR114:  *out = "ar114"; return;
        case CV_IA64_AR115:  *out = "ar115"; return;
        case CV_IA64_AR116:  *out = "ar116"; return;
        case CV_IA64_AR117:  *out = "ar117"; return;
        case CV_IA64_AR118:  *out = "ar118"; return;
        case CV_IA64_AR119:  *out = "ar119"; return;
        case CV_IA64_AR120:  *out = "ar120"; return;
        case CV_IA64_AR121:  *out = "ar121"; return;
        case CV_IA64_AR122:  *out = "ar122"; return;
        case CV_IA64_AR123:  *out = "ar123"; return;
        case CV_IA64_AR124:  *out = "ar124"; return;
        case CV_IA64_AR125:  *out = "ar125"; return;
        case CV_IA64_AR126:  *out = "ar126"; return;
        case CV_IA64_AR127:  *out = "ar127"; return;

        // CPUID Registers

        case CV_IA64_CPUID0: *out = "cpuid0"; return;
        case CV_IA64_CPUID1: *out = "cpuid1"; return;
        case CV_IA64_CPUID2: *out = "cpuid2"; return;
        case CV_IA64_CPUID3: *out = "cpuid3"; return;
        case CV_IA64_CPUID4: *out = "cpuid4"; return;

        // Control Registers

        case CV_IA64_ApDCR:  *out = "apdcr"; return;
        case CV_IA64_ApITM:  *out = "apitm"; return;
        case CV_IA64_ApIVA:  *out = "apiva"; return;
        case CV_IA64_CR3:    *out = "cr3"; return;
        case CV_IA64_CR4:    *out = "cr4"; return;
        case CV_IA64_CR5:    *out = "cr5"; return;
        case CV_IA64_CR6:    *out = "cr6"; return;
        case CV_IA64_CR7:    *out = "cr7"; return;
        case CV_IA64_ApPTA:  *out = "appta"; return;
        case CV_IA64_ApGPTA: *out = "apgpta"; return;
        case CV_IA64_CR10:   *out = "cr10"; return;
        case CV_IA64_CR11:   *out = "cr11"; return;
        case CV_IA64_CR12:   *out = "cr12"; return;
        case CV_IA64_CR13:   *out = "cr13"; return;
        case CV_IA64_CR14:   *out = "cr14"; return;
        case CV_IA64_CR15:   *out = "cr15"; return;
        case CV_IA64_StIPSR: *out = "stipsr"; return;
        case CV_IA64_StISR:  *out = "stisr"; return;
        case CV_IA64_CR18:   *out = "cr18"; return;
        case CV_IA64_StIIP:  *out = "stiip"; return;
        case CV_IA64_StIFA:  *out = "stifa"; return;
        case CV_IA64_StITIR: *out = "stitir"; return;
        case CV_IA64_StIIPA: *out = "stiipa"; return;
        case CV_IA64_StIFS:  *out = "stifs"; return;
        case CV_IA64_StIIM:  *out = "stiim"; return;
        case CV_IA64_StIHA:  *out = "stiha"; return;
        case CV_IA64_CR26:   *out = "cr26"; return;
        case CV_IA64_CR27:   *out = "cr27"; return;
        case CV_IA64_CR28:   *out = "cr28"; return;
        case CV_IA64_CR29:   *out = "cr29"; return;
        case CV_IA64_CR30:   *out = "cr30"; return;
        case CV_IA64_CR31:   *out = "cr31"; return;
        case CV_IA64_CR32:   *out = "cr32"; return;
        case CV_IA64_CR33:   *out = "cr33"; return;
        case CV_IA64_CR34:   *out = "cr34"; return;
        case CV_IA64_CR35:   *out = "cr35"; return;
        case CV_IA64_CR36:   *out = "cr36"; return;
        case CV_IA64_CR37:   *out = "cr37"; return;
        case CV_IA64_CR38:   *out = "cr38"; return;
        case CV_IA64_CR39:   *out = "cr39"; return;
        case CV_IA64_CR40:   *out = "cr40"; return;
        case CV_IA64_CR41:   *out = "cr41"; return;
        case CV_IA64_CR42:   *out = "cr42"; return;
        case CV_IA64_CR43:   *out = "cr43"; return;
        case CV_IA64_CR44:   *out = "cr44"; return;
        case CV_IA64_CR45:   *out = "cr45"; return;
        case CV_IA64_CR46:   *out = "cr46"; return;
        case CV_IA64_CR47:   *out = "cr47"; return;
        case CV_IA64_CR48:   *out = "cr48"; return;
        case CV_IA64_CR49:   *out = "cr49"; return;
        case CV_IA64_CR50:   *out = "cr50"; return;
        case CV_IA64_CR51:   *out = "cr51"; return;
        case CV_IA64_CR52:   *out = "cr52"; return;
        case CV_IA64_CR53:   *out = "cr53"; return;
        case CV_IA64_CR54:   *out = "cr54"; return;
        case CV_IA64_CR55:   *out = "cr55"; return;
        case CV_IA64_CR56:   *out = "cr56"; return;
        case CV_IA64_CR57:   *out = "cr57"; return;
        case CV_IA64_CR58:   *out = "cr58"; return;
        case CV_IA64_CR59:   *out = "cr59"; return;
        case CV_IA64_CR60:   *out = "cr60"; return;
        case CV_IA64_CR61:   *out = "cr61"; return;
        case CV_IA64_CR62:   *out = "cr62"; return;
        case CV_IA64_CR63:   *out = "cr63"; return;
        case CV_IA64_SaLID:  *out = "salid"; return;
        case CV_IA64_SaIVR:  *out = "saivr"; return;
        case CV_IA64_SaTPR:  *out = "satpr"; return;
        case CV_IA64_SaEOI:  *out = "saeoi"; return;
        case CV_IA64_SaIRR0: *out = "sairr0"; return;
        case CV_IA64_SaIRR1: *out = "sairr1"; return;
        case CV_IA64_SaIRR2: *out = "sairr2"; return;
        case CV_IA64_SaIRR3: *out = "sairr3"; return;
        case CV_IA64_SaITV:  *out = "saitv"; return;
        case CV_IA64_SaPMV:  *out = "sapmv"; return;
        case CV_IA64_SaCMCV: *out = "sacmcv"; return;
        case CV_IA64_CR75:   *out = "cr75"; return;
        case CV_IA64_CR76:   *out = "cr76"; return;
        case CV_IA64_CR77:   *out = "cr77"; return;
        case CV_IA64_CR78:   *out = "cr78"; return;
        case CV_IA64_CR79:   *out = "cr79"; return;
        case CV_IA64_SaLRR0: *out = "salrr0"; return;
        case CV_IA64_SaLRR1: *out = "salrr1"; return;
        case CV_IA64_CR82:   *out = "cr82"; return;
        case CV_IA64_CR83:   *out = "cr83"; return;
        case CV_IA64_CR84:   *out = "cr84"; return;
        case CV_IA64_CR85:   *out = "cr85"; return;
        case CV_IA64_CR86:   *out = "cr86"; return;
        case CV_IA64_CR87:   *out = "cr87"; return;
        case CV_IA64_CR88:   *out = "cr88"; return;
        case CV_IA64_CR89:   *out = "cr89"; return;
        case CV_IA64_CR90:   *out = "cr90"; return;
        case CV_IA64_CR91:   *out = "cr91"; return;
        case CV_IA64_CR92:   *out = "cr92"; return;
        case CV_IA64_CR93:   *out = "cr93"; return;
        case CV_IA64_CR94:   *out = "cr94"; return;
        case CV_IA64_CR95:   *out = "cr95"; return;
        case CV_IA64_CR96:   *out = "cr96"; return;
        case CV_IA64_CR97:   *out = "cr97"; return;
        case CV_IA64_CR98:   *out = "cr98"; return;
        case CV_IA64_CR99:   *out = "cr99"; return;
        case CV_IA64_CR100:  *out = "cr100"; return;
        case CV_IA64_CR101:  *out = "cr101"; return;
        case CV_IA64_CR102:  *out = "cr102"; return;
        case CV_IA64_CR103:  *out = "cr103"; return;
        case CV_IA64_CR104:  *out = "cr104"; return;
        case CV_IA64_CR105:  *out = "cr105"; return;
        case CV_IA64_CR106:  *out = "cr106"; return;
        case CV_IA64_CR107:  *out = "cr107"; return;
        case CV_IA64_CR108:  *out = "cr108"; return;
        case CV_IA64_CR109:  *out = "cr109"; return;
        case CV_IA64_CR110:  *out = "cr110"; return;
        case CV_IA64_CR111:  *out = "cr111"; return;
        case CV_IA64_CR112:  *out = "cr112"; return;
        case CV_IA64_CR113:  *out = "cr113"; return;
        case CV_IA64_CR114:  *out = "cr114"; return;
        case CV_IA64_CR115:  *out = "cr115"; return;
        case CV_IA64_CR116:  *out = "cr116"; return;
        case CV_IA64_CR117:  *out = "cr117"; return;
        case CV_IA64_CR118:  *out = "cr118"; return;
        case CV_IA64_CR119:  *out = "cr119"; return;
        case CV_IA64_CR120:  *out = "cr120"; return;
        case CV_IA64_CR121:  *out = "cr121"; return;
        case CV_IA64_CR122:  *out = "cr122"; return;
        case CV_IA64_CR123:  *out = "cr123"; return;
        case CV_IA64_CR124:  *out = "cr124"; return;
        case CV_IA64_CR125:  *out = "cr125"; return;
        case CV_IA64_CR126:  *out = "cr126"; return;
        case CV_IA64_CR127:  *out = "cr127"; return;

        // Protection Key Registers

        case CV_IA64_Pkr0:   *out = "pkr0"; return;
        case CV_IA64_Pkr1:   *out = "pkr1"; return;
        case CV_IA64_Pkr2:   *out = "pkr2"; return;
        case CV_IA64_Pkr3:   *out = "pkr3"; return;
        case CV_IA64_Pkr4:   *out = "pkr4"; return;
        case CV_IA64_Pkr5:   *out = "pkr5"; return;
        case CV_IA64_Pkr6:   *out = "pkr6"; return;
        case CV_IA64_Pkr7:   *out = "pkr7"; return;
        case CV_IA64_Pkr8:   *out = "pkr8"; return;
        case CV_IA64_Pkr9:   *out = "pkr9"; return;
        case CV_IA64_Pkr10:  *out = "pkr10"; return;
        case CV_IA64_Pkr11:  *out = "pkr11"; return;
        case CV_IA64_Pkr12:  *out = "pkr12"; return;
        case CV_IA64_Pkr13:  *out = "pkr13"; return;
        case CV_IA64_Pkr14:  *out = "pkr14"; return;
        case CV_IA64_Pkr15:  *out = "pkr15"; return;

        // Region Registers

        case CV_IA64_Rr0:    *out = "rr0"; return;
        case CV_IA64_Rr1:    *out = "rr1"; return;
        case CV_IA64_Rr2:    *out = "rr2"; return;
        case CV_IA64_Rr3:    *out = "rr3"; return;
        case CV_IA64_Rr4:    *out = "rr4"; return;
        case CV_IA64_Rr5:    *out = "rr5"; return;
        case CV_IA64_Rr6:    *out = "rr6"; return;
        case CV_IA64_Rr7:    *out = "rr7"; return;

        // Performance Monitor Data Registers

        case CV_IA64_PFD0:   *out = "pfd0"; return;
        case CV_IA64_PFD1:   *out = "pfd1"; return;
        case CV_IA64_PFD2:   *out = "pfd2"; return;
        case CV_IA64_PFD3:   *out = "pfd3"; return;
        case CV_IA64_PFD4:   *out = "pfd4"; return;
        case CV_IA64_PFD5:   *out = "pfd5"; return;
        case CV_IA64_PFD6:   *out = "pfd6"; return;
        case CV_IA64_PFD7:   *out = "pfd7"; return;
        case CV_IA64_PFD8:   *out = "pfd8"; return;
        case CV_IA64_PFD9:   *out = "pfd9"; return;
        case CV_IA64_PFD10:  *out = "pfd10"; return;
        case CV_IA64_PFD11:  *out = "pfd11"; return;
        case CV_IA64_PFD12:  *out = "pfd12"; return;
        case CV_IA64_PFD13:  *out = "pfd13"; return;
        case CV_IA64_PFD14:  *out = "pfd14"; return;
        case CV_IA64_PFD15:  *out = "pfd15"; return;
        case CV_IA64_PFD16:  *out = "pfd16"; return;
        case CV_IA64_PFD17:  *out = "pfd17"; return;

        // Performance Monitor Config Registers

        case CV_IA64_PFC0:   *out = "pfc0"; return;
        case CV_IA64_PFC1:   *out = "pfc1"; return;
        case CV_IA64_PFC2:   *out = "pfc2"; return;
        case CV_IA64_PFC3:   *out = "pfc3"; return;
        case CV_IA64_PFC4:   *out = "pfc4"; return;
        case CV_IA64_PFC5:   *out = "pfc5"; return;
        case CV_IA64_PFC6:   *out = "pfc6"; return;
        case CV_IA64_PFC7:   *out = "pfc7"; return;
        case CV_IA64_PFC8:   *out = "pfc8"; return;
        case CV_IA64_PFC9:   *out = "pfc9"; return;
        case CV_IA64_PFC10:  *out = "pfc10"; return;
        case CV_IA64_PFC11:  *out = "pfc11"; return;
        case CV_IA64_PFC12:  *out = "pfc12"; return;
        case CV_IA64_PFC13:  *out = "pfc13"; return;
        case CV_IA64_PFC14:  *out = "pfc14"; return;
        case CV_IA64_PFC15:  *out = "pfc15"; return;

        // Instruction Translation Registers

        case CV_IA64_TrI0:   *out = "tri0"; return;
        case CV_IA64_TrI1:   *out = "tri1"; return;
        case CV_IA64_TrI2:   *out = "tri2"; return;
        case CV_IA64_TrI3:   *out = "tri3"; return;
        case CV_IA64_TrI4:   *out = "tri4"; return;
        case CV_IA64_TrI5:   *out = "tri5"; return;
        case CV_IA64_TrI6:   *out = "tri6"; return;
        case CV_IA64_TrI7:   *out = "tri7"; return;

        // Data Translation Registers

        case CV_IA64_TrD0:   *out = "trd0"; return;
        case CV_IA64_TrD1:   *out = "trd1"; return;
        case CV_IA64_TrD2:   *out = "trd2"; return;
        case CV_IA64_TrD3:   *out = "trd3"; return;
        case CV_IA64_TrD4:   *out = "trd4"; return;
        case CV_IA64_TrD5:   *out = "trd5"; return;
        case CV_IA64_TrD6:   *out = "trd6"; return;
        case CV_IA64_TrD7:   *out = "trd7"; return;

        // Instruction Breakpoint Registers

        case CV_IA64_DbI0:   *out = "dbi0"; return;
        case CV_IA64_DbI1:   *out = "dbi1"; return;
        case CV_IA64_DbI2:   *out = "dbi2"; return;
        case CV_IA64_DbI3:   *out = "dbi3"; return;
        case CV_IA64_DbI4:   *out = "dbi4"; return;
        case CV_IA64_DbI5:   *out = "dbi5"; return;
        case CV_IA64_DbI6:   *out = "dbi6"; return;
        case CV_IA64_DbI7:   *out = "dbi7"; return;

        // Data Breakpoint Registers

        case CV_IA64_DbD0:   *out = "dbd0"; return;
        case CV_IA64_DbD1:   *out = "dbd1"; return;
        case CV_IA64_DbD2:   *out = "dbd2"; return;
        case CV_IA64_DbD3:   *out = "dbd3"; return;
        case CV_IA64_DbD4:   *out = "dbd4"; return;
        case CV_IA64_DbD5:   *out = "dbd5"; return;
        case CV_IA64_DbD6:   *out = "dbd6"; return;
        case CV_IA64_DbD7:   *out = "dbd7"; return;
      }
      break;


    case CV_CFL_TRICORE:
      //
      // Register set for the TriCore processor.
      //
      switch ( reg )
      {
        case CV_TRI_NOREG:   *out = "noreg"; return;

        // General Purpose Data Registers

        case CV_TRI_D0:      *out = "d0"; return;
        case CV_TRI_D1:      *out = "d1"; return;
        case CV_TRI_D2:      *out = "d2"; return;
        case CV_TRI_D3:      *out = "d3"; return;
        case CV_TRI_D4:      *out = "d4"; return;
        case CV_TRI_D5:      *out = "d5"; return;
        case CV_TRI_D6:      *out = "d6"; return;
        case CV_TRI_D7:      *out = "d7"; return;
        case CV_TRI_D8:      *out = "d8"; return;
        case CV_TRI_D9:      *out = "d9"; return;
        case CV_TRI_D10:     *out = "d10"; return;
        case CV_TRI_D11:     *out = "d11"; return;
        case CV_TRI_D12:     *out = "d12"; return;
        case CV_TRI_D13:     *out = "d13"; return;
        case CV_TRI_D14:     *out = "d14"; return;
        case CV_TRI_D15:     *out = "d15"; return;

        // General Purpose Address Registers

        case CV_TRI_A0:      *out = "a0"; return;
        case CV_TRI_A1:      *out = "a1"; return;
        case CV_TRI_A2:      *out = "a2"; return;
        case CV_TRI_A3:      *out = "a3"; return;
        case CV_TRI_A4:      *out = "a4"; return;
        case CV_TRI_A5:      *out = "a5"; return;
        case CV_TRI_A6:      *out = "a6"; return;
        case CV_TRI_A7:      *out = "a7"; return;
        case CV_TRI_A8:      *out = "a8"; return;
        case CV_TRI_A9:      *out = "a9"; return;
        case CV_TRI_A10:     *out = "a10"; return;
        case CV_TRI_A11:     *out = "a11"; return;
        case CV_TRI_A12:     *out = "a12"; return;
        case CV_TRI_A13:     *out = "a13"; return;
        case CV_TRI_A14:     *out = "a14"; return;
        case CV_TRI_A15:     *out = "a15"; return;

        // Extended (64-bit) data registers

        case CV_TRI_E0:      *out = "e0"; return;
        case CV_TRI_E2:      *out = "e2"; return;
        case CV_TRI_E4:      *out = "e4"; return;
        case CV_TRI_E6:      *out = "e6"; return;
        case CV_TRI_E8:      *out = "e8"; return;
        case CV_TRI_E10:     *out = "e10"; return;
        case CV_TRI_E12:     *out = "e12"; return;
        case CV_TRI_E14:     *out = "e14"; return;

        // Extended (64-bit) address registers

        case CV_TRI_EA0:     *out = "ea0"; return;
        case CV_TRI_EA2:     *out = "ea2"; return;
        case CV_TRI_EA4:     *out = "ea4"; return;
        case CV_TRI_EA6:     *out = "ea6"; return;
        case CV_TRI_EA8:     *out = "ea8"; return;
        case CV_TRI_EA10:    *out = "ea10"; return;
        case CV_TRI_EA12:    *out = "ea12"; return;
        case CV_TRI_EA14:    *out = "ea14"; return;

        case CV_TRI_PSW:     *out = "psw"; return;
        case CV_TRI_PCXI:    *out = "pcxi"; return;
        case CV_TRI_PC:      *out = "pc"; return;
        case CV_TRI_FCX:     *out = "fcx"; return;
        case CV_TRI_LCX:     *out = "lcx"; return;
        case CV_TRI_ISP:     *out = "isp"; return;
        case CV_TRI_ICR:     *out = "icr"; return;
        case CV_TRI_BIV:     *out = "biv"; return;
        case CV_TRI_BTV:     *out = "btv"; return;
        case CV_TRI_SYSCON:  *out = "syscon"; return;
        case CV_TRI_DPRx_0:  *out = "dprx_0"; return;
        case CV_TRI_DPRx_1:  *out = "dprx_1"; return;
        case CV_TRI_DPRx_2:  *out = "dprx_2"; return;
        case CV_TRI_DPRx_3:  *out = "dprx_3"; return;
//        case CV_TRI_CPRx_0:  *out = "cprx_0"; return;
//        case CV_TRI_CPRx_1:  *out = "cprx_1"; return;
//        case CV_TRI_CPRx_2:  *out = "cprx_2"; return;
//        case CV_TRI_CPRx_3:  *out = "cprx_3"; return;
//        case CV_TRI_DPMx_0:  *out = "dpmx_0"; return;
//        case CV_TRI_DPMx_1:  *out = "dpmx_1"; return;
//        case CV_TRI_DPMx_2:  *out = "dpmx_2"; return;
//        case CV_TRI_DPMx_3:  *out = "dpmx_3"; return;
//        case CV_TRI_CPMx_0:  *out = "cpmx_0"; return;
//        case CV_TRI_CPMx_1:  *out = "cpmx_1"; return;
//        case CV_TRI_CPMx_2:  *out = "cpmx_2"; return;
//        case CV_TRI_CPMx_3:  *out = "cpmx_3"; return;
        case CV_TRI_DBGSSR:  *out = "dbgssr"; return;
        case CV_TRI_EXEVT:   *out = "exevt"; return;
        case CV_TRI_SWEVT:   *out = "swevt"; return;
        case CV_TRI_CREVT:   *out = "crevt"; return;
        case CV_TRI_TRnEVT:  *out = "trnevt"; return;
        case CV_TRI_MMUCON:  *out = "mmucon"; return;
        case CV_TRI_ASI:     *out = "asi"; return;
        case CV_TRI_TVA:     *out = "tva"; return;
        case CV_TRI_TPA:     *out = "tpa"; return;
        case CV_TRI_TPX:     *out = "tpx"; return;
        case CV_TRI_TFA:     *out = "tfa"; return;
      }
      break;

    case CV_CFL_AM33:
      //
      // Register set for the AM33 and related processors.
      //
      switch ( reg )
      {
        case CV_AM33_NOREG:  *out = "noreg"; return;

        // "Extended" (general purpose integer) registers
        case CV_AM33_E0:     *out = "e0"; return;
        case CV_AM33_E1:     *out = "e1"; return;
        case CV_AM33_E2:     *out = "e2"; return;
        case CV_AM33_E3:     *out = "e3"; return;
        case CV_AM33_E4:     *out = "e4"; return;
        case CV_AM33_E5:     *out = "e5"; return;
        case CV_AM33_E6:     *out = "e6"; return;
        case CV_AM33_E7:     *out = "e7"; return;

        // Address registers
        case CV_AM33_A0:     *out = "a0"; return;
        case CV_AM33_A1:     *out = "a1"; return;
        case CV_AM33_A2:     *out = "a2"; return;
        case CV_AM33_A3:     *out = "a3"; return;

        // Integer data registers
        case CV_AM33_D0:     *out = "d0"; return;
        case CV_AM33_D1:     *out = "d1"; return;
        case CV_AM33_D2:     *out = "d2"; return;
        case CV_AM33_D3:     *out = "d3"; return;

        // (Single-precision) floating-point registers
        case CV_AM33_FS0:    *out = "fs0"; return;
        case CV_AM33_FS1:    *out = "fs1"; return;
        case CV_AM33_FS2:    *out = "fs2"; return;
        case CV_AM33_FS3:    *out = "fs3"; return;
        case CV_AM33_FS4:    *out = "fs4"; return;
        case CV_AM33_FS5:    *out = "fs5"; return;
        case CV_AM33_FS6:    *out = "fs6"; return;
        case CV_AM33_FS7:    *out = "fs7"; return;
        case CV_AM33_FS8:    *out = "fs8"; return;
        case CV_AM33_FS9:    *out = "fs9"; return;
        case CV_AM33_FS10:   *out = "fs10"; return;
        case CV_AM33_FS11:   *out = "fs11"; return;
        case CV_AM33_FS12:   *out = "fs12"; return;
        case CV_AM33_FS13:   *out = "fs13"; return;
        case CV_AM33_FS14:   *out = "fs14"; return;
        case CV_AM33_FS15:   *out = "fs15"; return;
        case CV_AM33_FS16:   *out = "fs16"; return;
        case CV_AM33_FS17:   *out = "fs17"; return;
        case CV_AM33_FS18:   *out = "fs18"; return;
        case CV_AM33_FS19:   *out = "fs19"; return;
        case CV_AM33_FS20:   *out = "fs20"; return;
        case CV_AM33_FS21:   *out = "fs21"; return;
        case CV_AM33_FS22:   *out = "fs22"; return;
        case CV_AM33_FS23:   *out = "fs23"; return;
        case CV_AM33_FS24:   *out = "fs24"; return;
        case CV_AM33_FS25:   *out = "fs25"; return;
        case CV_AM33_FS26:   *out = "fs26"; return;
        case CV_AM33_FS27:   *out = "fs27"; return;
        case CV_AM33_FS28:   *out = "fs28"; return;
        case CV_AM33_FS29:   *out = "fs29"; return;
        case CV_AM33_FS30:   *out = "fs30"; return;
        case CV_AM33_FS31:   *out = "fs31"; return;

        // Special purpose registers

        // Stack pointer
        case CV_AM33_SP:     *out = "sp"; return;

        // Program counter
        case CV_AM33_PC:     *out = "pc"; return;

        // Multiply-divide/accumulate registers
        case CV_AM33_MDR:    *out = "mdr"; return;
        case CV_AM33_MDRQ:   *out = "mdrq"; return;
        case CV_AM33_MCRH:   *out = "mcrh"; return;
        case CV_AM33_MCRL:   *out = "mcrl"; return;
        case CV_AM33_MCVF:   *out = "mcvf"; return;

        // CPU status words
        case CV_AM33_EPSW:   *out = "epsw"; return;
        case CV_AM33_FPCR:   *out = "fpcr"; return;

        // Loop buffer registers
        case CV_AM33_LIR:    *out = "lir"; return;
        case CV_AM33_LAR:    *out = "lar"; return;
      }
      break;

    case CV_CFL_M32R:
      //
      // Register set for the Mitsubishi M32R
      //
      switch ( reg )
      {
        case CV_M32R_NOREG:  *out = "noreg"; return;
        case CV_M32R_R0:     *out = "r0"; return;
        case CV_M32R_R1:     *out = "r1"; return;
        case CV_M32R_R2:     *out = "r2"; return;
        case CV_M32R_R3:     *out = "r3"; return;
        case CV_M32R_R4:     *out = "r4"; return;
        case CV_M32R_R5:     *out = "r5"; return;
        case CV_M32R_R6:     *out = "r6"; return;
        case CV_M32R_R7:     *out = "r7"; return;
        case CV_M32R_R8:     *out = "r8"; return;
        case CV_M32R_R9:     *out = "r9"; return;
        case CV_M32R_R10:    *out = "r10"; return;
        case CV_M32R_R11:    *out = "r11"; return;
        case CV_M32R_R12:    *out = "r12"; return;// Gloabal Pointer, if used
        case CV_M32R_R13:    *out = "r13"; return;// Frame Pointer, if allocated
        case CV_M32R_R14:    *out = "r14"; return;// Link Register
        case CV_M32R_R15:    *out = "r15"; return;// Stack Pointer
        case CV_M32R_PSW:    *out = "psw"; return;// Preocessor Status Register
        case CV_M32R_CBR:    *out = "cbr"; return;// Condition Bit Register
        case CV_M32R_SPI:    *out = "spi"; return;// Interrupt Stack Pointer
        case CV_M32R_SPU:    *out = "spu"; return;// User Stack Pointer
        case CV_M32R_SPO:    *out = "spo"; return;// OS Stack Pointer
        case CV_M32R_BPC:    *out = "bpc"; return;// Backup Program Counter
        case CV_M32R_ACHI:   *out = "achi"; return;// Accumulator High
        case CV_M32R_ACLO:   *out = "aclo"; return;// Accumulator Low
        case CV_M32R_PC:     *out = "pc"; return;// Program Counter
      }
      break;

      //
      // Register set for the SuperH SHMedia processor including compact
      // mode
      //
    case CV_CFL_SHMEDIA:
      switch ( reg )
      {
        // Integer - 64 bit general registers
        case CV_SHMEDIA_NOREG:*out = "noreg"; return;
        case CV_SHMEDIA_R0:  *out = "r0"; return;
        case CV_SHMEDIA_R1:  *out = "r1"; return;
        case CV_SHMEDIA_R2:  *out = "r2"; return;
        case CV_SHMEDIA_R3:  *out = "r3"; return;
        case CV_SHMEDIA_R4:  *out = "r4"; return;
        case CV_SHMEDIA_R5:  *out = "r5"; return;
        case CV_SHMEDIA_R6:  *out = "r6"; return;
        case CV_SHMEDIA_R7:  *out = "r7"; return;
        case CV_SHMEDIA_R8:  *out = "r8"; return;
        case CV_SHMEDIA_R9:  *out = "r9"; return;
        case CV_SHMEDIA_R10: *out = "r10"; return;
        case CV_SHMEDIA_R11: *out = "r11"; return;
        case CV_SHMEDIA_R12: *out = "r12"; return;
        case CV_SHMEDIA_R13: *out = "r13"; return;
        case CV_SHMEDIA_R14: *out = "r14"; return;
        case CV_SHMEDIA_R15: *out = "r15"; return;
        case CV_SHMEDIA_R16: *out = "r16"; return;
        case CV_SHMEDIA_R17: *out = "r17"; return;
        case CV_SHMEDIA_R18: *out = "r18"; return;
        case CV_SHMEDIA_R19: *out = "r19"; return;
        case CV_SHMEDIA_R20: *out = "r20"; return;
        case CV_SHMEDIA_R21: *out = "r21"; return;
        case CV_SHMEDIA_R22: *out = "r22"; return;
        case CV_SHMEDIA_R23: *out = "r23"; return;
        case CV_SHMEDIA_R24: *out = "r24"; return;
        case CV_SHMEDIA_R25: *out = "r25"; return;
        case CV_SHMEDIA_R26: *out = "r26"; return;
        case CV_SHMEDIA_R27: *out = "r27"; return;
        case CV_SHMEDIA_R28: *out = "r28"; return;
        case CV_SHMEDIA_R29: *out = "r29"; return;
        case CV_SHMEDIA_R30: *out = "r30"; return;
        case CV_SHMEDIA_R31: *out = "r31"; return;
        case CV_SHMEDIA_R32: *out = "r32"; return;
        case CV_SHMEDIA_R33: *out = "r33"; return;
        case CV_SHMEDIA_R34: *out = "r34"; return;
        case CV_SHMEDIA_R35: *out = "r35"; return;
        case CV_SHMEDIA_R36: *out = "r36"; return;
        case CV_SHMEDIA_R37: *out = "r37"; return;
        case CV_SHMEDIA_R38: *out = "r38"; return;
        case CV_SHMEDIA_R39: *out = "r39"; return;
        case CV_SHMEDIA_R40: *out = "r40"; return;
        case CV_SHMEDIA_R41: *out = "r41"; return;
        case CV_SHMEDIA_R42: *out = "r42"; return;
        case CV_SHMEDIA_R43: *out = "r43"; return;
        case CV_SHMEDIA_R44: *out = "r44"; return;
        case CV_SHMEDIA_R45: *out = "r45"; return;
        case CV_SHMEDIA_R46: *out = "r46"; return;
        case CV_SHMEDIA_R47: *out = "r47"; return;
        case CV_SHMEDIA_R48: *out = "r48"; return;
        case CV_SHMEDIA_R49: *out = "r49"; return;
        case CV_SHMEDIA_R50: *out = "r50"; return;
        case CV_SHMEDIA_R51: *out = "r51"; return;
        case CV_SHMEDIA_R52: *out = "r52"; return;
        case CV_SHMEDIA_R53: *out = "r53"; return;
        case CV_SHMEDIA_R54: *out = "r54"; return;
        case CV_SHMEDIA_R55: *out = "r55"; return;
        case CV_SHMEDIA_R56: *out = "r56"; return;
        case CV_SHMEDIA_R57: *out = "r57"; return;
        case CV_SHMEDIA_R58: *out = "r58"; return;
        case CV_SHMEDIA_R59: *out = "r59"; return;
        case CV_SHMEDIA_R60: *out = "r60"; return;
        case CV_SHMEDIA_R61: *out = "r61"; return;
        case CV_SHMEDIA_R62: *out = "r62"; return;
        case CV_SHMEDIA_R63: *out = "r63"; return;

        // Target Registers - 32 bit
        case CV_SHMEDIA_TR0: *out = "tr0"; return;
        case CV_SHMEDIA_TR1: *out = "tr1"; return;
        case CV_SHMEDIA_TR2: *out = "tr2"; return;
        case CV_SHMEDIA_TR3: *out = "tr3"; return;
        case CV_SHMEDIA_TR4: *out = "tr4"; return;
        case CV_SHMEDIA_TR5: *out = "tr5"; return;
        case CV_SHMEDIA_TR6: *out = "tr6"; return;
        case CV_SHMEDIA_TR7: *out = "tr7"; return;
        case CV_SHMEDIA_TR8: *out = "tr8"; return;  // future-proof
        case CV_SHMEDIA_TR9: *out = "tr9"; return;  // future-proof
        case CV_SHMEDIA_TR10:*out = "tr10"; return; // future-proof
        case CV_SHMEDIA_TR11:*out = "tr11"; return; // future-proof
        case CV_SHMEDIA_TR12:*out = "tr12"; return; // future-proof
        case CV_SHMEDIA_TR13:*out = "tr13"; return; // future-proof
        case CV_SHMEDIA_TR14:*out = "tr14"; return; // future-proof
        case CV_SHMEDIA_TR15:*out = "tr15"; return; // future-proof

        // Single - 32 bit fp registers
        case CV_SHMEDIA_FR0: *out = "fr0"; return;
        case CV_SHMEDIA_FR1: *out = "fr1"; return;
        case CV_SHMEDIA_FR2: *out = "fr2"; return;
        case CV_SHMEDIA_FR3: *out = "fr3"; return;
        case CV_SHMEDIA_FR4: *out = "fr4"; return;
        case CV_SHMEDIA_FR5: *out = "fr5"; return;
        case CV_SHMEDIA_FR6: *out = "fr6"; return;
        case CV_SHMEDIA_FR7: *out = "fr7"; return;
        case CV_SHMEDIA_FR8: *out = "fr8"; return;
        case CV_SHMEDIA_FR9: *out = "fr9"; return;
        case CV_SHMEDIA_FR10:*out = "fr10"; return;
        case CV_SHMEDIA_FR11:*out = "fr11"; return;
        case CV_SHMEDIA_FR12:*out = "fr12"; return;
        case CV_SHMEDIA_FR13:*out = "fr13"; return;
        case CV_SHMEDIA_FR14:*out = "fr14"; return;
        case CV_SHMEDIA_FR15:*out = "fr15"; return;
        case CV_SHMEDIA_FR16:*out = "fr16"; return;
        case CV_SHMEDIA_FR17:*out = "fr17"; return;
        case CV_SHMEDIA_FR18:*out = "fr18"; return;
        case CV_SHMEDIA_FR19:*out = "fr19"; return;
        case CV_SHMEDIA_FR20:*out = "fr20"; return;
        case CV_SHMEDIA_FR21:*out = "fr21"; return;
        case CV_SHMEDIA_FR22:*out = "fr22"; return;
        case CV_SHMEDIA_FR23:*out = "fr23"; return;
        case CV_SHMEDIA_FR24:*out = "fr24"; return;
        case CV_SHMEDIA_FR25:*out = "fr25"; return;
        case CV_SHMEDIA_FR26:*out = "fr26"; return;
        case CV_SHMEDIA_FR27:*out = "fr27"; return;
        case CV_SHMEDIA_FR28:*out = "fr28"; return;
        case CV_SHMEDIA_FR29:*out = "fr29"; return;
        case CV_SHMEDIA_FR30:*out = "fr30"; return;
        case CV_SHMEDIA_FR31:*out = "fr31"; return;
        case CV_SHMEDIA_FR32:*out = "fr32"; return;
        case CV_SHMEDIA_FR33:*out = "fr33"; return;
        case CV_SHMEDIA_FR34:*out = "fr34"; return;
        case CV_SHMEDIA_FR35:*out = "fr35"; return;
        case CV_SHMEDIA_FR36:*out = "fr36"; return;
        case CV_SHMEDIA_FR37:*out = "fr37"; return;
        case CV_SHMEDIA_FR38:*out = "fr38"; return;
        case CV_SHMEDIA_FR39:*out = "fr39"; return;
        case CV_SHMEDIA_FR40:*out = "fr40"; return;
        case CV_SHMEDIA_FR41:*out = "fr41"; return;
        case CV_SHMEDIA_FR42:*out = "fr42"; return;
        case CV_SHMEDIA_FR43:*out = "fr43"; return;
        case CV_SHMEDIA_FR44:*out = "fr44"; return;
        case CV_SHMEDIA_FR45:*out = "fr45"; return;
        case CV_SHMEDIA_FR46:*out = "fr46"; return;
        case CV_SHMEDIA_FR47:*out = "fr47"; return;
        case CV_SHMEDIA_FR48:*out = "fr48"; return;
        case CV_SHMEDIA_FR49:*out = "fr49"; return;
        case CV_SHMEDIA_FR50:*out = "fr50"; return;
        case CV_SHMEDIA_FR51:*out = "fr51"; return;
        case CV_SHMEDIA_FR52:*out = "fr52"; return;
        case CV_SHMEDIA_FR53:*out = "fr53"; return;
        case CV_SHMEDIA_FR54:*out = "fr54"; return;
        case CV_SHMEDIA_FR55:*out = "fr55"; return;
        case CV_SHMEDIA_FR56:*out = "fr56"; return;
        case CV_SHMEDIA_FR57:*out = "fr57"; return;
        case CV_SHMEDIA_FR58:*out = "fr58"; return;
        case CV_SHMEDIA_FR59:*out = "fr59"; return;
        case CV_SHMEDIA_FR60:*out = "fr60"; return;
        case CV_SHMEDIA_FR61:*out = "fr61"; return;
        case CV_SHMEDIA_FR62:*out = "fr62"; return;
        case CV_SHMEDIA_FR63:*out = "fr63"; return;

        // Double - 64 bit synonyms for 32bit fp register pairs
        //          subtract 128 to find first base single register
        case CV_SHMEDIA_DR0: *out = "dr0"; return;
        case CV_SHMEDIA_DR2: *out = "dr2"; return;
        case CV_SHMEDIA_DR4: *out = "dr4"; return;
        case CV_SHMEDIA_DR6: *out = "dr6"; return;
        case CV_SHMEDIA_DR8: *out = "dr8"; return;
        case CV_SHMEDIA_DR10:*out = "dr10"; return;
        case CV_SHMEDIA_DR12:*out = "dr12"; return;
        case CV_SHMEDIA_DR14:*out = "dr14"; return;
        case CV_SHMEDIA_DR16:*out = "dr16"; return;
        case CV_SHMEDIA_DR18:*out = "dr18"; return;
        case CV_SHMEDIA_DR20:*out = "dr20"; return;
        case CV_SHMEDIA_DR22:*out = "dr22"; return;
        case CV_SHMEDIA_DR24:*out = "dr24"; return;
        case CV_SHMEDIA_DR26:*out = "dr26"; return;
        case CV_SHMEDIA_DR28:*out = "dr28"; return;
        case CV_SHMEDIA_DR30:*out = "dr30"; return;
        case CV_SHMEDIA_DR32:*out = "dr32"; return;
        case CV_SHMEDIA_DR34:*out = "dr34"; return;
        case CV_SHMEDIA_DR36:*out = "dr36"; return;
        case CV_SHMEDIA_DR38:*out = "dr38"; return;
        case CV_SHMEDIA_DR40:*out = "dr40"; return;
        case CV_SHMEDIA_DR42:*out = "dr42"; return;
        case CV_SHMEDIA_DR44:*out = "dr44"; return;
        case CV_SHMEDIA_DR46:*out = "dr46"; return;
        case CV_SHMEDIA_DR48:*out = "dr48"; return;
        case CV_SHMEDIA_DR50:*out = "dr50"; return;
        case CV_SHMEDIA_DR52:*out = "dr52"; return;
        case CV_SHMEDIA_DR54:*out = "dr54"; return;
        case CV_SHMEDIA_DR56:*out = "dr56"; return;
        case CV_SHMEDIA_DR58:*out = "dr58"; return;
        case CV_SHMEDIA_DR60:*out = "dr60"; return;
        case CV_SHMEDIA_DR62:*out = "dr62"; return;

        // Vector - 128 bit synonyms for 32bit fp register quads
        //          subtract 384 to find first base single register
        case CV_SHMEDIA_FV0: *out = "fv0"; return;
        case CV_SHMEDIA_FV4: *out = "fv4"; return;
        case CV_SHMEDIA_FV8: *out = "fv8"; return;
        case CV_SHMEDIA_FV12:*out = "fv12"; return;
        case CV_SHMEDIA_FV16:*out = "fv16"; return;
        case CV_SHMEDIA_FV20:*out = "fv20"; return;
        case CV_SHMEDIA_FV24:*out = "fv24"; return;
        case CV_SHMEDIA_FV28:*out = "fv28"; return;
        case CV_SHMEDIA_FV32:*out = "fv32"; return;
        case CV_SHMEDIA_FV36:*out = "fv36"; return;
        case CV_SHMEDIA_FV40:*out = "fv40"; return;
        case CV_SHMEDIA_FV44:*out = "fv44"; return;
        case CV_SHMEDIA_FV48:*out = "fv48"; return;
        case CV_SHMEDIA_FV52:*out = "fv52"; return;
        case CV_SHMEDIA_FV56:*out = "fv56"; return;
        case CV_SHMEDIA_FV60:*out = "fv60"; return;

        // Matrix - 512 bit synonyms for 16 adjacent 32bit fp registers
        //          subtract 896 to find first base single register
        case CV_SHMEDIA_MTRX0: *out = "mtrx0"; return;
        case CV_SHMEDIA_MTRX16:*out = "mtrx16"; return;
        case CV_SHMEDIA_MTRX32:*out = "mtrx32"; return;
        case CV_SHMEDIA_MTRX48:*out = "mtrx48"; return;

        // Control - Implementation defined 64bit control registers
        case CV_SHMEDIA_CR0: *out = "cr0"; return;
        case CV_SHMEDIA_CR1: *out = "cr1"; return;
        case CV_SHMEDIA_CR2: *out = "cr2"; return;
        case CV_SHMEDIA_CR3: *out = "cr3"; return;
        case CV_SHMEDIA_CR4: *out = "cr4"; return;
        case CV_SHMEDIA_CR5: *out = "cr5"; return;
        case CV_SHMEDIA_CR6: *out = "cr6"; return;
        case CV_SHMEDIA_CR7: *out = "cr7"; return;
        case CV_SHMEDIA_CR8: *out = "cr8"; return;
        case CV_SHMEDIA_CR9: *out = "cr9"; return;
        case CV_SHMEDIA_CR10:*out = "cr10"; return;
        case CV_SHMEDIA_CR11:*out = "cr11"; return;
        case CV_SHMEDIA_CR12:*out = "cr12"; return;
        case CV_SHMEDIA_CR13:*out = "cr13"; return;
        case CV_SHMEDIA_CR14:*out = "cr14"; return;
        case CV_SHMEDIA_CR15:*out = "cr15"; return;
        case CV_SHMEDIA_CR16:*out = "cr16"; return;
        case CV_SHMEDIA_CR17:*out = "cr17"; return;
        case CV_SHMEDIA_CR18:*out = "cr18"; return;
        case CV_SHMEDIA_CR19:*out = "cr19"; return;
        case CV_SHMEDIA_CR20:*out = "cr20"; return;
        case CV_SHMEDIA_CR21:*out = "cr21"; return;
        case CV_SHMEDIA_CR22:*out = "cr22"; return;
        case CV_SHMEDIA_CR23:*out = "cr23"; return;
        case CV_SHMEDIA_CR24:*out = "cr24"; return;
        case CV_SHMEDIA_CR25:*out = "cr25"; return;
        case CV_SHMEDIA_CR26:*out = "cr26"; return;
        case CV_SHMEDIA_CR27:*out = "cr27"; return;
        case CV_SHMEDIA_CR28:*out = "cr28"; return;
        case CV_SHMEDIA_CR29:*out = "cr29"; return;
        case CV_SHMEDIA_CR30:*out = "cr30"; return;
        case CV_SHMEDIA_CR31:*out = "cr31"; return;
        case CV_SHMEDIA_CR32:*out = "cr32"; return;
        case CV_SHMEDIA_CR33:*out = "cr33"; return;
        case CV_SHMEDIA_CR34:*out = "cr34"; return;
        case CV_SHMEDIA_CR35:*out = "cr35"; return;
        case CV_SHMEDIA_CR36:*out = "cr36"; return;
        case CV_SHMEDIA_CR37:*out = "cr37"; return;
        case CV_SHMEDIA_CR38:*out = "cr38"; return;
        case CV_SHMEDIA_CR39:*out = "cr39"; return;
        case CV_SHMEDIA_CR40:*out = "cr40"; return;
        case CV_SHMEDIA_CR41:*out = "cr41"; return;
        case CV_SHMEDIA_CR42:*out = "cr42"; return;
        case CV_SHMEDIA_CR43:*out = "cr43"; return;
        case CV_SHMEDIA_CR44:*out = "cr44"; return;
        case CV_SHMEDIA_CR45:*out = "cr45"; return;
        case CV_SHMEDIA_CR46:*out = "cr46"; return;
        case CV_SHMEDIA_CR47:*out = "cr47"; return;
        case CV_SHMEDIA_CR48:*out = "cr48"; return;
        case CV_SHMEDIA_CR49:*out = "cr49"; return;
        case CV_SHMEDIA_CR50:*out = "cr50"; return;
        case CV_SHMEDIA_CR51:*out = "cr51"; return;
        case CV_SHMEDIA_CR52:*out = "cr52"; return;
        case CV_SHMEDIA_CR53:*out = "cr53"; return;
        case CV_SHMEDIA_CR54:*out = "cr54"; return;
        case CV_SHMEDIA_CR55:*out = "cr55"; return;
        case CV_SHMEDIA_CR56:*out = "cr56"; return;
        case CV_SHMEDIA_CR57:*out = "cr57"; return;
        case CV_SHMEDIA_CR58:*out = "cr58"; return;
        case CV_SHMEDIA_CR59:*out = "cr59"; return;
        case CV_SHMEDIA_CR60:*out = "cr60"; return;
        case CV_SHMEDIA_CR61:*out = "cr61"; return;
        case CV_SHMEDIA_CR62:*out = "cr62"; return;
        case CV_SHMEDIA_CR63:*out = "cr63"; return;

        case CV_SHMEDIA_FPSCR: *out = "fpscr"; return;

        // Compact mode synonyms
//        case CV_SHMEDIA_GBR:  *out = "gbr"; return;
        case CV_SHMEDIA_MACL: *out = "macl"; return;// synonym for lower 32bits of media R17
        case CV_SHMEDIA_MACH: *out = "mach"; return;// synonym for upper 32bits of media R17
//        case CV_SHMEDIA_PR:   *out = "pr"; return;
        case CV_SHMEDIA_T:    *out = "t"; return;// synonym for lowest bit of media R19
//        case CV_SHMEDIA_FPUL: *out = "fpul"; return;
        case CV_SHMEDIA_PC:   *out = "pc"; return;
//        case CV_SHMEDIA_SR:   *out = "sr"; return;
      }
      break;

    case CV_CFL_AMD64:
      //
      // AMD64 registers
      //
      switch ( reg )
      {
        case CV_AMD64_AL:     *out = "al"; return;
        case CV_AMD64_CL:     *out = "cl"; return;
        case CV_AMD64_DL:     *out = "dl"; return;
        case CV_AMD64_BL:     *out = "bl"; return;
        case CV_AMD64_AH:     *out = "ah"; return;
        case CV_AMD64_CH:     *out = "ch"; return;
        case CV_AMD64_DH:     *out = "dh"; return;
        case CV_AMD64_BH:     *out = "bh"; return;
        case CV_AMD64_AX:     *out = "ax"; return;
        case CV_AMD64_CX:     *out = "cx"; return;
        case CV_AMD64_DX:     *out = "dx"; return;
        case CV_AMD64_BX:     *out = "bx"; return;
        case CV_AMD64_SP:     *out = "sp"; return;
        case CV_AMD64_BP:     *out = "bp"; return;
        case CV_AMD64_SI:     *out = "si"; return;
        case CV_AMD64_DI:     *out = "di"; return;
        case CV_AMD64_EAX:    *out = "eax"; return;
        case CV_AMD64_ECX:    *out = "ecx"; return;
        case CV_AMD64_EDX:    *out = "edx"; return;
        case CV_AMD64_EBX:    *out = "ebx"; return;
        case CV_AMD64_ESP:    *out = "esp"; return;
        case CV_AMD64_EBP:    *out = "ebp"; return;
        case CV_AMD64_ESI:    *out = "esi"; return;
        case CV_AMD64_EDI:    *out = "edi"; return;
        case CV_AMD64_ES:     *out = "es"; return;
        case CV_AMD64_CS:     *out = "cs"; return;
        case CV_AMD64_SS:     *out = "ss"; return;
        case CV_AMD64_DS:     *out = "ds"; return;
        case CV_AMD64_FS:     *out = "fs"; return;
        case CV_AMD64_GS:     *out = "gs"; return;
        case CV_AMD64_FLAGS:  *out = "flags"; return;
        case CV_AMD64_RIP:    *out = "rip"; return;
        case CV_AMD64_EFLAGS: *out = "eflags"; return;

        // Control registers
        case CV_AMD64_CR0:    *out = "cr0"; return;
        case CV_AMD64_CR1:    *out = "cr1"; return;
        case CV_AMD64_CR2:    *out = "cr2"; return;
        case CV_AMD64_CR3:    *out = "cr3"; return;
        case CV_AMD64_CR4:    *out = "cr4"; return;
        case CV_AMD64_CR8:    *out = "cr8"; return;

        // Debug registers
        case CV_AMD64_DR0:    *out = "dr0"; return;
        case CV_AMD64_DR1:    *out = "dr1"; return;
        case CV_AMD64_DR2:    *out = "dr2"; return;
        case CV_AMD64_DR3:    *out = "dr3"; return;
        case CV_AMD64_DR4:    *out = "dr4"; return;
        case CV_AMD64_DR5:    *out = "dr5"; return;
        case CV_AMD64_DR6:    *out = "dr6"; return;
        case CV_AMD64_DR7:    *out = "dr7"; return;
        case CV_AMD64_DR8:    *out = "dr8"; return;
        case CV_AMD64_DR9:    *out = "dr9"; return;
        case CV_AMD64_DR10:   *out = "dr10"; return;
        case CV_AMD64_DR11:   *out = "dr11"; return;
        case CV_AMD64_DR12:   *out = "dr12"; return;
        case CV_AMD64_DR13:   *out = "dr13"; return;
        case CV_AMD64_DR14:   *out = "dr14"; return;
        case CV_AMD64_DR15:   *out = "dr15"; return;

        case CV_AMD64_GDTR:   *out = "gdtr"; return;
        case CV_AMD64_GDTL:   *out = "gdtl"; return;
        case CV_AMD64_IDTR:   *out = "idtr"; return;
        case CV_AMD64_IDTL:   *out = "idtl"; return;
        case CV_AMD64_LDTR:   *out = "ldtr"; return;
        case CV_AMD64_TR:     *out = "tr"; return;

        case CV_AMD64_ST0:    *out = "st0"; return;
        case CV_AMD64_ST1:    *out = "st1"; return;
        case CV_AMD64_ST2:    *out = "st2"; return;
        case CV_AMD64_ST3:    *out = "st3"; return;
        case CV_AMD64_ST4:    *out = "st4"; return;
        case CV_AMD64_ST5:    *out = "st5"; return;
        case CV_AMD64_ST6:    *out = "st6"; return;
        case CV_AMD64_ST7:    *out = "st7"; return;
        case CV_AMD64_CTRL:   *out = "ctrl"; return;
        case CV_AMD64_STAT:   *out = "stat"; return;
        case CV_AMD64_TAG:    *out = "tag"; return;
        case CV_AMD64_FPIP:   *out = "fpip"; return;
        case CV_AMD64_FPCS:   *out = "fpcs"; return;
        case CV_AMD64_FPDO:   *out = "fpdo"; return;
        case CV_AMD64_FPDS:   *out = "fpds"; return;
        case CV_AMD64_ISEM:   *out = "isem"; return;
        case CV_AMD64_FPEIP:  *out = "fpeip"; return;
        case CV_AMD64_FPEDO:  *out = "fpedo"; return;

        case CV_AMD64_MM0:    *out = "mm0"; return;
        case CV_AMD64_MM1:    *out = "mm1"; return;
        case CV_AMD64_MM2:    *out = "mm2"; return;
        case CV_AMD64_MM3:    *out = "mm3"; return;
        case CV_AMD64_MM4:    *out = "mm4"; return;
        case CV_AMD64_MM5:    *out = "mm5"; return;
        case CV_AMD64_MM6:    *out = "mm6"; return;
        case CV_AMD64_MM7:    *out = "mm7"; return;

        case CV_AMD64_XMM0:   *out = "xmm0"; return;// KATMAI registers
        case CV_AMD64_XMM1:   *out = "xmm1"; return;
        case CV_AMD64_XMM2:   *out = "xmm2"; return;
        case CV_AMD64_XMM3:   *out = "xmm3"; return;
        case CV_AMD64_XMM4:   *out = "xmm4"; return;
        case CV_AMD64_XMM5:   *out = "xmm5"; return;
        case CV_AMD64_XMM6:   *out = "xmm6"; return;
        case CV_AMD64_XMM7:   *out = "xmm7"; return;

        case CV_AMD64_XMM0_0: *out = "xmm0_0"; return;  // KATMAI sub-registers
        case CV_AMD64_XMM0_1: *out = "xmm0_1"; return;
        case CV_AMD64_XMM0_2: *out = "xmm0_2"; return;
        case CV_AMD64_XMM0_3: *out = "xmm0_3"; return;
        case CV_AMD64_XMM1_0: *out = "xmm1_0"; return;
        case CV_AMD64_XMM1_1: *out = "xmm1_1"; return;
        case CV_AMD64_XMM1_2: *out = "xmm1_2"; return;
        case CV_AMD64_XMM1_3: *out = "xmm1_3"; return;
        case CV_AMD64_XMM2_0: *out = "xmm2_0"; return;
        case CV_AMD64_XMM2_1: *out = "xmm2_1"; return;
        case CV_AMD64_XMM2_2: *out = "xmm2_2"; return;
        case CV_AMD64_XMM2_3: *out = "xmm2_3"; return;
        case CV_AMD64_XMM3_0: *out = "xmm3_0"; return;
        case CV_AMD64_XMM3_1: *out = "xmm3_1"; return;
        case CV_AMD64_XMM3_2: *out = "xmm3_2"; return;
        case CV_AMD64_XMM3_3: *out = "xmm3_3"; return;
        case CV_AMD64_XMM4_0: *out = "xmm4_0"; return;
        case CV_AMD64_XMM4_1: *out = "xmm4_1"; return;
        case CV_AMD64_XMM4_2: *out = "xmm4_2"; return;
        case CV_AMD64_XMM4_3: *out = "xmm4_3"; return;
        case CV_AMD64_XMM5_0: *out = "xmm5_0"; return;
        case CV_AMD64_XMM5_1: *out = "xmm5_1"; return;
        case CV_AMD64_XMM5_2: *out = "xmm5_2"; return;
        case CV_AMD64_XMM5_3: *out = "xmm5_3"; return;
        case CV_AMD64_XMM6_0: *out = "xmm6_0"; return;
        case CV_AMD64_XMM6_1: *out = "xmm6_1"; return;
        case CV_AMD64_XMM6_2: *out = "xmm6_2"; return;
        case CV_AMD64_XMM6_3: *out = "xmm6_3"; return;
        case CV_AMD64_XMM7_0: *out = "xmm7_0"; return;
        case CV_AMD64_XMM7_1: *out = "xmm7_1"; return;
        case CV_AMD64_XMM7_2: *out = "xmm7_2"; return;
        case CV_AMD64_XMM7_3: *out = "xmm7_3"; return;

        case CV_AMD64_XMM0L:  *out = "xmm0l"; return;
        case CV_AMD64_XMM1L:  *out = "xmm1l"; return;
        case CV_AMD64_XMM2L:  *out = "xmm2l"; return;
        case CV_AMD64_XMM3L:  *out = "xmm3l"; return;
        case CV_AMD64_XMM4L:  *out = "xmm4l"; return;
        case CV_AMD64_XMM5L:  *out = "xmm5l"; return;
        case CV_AMD64_XMM6L:  *out = "xmm6l"; return;
        case CV_AMD64_XMM7L:  *out = "xmm7l"; return;

        case CV_AMD64_XMM0H:  *out = "xmm0h"; return;
        case CV_AMD64_XMM1H:  *out = "xmm1h"; return;
        case CV_AMD64_XMM2H:  *out = "xmm2h"; return;
        case CV_AMD64_XMM3H:  *out = "xmm3h"; return;
        case CV_AMD64_XMM4H:  *out = "xmm4h"; return;
        case CV_AMD64_XMM5H:  *out = "xmm5h"; return;
        case CV_AMD64_XMM6H:  *out = "xmm6h"; return;
        case CV_AMD64_XMM7H:  *out = "xmm7h"; return;

        case CV_AMD64_MXCSR:  *out = "mxcsr"; return; // XMM status register

        case CV_AMD64_EMM0L:  *out = "emm0l"; return; // XMM sub-registers (WNI integer)
        case CV_AMD64_EMM1L:  *out = "emm1l"; return;
        case CV_AMD64_EMM2L:  *out = "emm2l"; return;
        case CV_AMD64_EMM3L:  *out = "emm3l"; return;
        case CV_AMD64_EMM4L:  *out = "emm4l"; return;
        case CV_AMD64_EMM5L:  *out = "emm5l"; return;
        case CV_AMD64_EMM6L:  *out = "emm6l"; return;
        case CV_AMD64_EMM7L:  *out = "emm7l"; return;

        case CV_AMD64_EMM0H:  *out = "emm0h"; return;
        case CV_AMD64_EMM1H:  *out = "emm1h"; return;
        case CV_AMD64_EMM2H:  *out = "emm2h"; return;
        case CV_AMD64_EMM3H:  *out = "emm3h"; return;
        case CV_AMD64_EMM4H:  *out = "emm4h"; return;
        case CV_AMD64_EMM5H:  *out = "emm5h"; return;
        case CV_AMD64_EMM6H:  *out = "emm6h"; return;
        case CV_AMD64_EMM7H:  *out = "emm7h"; return;

        // do not change the order of these regs, first one must be even too
        case CV_AMD64_MM00:   *out = "mm00"; return;
        case CV_AMD64_MM01:   *out = "mm01"; return;
        case CV_AMD64_MM10:   *out = "mm10"; return;
        case CV_AMD64_MM11:   *out = "mm11"; return;
        case CV_AMD64_MM20:   *out = "mm20"; return;
        case CV_AMD64_MM21:   *out = "mm21"; return;
        case CV_AMD64_MM30:   *out = "mm30"; return;
        case CV_AMD64_MM31:   *out = "mm31"; return;
        case CV_AMD64_MM40:   *out = "mm40"; return;
        case CV_AMD64_MM41:   *out = "mm41"; return;
        case CV_AMD64_MM50:   *out = "mm50"; return;
        case CV_AMD64_MM51:   *out = "mm51"; return;
        case CV_AMD64_MM60:   *out = "mm60"; return;
        case CV_AMD64_MM61:   *out = "mm61"; return;
        case CV_AMD64_MM70:   *out = "mm70"; return;
        case CV_AMD64_MM71:   *out = "mm71"; return;

        // Extended KATMAI registers
        case CV_AMD64_XMM8:   *out = "xmm8"; return;// KATMAI registers
        case CV_AMD64_XMM9:   *out = "xmm9"; return;
        case CV_AMD64_XMM10:  *out = "xmm10"; return;
        case CV_AMD64_XMM11:  *out = "xmm11"; return;
        case CV_AMD64_XMM12:  *out = "xmm12"; return;
        case CV_AMD64_XMM13:  *out = "xmm13"; return;
        case CV_AMD64_XMM14:  *out = "xmm14"; return;
        case CV_AMD64_XMM15:  *out = "xmm15"; return;

        case CV_AMD64_XMM8_0: *out = "xmm8_0"; return;  // KATMAI sub-registers
        case CV_AMD64_XMM8_1: *out = "xmm8_1"; return;
        case CV_AMD64_XMM8_2: *out = "xmm8_2"; return;
        case CV_AMD64_XMM8_3: *out = "xmm8_3"; return;
        case CV_AMD64_XMM9_0: *out = "xmm9_0"; return;
        case CV_AMD64_XMM9_1: *out = "xmm9_1"; return;
        case CV_AMD64_XMM9_2: *out = "xmm9_2"; return;
        case CV_AMD64_XMM9_3: *out = "xmm9_3"; return;
        case CV_AMD64_XMM10_0:*out = "xmm10_0"; return;
        case CV_AMD64_XMM10_1:*out = "xmm10_1"; return;
        case CV_AMD64_XMM10_2:*out = "xmm10_2"; return;
        case CV_AMD64_XMM10_3:*out = "xmm10_3"; return;
        case CV_AMD64_XMM11_0:*out = "xmm11_0"; return;
        case CV_AMD64_XMM11_1:*out = "xmm11_1"; return;
        case CV_AMD64_XMM11_2:*out = "xmm11_2"; return;
        case CV_AMD64_XMM11_3:*out = "xmm11_3"; return;
        case CV_AMD64_XMM12_0:*out = "xmm12_0"; return;
        case CV_AMD64_XMM12_1:*out = "xmm12_1"; return;
        case CV_AMD64_XMM12_2:*out = "xmm12_2"; return;
        case CV_AMD64_XMM12_3:*out = "xmm12_3"; return;
        case CV_AMD64_XMM13_0:*out = "xmm13_0"; return;
        case CV_AMD64_XMM13_1:*out = "xmm13_1"; return;
        case CV_AMD64_XMM13_2:*out = "xmm13_2"; return;
        case CV_AMD64_XMM13_3:*out = "xmm13_3"; return;
        case CV_AMD64_XMM14_0:*out = "xmm14_0"; return;
        case CV_AMD64_XMM14_1:*out = "xmm14_1"; return;
        case CV_AMD64_XMM14_2:*out = "xmm14_2"; return;
        case CV_AMD64_XMM14_3:*out = "xmm14_3"; return;
        case CV_AMD64_XMM15_0:*out = "xmm15_0"; return;
        case CV_AMD64_XMM15_1:*out = "xmm15_1"; return;
        case CV_AMD64_XMM15_2:*out = "xmm15_2"; return;
        case CV_AMD64_XMM15_3:*out = "xmm15_3"; return;

        case CV_AMD64_XMM8L:  *out = "xmm8l"; return;
        case CV_AMD64_XMM9L:  *out = "xmm9l"; return;
        case CV_AMD64_XMM10L: *out = "xmm10l"; return;
        case CV_AMD64_XMM11L: *out = "xmm11l"; return;
        case CV_AMD64_XMM12L: *out = "xmm12l"; return;
        case CV_AMD64_XMM13L: *out = "xmm13l"; return;
        case CV_AMD64_XMM14L: *out = "xmm14l"; return;
        case CV_AMD64_XMM15L: *out = "xmm15l"; return;

        case CV_AMD64_XMM8H:  *out = "xmm8h"; return;
        case CV_AMD64_XMM9H:  *out = "xmm9h"; return;
        case CV_AMD64_XMM10H: *out = "xmm10h"; return;
        case CV_AMD64_XMM11H: *out = "xmm11h"; return;
        case CV_AMD64_XMM12H: *out = "xmm12h"; return;
        case CV_AMD64_XMM13H: *out = "xmm13h"; return;
        case CV_AMD64_XMM14H: *out = "xmm14h"; return;
        case CV_AMD64_XMM15H: *out = "xmm15h"; return;

        case CV_AMD64_EMM8L:  *out = "emm8l"; return; // XMM sub-registers (WNI integer)
        case CV_AMD64_EMM9L:  *out = "emm9l"; return;
        case CV_AMD64_EMM10L: *out = "emm10l"; return;
        case CV_AMD64_EMM11L: *out = "emm11l"; return;
        case CV_AMD64_EMM12L: *out = "emm12l"; return;
        case CV_AMD64_EMM13L: *out = "emm13l"; return;
        case CV_AMD64_EMM14L: *out = "emm14l"; return;
        case CV_AMD64_EMM15L: *out = "emm15l"; return;

        case CV_AMD64_EMM8H:  *out = "emm8h"; return;
        case CV_AMD64_EMM9H:  *out = "emm9h"; return;
        case CV_AMD64_EMM10H: *out = "emm10h"; return;
        case CV_AMD64_EMM11H: *out = "emm11h"; return;
        case CV_AMD64_EMM12H: *out = "emm12h"; return;
        case CV_AMD64_EMM13H: *out = "emm13h"; return;
        case CV_AMD64_EMM14H: *out = "emm14h"; return;
        case CV_AMD64_EMM15H: *out = "emm15h"; return;

        // Low byte forms of some standard registers
        case CV_AMD64_SIL:    *out = "sil"; return;
        case CV_AMD64_DIL:    *out = "dil"; return;
        case CV_AMD64_BPL:    *out = "bpl"; return;
        case CV_AMD64_SPL:    *out = "spl"; return;

        // 64-bit regular registers
        case CV_AMD64_RAX:    *out = "rax"; return;
        case CV_AMD64_RBX:    *out = "rbx"; return;
        case CV_AMD64_RCX:    *out = "rcx"; return;
        case CV_AMD64_RDX:    *out = "rdx"; return;
        case CV_AMD64_RSI:    *out = "rsi"; return;
        case CV_AMD64_RDI:    *out = "rdi"; return;
        case CV_AMD64_RBP:    *out = "rbp"; return;
        case CV_AMD64_RSP:    *out = "rsp"; return;

        // 64-bit integer registers with 8-, 16-, and 32-bit forms (B, W, and D)
        case CV_AMD64_R8:     *out = "r8"; return;
        case CV_AMD64_R9:     *out = "r9"; return;
        case CV_AMD64_R10:    *out = "r10"; return;
        case CV_AMD64_R11:    *out = "r11"; return;
        case CV_AMD64_R12:    *out = "r12"; return;
        case CV_AMD64_R13:    *out = "r13"; return;
        case CV_AMD64_R14:    *out = "r14"; return;
        case CV_AMD64_R15:    *out = "r15"; return;

        case CV_AMD64_R8B:    *out = "r8b"; return;
        case CV_AMD64_R9B:    *out = "r9b"; return;
        case CV_AMD64_R10B:   *out = "r10b"; return;
        case CV_AMD64_R11B:   *out = "r11b"; return;
        case CV_AMD64_R12B:   *out = "r12b"; return;
        case CV_AMD64_R13B:   *out = "r13b"; return;
        case CV_AMD64_R14B:   *out = "r14b"; return;
        case CV_AMD64_R15B:   *out = "r15b"; return;

        case CV_AMD64_R8W:    *out = "r8w"; return;
        case CV_AMD64_R9W:    *out = "r9w"; return;
        case CV_AMD64_R10W:   *out = "r10w"; return;
        case CV_AMD64_R11W:   *out = "r11w"; return;
        case CV_AMD64_R12W:   *out = "r12w"; return;
        case CV_AMD64_R13W:   *out = "r13w"; return;
        case CV_AMD64_R14W:   *out = "r14w"; return;
        case CV_AMD64_R15W:   *out = "r15w"; return;

        case CV_AMD64_R8D:    *out = "r8d"; return;
        case CV_AMD64_R9D:    *out = "r9d"; return;
        case CV_AMD64_R10D:   *out = "r10d"; return;
        case CV_AMD64_R11D:   *out = "r11d"; return;
        case CV_AMD64_R12D:   *out = "r12d"; return;
        case CV_AMD64_R13D:   *out = "r13d"; return;
        case CV_AMD64_R14D:   *out = "r14d"; return;
        case CV_AMD64_R15D:   *out = "r15d"; return;
      }
      break;

    case CV_CFL_ARM64:
      //
      // ARM64 registers
      //
      switch ( reg )
      {
        case CV_ARM_NOREG:  *out = "noreg"; return;
        case CV_ARM64_W0:   *out = "w0";    return;
        case CV_ARM64_W1:   *out = "w1";    return;
        case CV_ARM64_W2:   *out = "w2";    return;
        case CV_ARM64_W3:   *out = "w3";    return;
        case CV_ARM64_W4:   *out = "w4";    return;
        case CV_ARM64_W5:   *out = "w5";    return;
        case CV_ARM64_W6:   *out = "w6";    return;
        case CV_ARM64_W7:   *out = "w7";    return;
        case CV_ARM64_W8:   *out = "w8";    return;
        case CV_ARM64_W9:   *out = "w9";    return;
        case CV_ARM64_W10:  *out = "w10";   return;
        case CV_ARM64_W11:  *out = "w11";   return;
        case CV_ARM64_W12:  *out = "w12";   return;
        case CV_ARM64_W13:  *out = "w13";   return;
        case CV_ARM64_W14:  *out = "w14";   return;
        case CV_ARM64_W15:  *out = "w15";   return;
        case CV_ARM64_W16:  *out = "w16";   return;
        case CV_ARM64_W17:  *out = "w17";   return;
        case CV_ARM64_W18:  *out = "w18";   return;
        case CV_ARM64_W19:  *out = "w19";   return;
        case CV_ARM64_W20:  *out = "w20";   return;
        case CV_ARM64_W21:  *out = "w21";   return;
        case CV_ARM64_W22:  *out = "w22";   return;
        case CV_ARM64_W23:  *out = "w23";   return;
        case CV_ARM64_W24:  *out = "w24";   return;
        case CV_ARM64_W25:  *out = "w25";   return;
        case CV_ARM64_W26:  *out = "w26";   return;
        case CV_ARM64_W27:  *out = "w27";   return;
        case CV_ARM64_W28:  *out = "w28";   return;
        case CV_ARM64_W29:  *out = "w29";   return;
        case CV_ARM64_WZR:  *out = "wzr";   return;

        // 64-bit integer registers
        case CV_ARM64_X0:   *out = "x0";    return;
        case CV_ARM64_X1:   *out = "x1";    return;
        case CV_ARM64_X2:   *out = "x2";    return;
        case CV_ARM64_X3:   *out = "x3";    return;
        case CV_ARM64_X4:   *out = "x4";    return;
        case CV_ARM64_X5:   *out = "x5";    return;
        case CV_ARM64_X6:   *out = "x6";    return;
        case CV_ARM64_X7:   *out = "x7";    return;
        case CV_ARM64_X8:   *out = "x8";    return;
        case CV_ARM64_X9:   *out = "x9";    return;
        case CV_ARM64_X10:  *out = "x10";   return;
        case CV_ARM64_X11:  *out = "x11";   return;
        case CV_ARM64_X12:  *out = "x12";   return;
        case CV_ARM64_X13:  *out = "x13";   return;
        case CV_ARM64_X14:  *out = "x14";   return;
        case CV_ARM64_X15:  *out = "x15";   return;
        case CV_ARM64_IP0:  *out = "x16";   return;
        case CV_ARM64_IP1:  *out = "x17";   return;
        case CV_ARM64_X18:  *out = "x18";   return;
        case CV_ARM64_X19:  *out = "x19";   return;
        case CV_ARM64_X20:  *out = "x20";   return;
        case CV_ARM64_X21:  *out = "x21";   return;
        case CV_ARM64_X22:  *out = "x22";   return;
        case CV_ARM64_X23:  *out = "x23";   return;
        case CV_ARM64_X24:  *out = "x24";   return;
        case CV_ARM64_X25:  *out = "x25";   return;
        case CV_ARM64_X26:  *out = "x26";   return;
        case CV_ARM64_X27:  *out = "x27";   return;
        case CV_ARM64_X28:  *out = "x28";   return;
        case CV_ARM64_FP:   *out = "fp";    return; // x29
        case CV_ARM64_LR:   *out = "lr";    return; // x30
        case CV_ARM64_SP:   *out = "sp";    return;
        case CV_ARM64_ZR:   *out = "xzr";   return;

        // 32-bit floating point registers
        case CV_ARM64_S0:   *out = "s0";   return;
        case CV_ARM64_S1:   *out = "s1";   return;
        case CV_ARM64_S2:   *out = "s2";   return;
        case CV_ARM64_S3:   *out = "s3";   return;
        case CV_ARM64_S4:   *out = "s4";   return;
        case CV_ARM64_S5:   *out = "s5";   return;
        case CV_ARM64_S6:   *out = "s6";   return;
        case CV_ARM64_S7:   *out = "s7";   return;
        case CV_ARM64_S8:   *out = "s8";   return;
        case CV_ARM64_S9:   *out = "s9";   return;
        case CV_ARM64_S10:  *out = "s10";  return;
        case CV_ARM64_S11:  *out = "s11";  return;
        case CV_ARM64_S12:  *out = "s12";  return;
        case CV_ARM64_S13:  *out = "s13";  return;
        case CV_ARM64_S14:  *out = "s14";  return;
        case CV_ARM64_S15:  *out = "s15";  return;
        case CV_ARM64_S16:  *out = "s16";  return;
        case CV_ARM64_S17:  *out = "s17";  return;
        case CV_ARM64_S18:  *out = "s18";  return;
        case CV_ARM64_S19:  *out = "s19";  return;
        case CV_ARM64_S20:  *out = "s20";  return;
        case CV_ARM64_S21:  *out = "s21";  return;
        case CV_ARM64_S22:  *out = "s22";  return;
        case CV_ARM64_S23:  *out = "s23";  return;
        case CV_ARM64_S24:  *out = "s24";  return;
        case CV_ARM64_S25:  *out = "s25";  return;
        case CV_ARM64_S26:  *out = "s26";  return;
        case CV_ARM64_S27:  *out = "s27";  return;
        case CV_ARM64_S28:  *out = "s28";  return;
        case CV_ARM64_S29:  *out = "s29";  return;
        case CV_ARM64_S30:  *out = "s30";  return;
        case CV_ARM64_S31:  *out = "s31";  return;

        // 64-bit floating point registers
        case CV_ARM64_D0:   *out = "d0";   return;
        case CV_ARM64_D1:   *out = "d1";   return;
        case CV_ARM64_D2:   *out = "d2";   return;
        case CV_ARM64_D3:   *out = "d3";   return;
        case CV_ARM64_D4:   *out = "d4";   return;
        case CV_ARM64_D5:   *out = "d5";   return;
        case CV_ARM64_D6:   *out = "d6";   return;
        case CV_ARM64_D7:   *out = "d7";   return;
        case CV_ARM64_D8:   *out = "d8";   return;
        case CV_ARM64_D9:   *out = "d9";   return;
        case CV_ARM64_D10:  *out = "d10";  return;
        case CV_ARM64_D11:  *out = "d11";  return;
        case CV_ARM64_D12:  *out = "d12";  return;
        case CV_ARM64_D13:  *out = "d13";  return;
        case CV_ARM64_D14:  *out = "d14";  return;
        case CV_ARM64_D15:  *out = "d15";  return;
        case CV_ARM64_D16:  *out = "d16";  return;
        case CV_ARM64_D17:  *out = "d17";  return;
        case CV_ARM64_D18:  *out = "d18";  return;
        case CV_ARM64_D19:  *out = "d19";  return;
        case CV_ARM64_D20:  *out = "d20";  return;
        case CV_ARM64_D21:  *out = "d21";  return;
        case CV_ARM64_D22:  *out = "d22";  return;
        case CV_ARM64_D23:  *out = "d23";  return;
        case CV_ARM64_D24:  *out = "d24";  return;
        case CV_ARM64_D25:  *out = "d25";  return;
        case CV_ARM64_D26:  *out = "d26";  return;
        case CV_ARM64_D27:  *out = "d27";  return;
        case CV_ARM64_D28:  *out = "d28";  return;
        case CV_ARM64_D29:  *out = "d29";  return;
        case CV_ARM64_D30:  *out = "d30";  return;
        case CV_ARM64_D31:  *out = "d31";  return;

        // 128-bit SIMD registers
        case CV_ARM64_Q0:   *out = "q0";   return;
        case CV_ARM64_Q1:   *out = "q1";   return;
        case CV_ARM64_Q2:   *out = "q2";   return;
        case CV_ARM64_Q3:   *out = "q3";   return;
        case CV_ARM64_Q4:   *out = "q4";   return;
        case CV_ARM64_Q5:   *out = "q5";   return;
        case CV_ARM64_Q6:   *out = "q6";   return;
        case CV_ARM64_Q7:   *out = "q7";   return;
        case CV_ARM64_Q8:   *out = "q8";   return;
        case CV_ARM64_Q9:   *out = "q9";   return;
        case CV_ARM64_Q10:  *out = "q10";  return;
        case CV_ARM64_Q11:  *out = "q11";  return;
        case CV_ARM64_Q12:  *out = "q12";  return;
        case CV_ARM64_Q13:  *out = "q13";  return;
        case CV_ARM64_Q14:  *out = "q14";  return;
        case CV_ARM64_Q15:  *out = "q15";  return;
        case CV_ARM64_Q16:  *out = "q16";  return;
        case CV_ARM64_Q17:  *out = "q17";  return;
        case CV_ARM64_Q18:  *out = "q18";  return;
        case CV_ARM64_Q19:  *out = "q19";  return;
        case CV_ARM64_Q20:  *out = "q20";  return;
        case CV_ARM64_Q21:  *out = "q21";  return;
        case CV_ARM64_Q22:  *out = "q22";  return;
        case CV_ARM64_Q23:  *out = "q23";  return;
        case CV_ARM64_Q24:  *out = "q24";  return;
        case CV_ARM64_Q25:  *out = "q25";  return;
        case CV_ARM64_Q26:  *out = "q26";  return;
        case CV_ARM64_Q27:  *out = "q27";  return;
        case CV_ARM64_Q28:  *out = "q28";  return;
        case CV_ARM64_Q29:  *out = "q29";  return;
        case CV_ARM64_Q30:  *out = "q30";  return;
        case CV_ARM64_Q31:  *out = "q31";  return;
      }
      break;

    default:
      break;
  }
  out->sprnt("reg %d", reg);
}
