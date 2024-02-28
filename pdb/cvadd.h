//
// Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
// ALL RIGHTS RESERVED.
//
// Utilities to extend cvconst.h and cvinfo.h
//
#pragma once

//----------------------------------------------------------------------------
inline bool is_intel386(uint32_t machine_type)
{
  return machine_type == CV_CFL_80386
      || machine_type == CV_CFL_80486
      || machine_type == CV_CFL_PENTIUM
      || machine_type == CV_CFL_PENTIUMII
      || machine_type == CV_CFL_PENTIUMIII;
}

//----------------------------------------------------------------------------
inline bool is_intel64(uint32_t machine_type)
{
  return machine_type == CV_CFL_X64;
}

//----------------------------------------------------------------------------
inline bool is_arm(uint32_t machine_type)
{
  return machine_type == CV_CFL_ARM3
      || machine_type == CV_CFL_ARM4
      || machine_type == CV_CFL_ARM4T
      || machine_type == CV_CFL_ARM5
      || machine_type == CV_CFL_ARM5T
      || machine_type == CV_CFL_ARM6
      || machine_type == CV_CFL_ARM7
      || machine_type == CV_CFL_ARMNT
      || machine_type == CV_CFL_ARM_XMAC
      || machine_type == CV_CFL_ARM_WMMX
      || machine_type == CV_CFL_THUMB;
}

//----------------------------------------------------------------------------
inline int get_stack_reg(uint32_t machine_type)
{
  return is_intel386(machine_type) ? CV_REG_ESP
       : is_intel64(machine_type)  ? CV_AMD64_RSP
       : is_arm(machine_type)      ? CV_ARM_SP
       :                             CV_REG_NONE;
}

//----------------------------------------------------------------------------
inline int get_frame_reg(uint32_t machine_type)
{
  return is_intel386(machine_type) ? CV_REG_EBP
       : is_intel64(machine_type)  ? CV_AMD64_RBP
       : is_arm(machine_type)      ? CV_ARM_R11
       :                             CV_REG_NONE;
}
