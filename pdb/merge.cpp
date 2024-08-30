
/*
        Interactive disassembler (IDA).
        Copyright (c) 1990-2024 Hex-Rays SA <support@hex-rays.com>
        ALL RIGHTS RESERVED.

        Merge functionality.

*/

#include "pdb.hpp"
#include <mergemod.hpp>

//--------------------------------------------------------------------------
static const idbattr_info_t idpopts_info[] =
{
  IDI_ALTENTRY(PDB_DLLBASE_NODE_IDX, atag, sizeof(ea_t), 0, nullptr, "loading_result"),
};

SIMPLE_MODDATA_DIFF_HELPER(helper, "pdb", PDB_NODE_NAME, idpopts_info);

//--------------------------------------------------------------------------
void create_merge_handlers(merge_data_t &md)
{
  DEFINE_PLUGIN_MH_PARAMS("PDB", MH_TERSE);
  create_std_modmerge_handlers(mhp, data_id, helper);
}
