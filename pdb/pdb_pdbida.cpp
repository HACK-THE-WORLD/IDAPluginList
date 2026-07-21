//
// This file provides stub implementations for PDBIDA-specific functions.
// In the private build, PDB_PDBIDA_DEFINED is set and a separate file
// provides the real implementations.
//

#ifndef PDB_PDBIDA_DEFINED

static bool get_pdb_path_override(pdbargs_t *, netnode) { return false; }

static bool skip_pdb_details_dialog(const pdbargs_t *) { return false; }

static bool try_pdbida_first(pdb_ctx_t &, pdbargs_t &, bool *, HRESULT *)
{
  return false;
}

static void pdbida_apply_end(const pdbida_state_t &, const char *) {}

static bool handle_coff_run(pdb_ctx_t &, size_t, bool *) { return false; }

static bool parse_pdbida_option(pdb_ctx_t &, const char *) { return false; }

static bool try_open_pdbida(pdb_modinfo_t &, pdbargs_t &, HRESULT *)
{
  return false;
}

static void pdb_add_test_feature() {}

#endif // PDB_PDBIDA_DEFINED
