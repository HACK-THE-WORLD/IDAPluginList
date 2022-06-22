
// Common definitions for the old and new pdb plugins

// helper functions provided by the new pdb plugin
bool apply_name(ea_t ea, const qstring &name, int maybe_func);
void load_vc_til(void);

// entry point of the old pdb plugin
bool old_pdb_plugin(ea_t loaded_base, const char *input, const char *spath);
