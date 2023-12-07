import collections
import json
#
import tlsh
#
import idaapi
import idautils
#
from idaclu import ida_shims


SCRIPT_NAME = 'TLSH Similarity'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_items(func_ea):
    for item in idautils.FuncItems(func_ea):
        if ida_shims.is_code(ida_shims.get_full_flags(item)):
            yield item

def get_dasm_list(func_ea):
    func_instructs = []
    for item in get_items(func_ea):
        dasm = ida_shims.generate_disasm_line(item, idaapi.GENDSM_FORCE_CODE)
        dasm_clean = dasm.split(';')[0]  # remove comments
        func_instructs.append(dasm_clean)
    return func_instructs

def get_mnem_list(func_ea):
    func_mnemonics = []
    for item in get_items(func_ea):
        mnem = ida_shims.print_insn_mnem(item)
        func_mnemonics.append(mnem)
    return func_mnemonics

def get_psdo_list(func_ea):
    func_pseudocode = []
    decomp_str = ""
    try:
        decomp_str = idaapi.decompile(func_ea)
    except idaapi.DecompilationFailure:
        return []
    for line in str(decomp_str).split('\n'):
        if '//' in line:
            code = line.split('//')[0]
            if code != '':
                func_pseudocode.append(code.lstrip())
        else:
            if line != '':
                func_pseudocode.append(line.lstrip())
    return func_pseudocode

def get_psdo_body(func_ea):
    psdo_list = get_psdo_list(func_ea)
    return psdo_list[2:-1]

def get_func_bytes(func_addr):
    func_bytes = b''
    for beg, end in idautils.Chunks(func_addr):
        fb = ida_shims.get_bytes(beg, end-beg)
        func_bytes += fb
    return func_bytes

def get_number_ratio(num1, num2):
    if num1 == num2:
        return 1
    if num1 > num2:
        return num2 / num1
    if num1 < num2:
        return num1 / num2

def get_func_descriptors(func_gen):
    func_dscs = []
    for func_addr in func_gen():
        func_name = ida_shims.get_func_name(func_addr)
        func_desc = idaapi.get_func(func_addr)

        func_inst = get_dasm_list(func_addr)
        func_mnem = get_mnem_list(func_addr)
        func_psdo = get_psdo_list(func_addr)
        func_size = ida_shims.calc_func_size(func_desc)

        func_byts_line = get_func_bytes(func_addr)    # get_bytes(func_addr, func_size)
        func_mnem_line = "@".join(func_mnem).encode('utf-8', errors='replace')
        func_inst_line = "@".join(func_inst).encode('utf-8', errors='replace')
        func_psdo_line = "@".join(func_psdo).encode('utf-8', errors='replace')

        func_byts_size = len(func_byts_line)
        func_mnem_size = len(func_mnem_line)
        func_inst_size = len(func_inst_line)
        func_psdo_size = len(func_psdo_line)

        tlsh_byts = tlsh.hash(func_byts_line)
        tlsh_mnem = tlsh.hash(func_mnem_line)
        tlsh_inst = tlsh.hash(func_inst_line)
        tlsh_psdo = tlsh.hash(func_psdo_line)

        func_dscs.append({
            # general
            'func_addr': func_addr,
            'func_name': func_name,
            # tlsh
            'byts_hash': tlsh_byts,
            'mnem_hash': tlsh_mnem,
            'inst_hash': tlsh_inst,
            'psdo_hash': tlsh_psdo,
            # sizes
            'byts_size': func_byts_size,
            'mnem_size': func_mnem_size,
            'inst_size': func_inst_size,
            'psdo_size': func_psdo_size
        })

    return func_dscs

def get_func_clusters(func_descriptors):
    clusters = collections.defaultdict(list)
    data_type = [('byts', 100), ('mnem', 60), ('inst', 60), ('psdo', 60)]
    for idx, sup in enumerate(func_descriptors):
        for jdx, sub in enumerate(func_descriptors):
            if sup['func_addr'] != sub['func_addr']:

                byts_score = None

                for (dt, th) in data_type:
                    size_key = '{}_size'.format(dt)
                    hash_key = '{}_hash'.format(dt)
                    if sup[hash_key] != "TNULL" and sub[hash_key] != "TNULL": 
                        score = tlsh.diff(sup[hash_key], sub[hash_key])
                        # pairs only
                        if score and score <= th:
                            clusters[dt].append({
                                'score': score, 
                                'func_1': sup['func_addr'], 
                                'func_2': sub['func_addr']}
                            )

                            cluster_id = -1  # there is no recipient cluster for a given pair
                            for i, clu in enumerate(clusters['aggregated']):  # enumerating already existing clusters
                                if sup['func_addr'] in clu or sub['func_addr'] in clu:
                                    cluster_id = i

                            if cluster_id != -1:  # was found, but need more details
                                if sup['func_addr'] not in clusters['aggregated'][cluster_id]:
                                    clusters['aggregated'][cluster_id].append(sup['func_addr'])
                                elif sub['func_addr'] not in clusters['aggregated'][cluster_id]:
                                    clusters['aggregated'][cluster_id].append(sub['func_addr'])
                                else:
                                    pass
                            else:  # nothing similar was found
                                clusters['aggregated'].append([sup['func_addr'], sub['func_addr']])
    return clusters

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    func_descriptors = get_func_descriptors(func_gen)
    func_clusters = get_func_clusters(func_descriptors)


    for idx, clu in enumerate(func_clusters['aggregated']):
        for addr in clu:
            key_name = "cluster: {}".format(idx)
            report['data'][key_name].append(addr)
            report['stat'][key_name] += 1


    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
