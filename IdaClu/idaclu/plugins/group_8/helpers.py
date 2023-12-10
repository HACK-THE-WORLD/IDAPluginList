import collections
import math
#
import idc
import idaapi
import idautils
#
from idaclu import ida_shims
#
from ngrams import determine_ngram_database

ARITHMETIC_OPERATION = set([
    idaapi.cot_add,   # x + y
    idaapi.cot_lnot,  # !x
    idaapi.cot_sub,   # x - y
    idaapi.cot_mul,   # x * y
    idaapi.cot_fmul,  # x * y fp
    idaapi.cot_sdiv,  # x / y signed
    idaapi.cot_udiv,  # x / y unsigned
    idaapi.cot_fdiv,  # x / y fp
    idaapi.cot_smod,  # x % y signed
    idaapi.cot_umod   # x % y unsigned
])

ARITHMETIC_OPERATION_ASG = set([
    idaapi.cot_asgadd,   # x += y
    idaapi.cot_asgsub,   # x -= y
    idaapi.cot_asgmul,   # x *= y
    idaapi.cot_asgsdiv,  # x /= y signed
    idaapi.cot_asgudiv,  # x /= y unsigned
    idaapi.cot_asgsmod,  # x %= y signed
    idaapi.cot_asgumod   # x %= y unsigned
])

BOOLEAN_OPERATION = set([
    idaapi.cot_bnot,  # ~x
    idaapi.cot_band,  # x & y
    idaapi.cot_bor,   # x | y
    idaapi.cot_xor,   # x ^ y
    idaapi.cot_sshr,  # x >> y signed
    idaapi.cot_ushr,  # x >> y unsigned
    idaapi.cot_shl,   # x << y
])

BOOLEAN_OPERATION_ASG = set([
    idaapi.cot_asgbor,   # x |= y
    idaapi.cot_asgxor,   # x ^= y
    idaapi.cot_asgband,  # x &= y
    idaapi.cot_asgsshr,  # x >>= y signed
    idaapi.cot_asgushr,  # x >>= y unsigned
    idaapi.cot_asgshl,   # x <<= y
])


def calc_flattening_score(function):
    score = 0.0
    # 0: get the basic blocks of the function
    basic_blocks = idaapi.FlowChart(idaapi.get_func(function))
    # 1: walk over all basic blocks
    for block in basic_blocks:
        # 2: get all blocks that are dominated by the current block
        dominated = get_dominated_by(block)
        # 3: check for a back edge
        dominators = [d.start_ea for d in block.preds()]
        if not any((dominator in dominated for dominator in dominators)):
            continue
        # 4: calculate relation of dominated blocks to the blocks in the graph
        score = max(score, len(dominated) / basic_blocks.size)
    return score

def get_dominated_by(dominator):
    worked_on_eas = set()
    # 1: initialize worklist
    worklist = [dominator]
    # 2: perform a depth-first search on the dominator tree
    while worklist:
        # get next block
        block = worklist.pop(0)
        worked_on_eas.add(block.start_ea)
        for child in block.succs():
            if child.start_ea not in worked_on_eas:
                worked_on_eas.add(child.start_ea)
                worklist.append(child)
    return worked_on_eas

def calculate_entropy(data):
    # count byte occurrences and calculate total bytes
    byte_count = collections.Counter(data)
    total_bytes = len(data)

    # calculate entropy using the counted byte occurrences
    entropy = 0.0
    for count in byte_count.values():
        # calculate byte probability and update entropy
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy

def get_top_10_functions(functions, scoring_function):
    # sort functions by scoring function
    sorted_functions = sorted(((f, scoring_function(f))
                               for f in functions), key=lambda x: x[1])
    # bound to locate the top 10%, but 10 minimum, 1k maximum
    bound = max(min(math.ceil(((len(functions) * 10) / 100)), 1000), 10)
    # yield top 10% (iterate in descending order)
    for function, score in list(reversed(sorted_functions))[:bound]:
        yield function, score

def sort_elements(iterator, scoring_function):
    # sort elements by scoring function
    sorted_elements = sorted(((elem, scoring_function(elem))
                              for elem in iterator), key=lambda x: x[1])
    # yield in descending order
    for element, score in list(reversed(sorted_elements)):
        yield element, score
    
def calc_cyclomatic_complexity(func_addr):
    # number of basic blocks
    child = set([])
    
    num_blocks = 0
    num_edges = 0
    basic_blocks = idaapi.FlowChart(idaapi.get_func(func_addr), flags=(idaapi.FC_PREDS | idaapi.FC_NOEXT))
    for block in basic_blocks:
        for succ_block in block.succs():
            child.add(succ_block.id)     
        for pred_block in block.preds():
            child.add(pred_block.id)
    for block in basic_blocks:
        if block.id in child or block.id == 0:
            num_blocks += 1
            num_edges += len([b for b in block.succs()])
            # number of edges in the graph
    return num_edges - num_blocks + 2

def calc_average_instructions_per_block(function):
    # number of basic blocks -- set to 1 if 0
    basic_blocks = idaapi.FlowChart(idaapi.get_func(function))
    num_blocks = max(1, basic_blocks.size)
    # number of instructions
    num_instructions = sum(
        (len([i for i in idautils.Heads(b.start_ea, b.end_ea)]) for b in basic_blocks))
    return num_instructions / num_blocks

def block_is_in_loop(block):
    # 0: get the blocks dominated by this block
    dominated = get_dominated_by(block)
    # 1: get the predecessors of this block
    dominators = [d.start_ea for d in block.preds()]
    # 2: check if any predecessor is also dominated by this block
    return any((p in dominated for p in dominators))

def computes_xor_const(insn):
    # check for a xor operation
    if insn.get_canon_mnem() == 'xor':
        # check if one operand is a constant
        ops = [op for op in insn.ops]
        if ops[1].type == idaapi.o_imm or ops[0].type == idaapi.o_imm:
            return True
    return False

def contains_xor_decryption_loop(function):
    # walk over all blocks which are part of a loop
    basic_blocks = idaapi.FlowChart(idaapi.get_func(function))
    for block in basic_blocks:
        if not block_is_in_loop(block):
            continue
        # walk over all instructions
        addr = block.start_ea
        while addr < block.end_ea:
            # get instruction
            insn = idaapi.insn_t()
            insn_len = idaapi.decode_insn(insn, addr)
            # check if it performs an xor with a constant
            if computes_xor_const(insn):
                return True
            # compute next address
            addr += insn_len
    return False

def sliding_window(l, window_size):
    # yields all sliding windows of size `window_size` for a given list
    for index in range(len(l) - window_size + 1):
        yield l[index:index + window_size]

def calc_ngrams(function, n):
    fn = idaapi.get_func(function)
    hi = [h for h in fn.head_items()]
    mnemonics_sorted = [idc.print_insn_mnem(ea) for ea in hi]

    # calculate all n-grams
    grams_n = collections.Counter(["".join(w) for w in sliding_window(mnemonics_sorted, n)])
    return grams_n

def calc_uncommon_instruction_sequences_score(function):
    # determine ngram database based on function's architecture
    bitness = idaapi.get_func_bitness(function)
    if bitness == 1:
        arch = "x86"
    elif bitness == 2:
        arch = "x86_64"
    else:
        arch = None
    use_llil, ngram_database = determine_ngram_database(arch)
    # calculate all 3-grams in the function
    function_ngrams = calc_ngrams(function, 3)
    # heuristic to avoid overfitting to small function stubs
    if sum(function_ngrams.values()) < 5:
        return 0.0
    # count the number of ngrams in the function which are not in MOST_COMMON_3GRAMS
    count = sum((value for gram, value in function_ngrams.items()
                 if gram not in ngram_database))
    # average relative to the amount of ngrams in the functions
    score = count / sum(function_ngrams.values())
    return score

def get_basic_blocks(func_addr, is_attached):
    'identfies basic blocks that do not have an entry point and are not the entry point of a function' 
    child = set([])

    # ignore external blocks referenced by the function!
    basic_blocks = idaapi.FlowChart(idaapi.get_func(func_addr), flags=(idaapi.FC_PREDS | idaapi.FC_NOEXT))  
    for block in basic_blocks:
        for succ_block in block.succs():
            child.add(succ_block.id)     
        for pred_block in block.preds():
            child.add(pred_block.id)
    for block in basic_blocks:
        if is_attached == False and block.id not in child and block.id != 0:
            yield block
        if is_attached == True and block.id in child or block.id == 0:
            yield block
            
def calc_cyclomatic_complexity(func_addr):
    num_blocks = 0
    num_edges = 0
    for bb in get_basic_blocks(func_addr, True):
        num_blocks += 1
        num_edges += len([b for b in bb.succs()])
        # number of edges in the graph
    return num_edges - num_blocks + 2

def get_orph_eas(func_addr):
    for bb in get_basic_blocks(func_addr, False):
        yield (bb.start_ea, bb.end_ea)

def get_orph_count(func_addr):
    orph_num = len(list(get_orph_eas(func_addr)))
    return orph_num

# ex- uses_mixed_boolean_arithmetic()
class MbaVisitor(idaapi.ctree_visitor_t):
    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
        self.mba_eas = set([])
    def list_parents(self, op_found):
        for parent in self.parents:
            if (parent is not None):
                if op_found == 'b':
                    if (parent.op in ARITHMETIC_OPERATION or
                        parent.op in ARITHMETIC_OPERATION_ASG):
                        self.mba_eas.add(parent.ea)
                if op_found == 'a':
                    if (parent.op in BOOLEAN_OPERATION or
                        parent.op in BOOLEAN_OPERATION_ASG):
                        self.mba_eas.add(parent.ea)
    def visit_expr(self, e):
        if e.op in BOOLEAN_OPERATION:
            self.list_parents('b')
        elif e.op in ARITHMETIC_OPERATION:
            self.list_parents('a')
        return 0

def calculate_complex_arithmetic_expressions(function):  
    instr_mba = 0
    cfunc = idaapi.decompile(function)
    if cfunc:
        mba_visitor = MbaVisitor()
        mba_visitor.apply_to(cfunc.body, None)
        # if an expression has a boolean and an arithmetic operation, the expression has some arithmetic complexity
        if len(mba_visitor.mba_eas):
            instr_mba = len(mba_visitor.mba_eas)
    return instr_mba
