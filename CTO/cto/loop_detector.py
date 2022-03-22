import ida_kernwin
import idautils
import ida_gdl
import ida_funcs

class loop_detector(object):
    def __init__(self, ea, quantity_limit=True, chunk_quantity=1000):
        self.ea = ea
        self.f = ida_gdl.FlowChart(ida_funcs.get_func(ea))
        self.chunk_quantity = chunk_quantity
        self.quantity_limit = quantity_limit
        self.finished = set([])
        self.recognized_loop = []

    def get_bb(self, ea):
        block = None
        for block in self.f:
            if block.start_ea <= ea and ea < block.end_ea:
                return block
        
    def find_loop_bbs(self, block, results, result=None, finished=None):
        if result is None:
            result = []
        if finished is None:
            finished = set([])
        if (block.start_ea, block.end_ea) in finished:
            return

        # find successor blocks recursively
        if (block.start_ea, block.end_ea) not in result:
            result.append((block.start_ea, block.end_ea))
            for sb in block.succs():
                self.find_loop_bbs(sb, results, result, finished)
            finished.add(result.pop())
        else:
            # found loop
            idx = result.index((block.start_ea, block.end_ea))
            results.append(result[idx:])

    def find_loop_bbs_by_ea(self, ea, suppress_repetition=True):
        block = self.get_bb(ea)
        results = []
        loops = []
        self.find_loop_bbs(block, loops)
        for l in loops:
            if (block.start_ea, block.end_ea) in l:
                if suppress_repetition and set(l) in self.recognized_loop:
                    pass
                else:
                    if suppress_repetition:
                        self.recognized_loop.append(set(l))
                    results.append(l)
        return results

    def find_loops(self):
        if not self.quantity_limit or self.f.size <= self.chunk_quantity:
            finished = set([])
            for curr_bb in self.f:
                #print "  currBB: %08x" % currBB.start_ea
                results = []
                self.find_loop_bbs(curr_bb, results)
                for loop in results:
                    flag2 = True
                    for f in finished:
                        flag = True
                        i = 0
                        for bb in loop:
                            if bb not in f:
                                flag = False
                                break
                            i += 1
                        if flag and len(f) == i:
                            flag2 = False
                            break
                    if flag2:
                        finished.add(tuple(loop))
                        yield loop

    def get_all_loops_in_func(self):
        for bb in self.f:
            loops_in_func = []
            for loop in self.find_loops():
                loops_in_func.append(loop)
            return loops_in_func

def print_loops(loops):
    i = 0
    for loop in loops:
        if len(loop) > 0:
            print("  found loop starting at %08x:" % loop[0][0])
            for lbb in loop:
                print("    bb_start_ea: %08x" % lbb[0])
            i += 1
    print("found %d loops!" % i)

"""
def recognized_loop(func_ea, chunk_quantity=1000, quantity_limit=True):
    ld = loop_detector(func_ea, quantity_limit, chunk_quantity)
    loops = ld.find_loops()
    print("func addr: %08x" % func_ea)
    print_loops(loops)
"""

def get_all_loops_in_all_funcs():
    for func_ea in idautils.Functions():
        ld = loop_detector(func_ea)
        loops = ld.get_all_loops_in_func()
        yield func_ea, loops

def main():
    for func_ea, loops in get_all_loops_in_all_funcs():
        print("----------------- %x -------------------" % func_ea)
        print_loops(loops)

"""
def main():
    ea = ida_kernwin.get_screen_ea()
    print("-----------------all loops in func -------------------")
    ld = loop_detector(ea)
    loops = ld.get_all_loops_in_func()
    print_loops(loops)
"""

if __name__ == '__main__':
    main()
