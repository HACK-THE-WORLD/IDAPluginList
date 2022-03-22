import tempfile
import inspect
import os

import ida_kernwin

class debug(object):
    def __init__(self, debug=False):
        self.f = None
        self.output_lines = 0
        self.max_output_lines = 20000
        self.trace_back_frames = 2

    def _dbg_print(self, *msg):
        if not self.f:
            try:
                self.f = tempfile.NamedTemporaryFile(delete=False, buffering=0)
            except TypeError:
                self.f = tempfile.NamedTemporaryFile(delete=False) # for python 2.7
            if self.f:
                ida_kernwin.msg("%s was created as a debug log file.\n" % self.f.name)
                self.output_lines = 0
        callee_stks = inspect.stack()
        if len(callee_stks) > 1:
            callee_stk = inspect.stack()[self.trace_back_frames]
            # for python 2
            if isinstance(callee_stk, tuple):
                frame, filename, lineno, function, source_code, source_index = callee_stk
            # for python 3
            else:
                filename = callee_stk.filename
                lineno = callee_stk.lineno
                function = callee_stk.function
        else:
            filename = ""
            lineno = -1
            function = ""
            
        if len(msg) > 0:
            if isinstance(msg[-1], str):
                if not msg[-1].endswith(os.linesep):
                    msg = list(msg)
                    msg.append(os.linesep)
            else:
                msg = list(msg)
                msg.append(os.linesep)
        msg = "[%s:%d %s] " % (os.path.basename(filename), lineno, function) + " ".join([str(x) for x in msg])
        if self.f:
            self.f.write(msg.encode('utf-8'))
        if self.output_lines < self.max_output_lines:
            ida_kernwin.msg(msg)
        elif self.output_lines == self.max_output_lines:
            ida_kernwin.msg("The number of lines has been exceeded. Stop displaying debug messages.%s" % os.linesep)
            if self.f:
                ida_kernwin.msg("See %s to check the rest of messages.%s" % (self.f.name, os.linesep))
        self.output_lines += 1
            
    def dbg_print(self, *msg):
        self._dbg_print(*msg)
