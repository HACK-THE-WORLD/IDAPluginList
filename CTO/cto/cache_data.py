import idc
import ida_idaapi
import ida_kernwin

import traceback
import os
import sys
import threading

import debug_print
ida_idaapi.require("debug_print")

class cache_data(debug_print.debug):
    def __init__(self, data_dict=None, config=None, debug=False):
        #debug_print.debug.__init__(self, debug)
        super(cache_data, self).__init__(debug)
        
        self.idb_name = idc.get_idb_path()
        self.dh = self.data_handler(self.idb_name, config, data_dict)
        
    class data_handler(object):
        class data_storage(object):
            def __init__(self, config=None, data_dict=None):
                if config is None:
                    self.config = {}
                else:
                    self.config = config.__dict__

                if data_dict is None or len(data_dict) == 0:
                    self.func_relations = {}
                    self.import_eas = {}
                    self.string_eas = {}
                    self.paths_cache = {}
                    self.dyn_apicalls = {}
                    self.opnums = {}
                    self.eps = {}
                    self.vtbl_refs = {}
                    self.internal_caches = {}
                else:
                    self.func_relations = data_dict['func_relations']
                    self.import_eas = data_dict['import_eas']
                    self.string_eas = data_dict['string_eas']
                    self.paths_cache = data_dict['paths_cache']
                    self.dyn_apicalls = data_dict['dyn_apicalls']
                    self.opnums = data_dict['opnums']
                    self.eps = data_dict['eps']
                    self.vtbl_refs = data_dict["vtbl_refs"]
                    self.internal_caches = data_dict["internal_caches"]
        
            def __iter__(self):
                return iter(self.__dict__.keys())
            def __getitem__(self, key):
                return self.__dict__[key]
            def __setitem__(self, key, value):
                self.__dict__[key] = value
        
        def __init__(self, idb_name, config, data_dict=None):
            self.lock = threading.Lock()
            self.idb_name = idb_name
            self.save_name = idb_name + '.pickle'
            #self.save_name = idb_name + '.cto.json'
            self.data = self.convert_data(config, data_dict)
            
        def convert_data(self, config, data_dict=None):
            return self.data_storage(config, data_dict)
            
        def save_data(self, data=None):
            if data is None:
                data = self.data
            import pickle
            #import json
            try:
                self.lock.acquire()
                f = open(self.save_name, 'wb')
                pickle.dump(data.__dict__, f, protocol=2)
                #f = open(self.save_name, 'w')
                #json.dump(data.__dict__, f)
                f.close()
                self.lock.release()
            except (OSError, IOError) as e:
                ida_kernwin.msg("Could not save the call tree cache and config data (%s: %s)%s" % (str(type(e)), e, os.linesep))
                return False
            #except FileNotFoundError as e:
            #    ida_kernwin.msg("Could not save the call tree cache and config data (%s: %s)%s" % (str(type(e)), e, os.linesep))
            #    return False
            except Exception as e:
                exc_type, exc_obj, tb = sys.exc_info()
                lineno = tb.tb_lineno
                ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
                traceback.print_exc()
                self.lock.release()
                return False
            return True
        
        def load_data(self, config, data=None):
            if data is None:
                data = self.data
            import pickle
            #import json
            if os.path.exists(self.save_name):
                try:
                    self.lock.acquire()
                    f = open(self.save_name, 'rb')
                    d = pickle.load(f)
                    #f = open(self.save_name, 'r')
                    #d = json.load(f)
                    f.close()
                    self.lock.release()
                except ValueError as e:
                    ida_kernwin.msg("Could not load the pickled data (%s: %s)%s" % (str(type(e)), e, os.linesep))
                except (OSError, IOError, EOFError) as e:
                    ida_kernwin.msg("Could not load the pickled data (%s: %s)%s" % (str(type(e)), e, os.linesep))
                #except FileNotFoundError as e:
                #    ida_kernwin.msg("Could not find the pickled data. Skip loading%s" % (os.linesep))
                except Exception as e:
                    exc_type, exc_obj, tb = sys.exc_info()
                    lineno = tb.tb_lineno
                    ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
                    traceback.print_exc()
                    self.lock.release()
                else:
                    _dummy = self.data_storage(config)
                    for k in _dummy:
                        if k in d and d[k]:
                            if k == "config":
                                for dck in config.__dict__:
                                    if dck in d[k]:
                                        config.__dict__[dck] = d[k][dck]
                            else:
                                data[k] = d[k]
                        else:
                            #return False
                            pass
                    
                    return data.__dict__
            return None
