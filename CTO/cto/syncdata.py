import sys

class sync_data(object):
    g_data_name = "g_cto_data"
    
    def get(self):
        # this process should be the first instance of CTO related object
        if not hasattr(sys.modules["__main__"], self.g_data_name):
            print("data is unavailable. extract data from idb or pickle")
            return None
        else:
            print("get data from global variable")
            # Read the global dict
            return sys.modules["__main__"].__dict__[self.g_data_name]
            
    def set(self, cto_data):
        # set the mode to the master to update the pickle file
        # 
        setattr(sys.modules["__main__"], self.g_data_name, cto_data)

    def close(self):
        # check the refcount
        if hasattr(sys.modules["__main__"], self.g_data_name) and sys.modules["__main__"].__dict__[self.g_data_name]['refcnt'] < 1:
            print("global variable data deleted")
            delattr(sys.modules["__main__"], self.g_data_name)
    
    def __del__(self):
        self.close()
