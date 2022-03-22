class _config_base(object):
    def __init__(self):
        self.get_default_config()
    
    def __len__(self):
        return len(self.__dict__)
    def __repr__(self):
        return str(self.__dict__)
    def __str__(self):
        return str(self.__dict__)
    def __iter__(self):
        return iter(self.__dict__.keys())
    def __getitem__(self, key):
        return self.__dict__[key]
    def __setitem__(self, key, value):
        self.__dict__[key] = value
        
    def get_default_config(self):
        self.debug = False
