# a plugin extension to be incorporated into symless plugin
class plugin_t:
    # load the plugin
    def __init__(self):
        pass

    # terminate & clean the extension
    def term(self):
        pass


# entry function to be defined by every additional plugin
def get_plugin() -> plugin_t:
    return None
