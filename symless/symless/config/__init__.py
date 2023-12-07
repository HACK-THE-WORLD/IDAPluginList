import inspect
import json
import os

# different log levels
LOG_LEVEL_CRITICAL = 50
LOG_LEVEL_ERROR = 40
LOG_LEVEL_WARNING = 30
LOG_LEVEL_INFO = 20
LOG_LEVEL_DEBUG = 10
LOG_LEVEL_VERBOSE_DEBUG = 5

LOG_LEVEL_DEFAULT = LOG_LEVEL_WARNING


# symless global settings
class Settings:
    def __init__(self):
        self.log_level = LOG_LEVEL_DEFAULT
        self.debug = False
        self.rebase_db = True  # set imagebase to 0 before generating structures (& names)

        # symless folder path
        self.root = os.path.realpath(os.path.join(os.path.dirname(inspect.getsourcefile(lambda: 0)), ".."))

        config_file = os.path.join(self.root, "config", "config.json")
        self.initialize(config_file)

    # initialize global config with config file
    def initialize(self, config_file: str):
        with open(config_file, "rb") as config:
            settings = json.load(config)
            for key, value in settings.items():
                self.__setattr__(key, value)


# global settings variable
g_settings = Settings()
