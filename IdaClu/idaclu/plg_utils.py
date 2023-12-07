import collections
import os
import re
import sys


class PluginPath():
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        sys.path.insert(0, self.path)

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            sys.path.remove(self.path)
        except ValueError:
            pass

class RgbColor:
    def __init__(self, color_ref, color_nam='unknown'):
        ver_py = sys.version_info.major
        if (ver_py == 2 and
            any(isinstance(color_ref, t) for t in (int, long)) and
            color_ref <= 0xFFFFFFFF):
            self.r, self.g, self.b = self.get_from_tuple(int(color_ref))
        elif (ver_py == 3 and
            isinstance(color_ref, int) and
            color_ref <= 0xFFFFFFFF):
            self.r, self.g, self.b = self.get_from_tuple(color_ref)
        elif isinstance(color_ref, tuple) and len(color_ref) == 3:
            self.r, self.g, self.b = color_ref
        elif isinstance(color_ref, str):
            self.r, self.g, self.b = self.get_from_str(color_ref)
        else:
            raise ValueError("Invalid init value")
        self.name = color_nam

    def get_from_tuple(self, rgb_int):
        r = (rgb_int >> 16) & 255
        g = (rgb_int >> 8) & 255
        b = rgb_int & 255
        return (r, g, b)

    def get_from_str(self, color_ref):
        rgb_pat = r'rgb\((\d{1,3}),(\d{1,3}),(\d{1,3})\)'
        match = re.search(rgb_pat, color_ref)
        if match:
            r, g, b =  map(int, match.groups())
            if not all(0 <= c <= 255 for c in (r, g, b)):
                raise ValueError("Invalid color component values")
            return (r, g, b)
        else:
            raise ValueError("Invalid 'rgb(r,g,b)' string format")

    def get_to_str(self):
        return "rgb({},{},{})".format(self.r, self.g, self.b)

    def get_to_int(self):
        return (self.r << 16) + (self.g << 8) + self.b

    def __eq__(self, b):
        if isinstance(b, RgbColor):
            return self.r == b.r and self.g == b.g and self.b == b.b
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return self.get_to_str()

def from_hex(hex_sv):
    return int(hex_sv, base=16)

def invert_dict(original_dict):
    inverted_dict = {}
    for key, value in original_dict.items():
        if value not in inverted_dict:
            inverted_dict[value] = []
        inverted_dict[value].append(key)
    return inverted_dict

def add_prefix(func_name, func_pref, is_shadow=False):
    dlim_vars = ['%', '_']
    dlim_char = dlim_vars[int(is_shadow)]
    pref_norm = func_pref.strip('_')
    if is_shadow == False:
        dlim_anti = dlim_vars[int(not is_shadow)] 
        if dlim_anti in pref_norm:
            pref_norm = pref_norm.replace(dlim_anti, dlim_char)
    func_name_new = '{}{}{}'.format(pref_norm, dlim_char, func_name)
    return func_name_new

def get_folder_tree(root_folder):
    folder_structure = {}
    for folder_name in os.listdir(root_folder):
        folder_path = os.path.join(root_folder, folder_name)
        if os.path.isdir(folder_path):
            folder_structure[folder_name] = get_folder_tree(folder_path)
        else:
            folder_structure[folder_name] = "file"
    return folder_structure

def get_ordered_folder_tree(root_folder):
    return collections.OrderedDict(sorted(get_folder_tree(root_folder).items()))

def import_path(path):
    strpath = str(path)
    parent_path = os.path.dirname(os.path.abspath(path))
    sys.path.append(parent_path)
    module = __import__(os.path.basename(path))
    sys.path.pop()
    return module
