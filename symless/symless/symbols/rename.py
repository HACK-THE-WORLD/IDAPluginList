from typing import Collection, List, Tuple

import symless.generation as generation
from symless.symbols import *


# update list of potential names with given candidate
def add_candidate_name(names: List[Tuple[int, str]], candidate: Tuple[int, str]):
    relevance, name = candidate

    seeker = (i for i, (_, n) in enumerate(names) if (n == name))
    try:
        idx = next(seeker)  # name exists, update relevance
        old_rel, _ = names[idx]
        if old_rel > relevance:
            names[idx] = (relevance, name)
    except StopIteration:
        names.append((relevance, name))


# get a list of possible names for a structure
# ordered by preferences
def find_structure_name(struc: generation.structure_t) -> Collection[str]:
    names: List[Tuple[int, str]] = list()
    current_root, depth = None, 0

    # loop over all nodes associated to the structure
    # get names from the associated nodes
    for root, shift, block in struc.node_flow():
        if root != current_root:
            current_root, depth = root, 0

        if shift == 0 and depth <= 2:
            name, relevance = block.get_owner().find_name()
            if name is not None:  # add possible name to the list
                name = struc_name_cleanup(name)
                relevance *= depth + 1
                add_candidate_name(names, (relevance, name))

        depth += 1

    # add name from associated vtable to the list
    field = struc.get_field(0)

    # first field is a vtable pointer
    if isinstance(field, generation.vtbl_ptr_field_t):
        _, vtable = field.get_structure()
        derived, _ = get_classnames_from_vtable(vtable.ea)
        if derived is not None:
            # names from first vtable are more accurate than names from ctors
            # set best preference (0)
            add_candidate_name(names, (0, struc_name_cleanup(derived)))

    names.sort(key=lambda k: k[0])
    return [n for _, n in names]


# name all structures from given record
# use symbols for naming
# TODO: select less derived when conflict on name
def define_structures_names(record: generation.structure_record_t):
    all_names = set()  # all given names record

    for struc in record.get_structures():
        # define structure's fields names
        struc.compute_names()

        # define structure's name
        names = find_structure_name(struc)
        if len(names) == 0:
            continue

        # name conflict, make it unique
        name = names[0]
        if name in all_names:
            name = f"{name}_0x{struc.ea:x}"

        all_names.add(name)
        struc.set_name(name)
