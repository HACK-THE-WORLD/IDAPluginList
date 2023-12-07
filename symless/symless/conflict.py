import collections
from typing import Collection, Dict, List, Set, Tuple

import symless.generation as generation
import symless.model as model
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils


# for possible overlapping fields for a structure
# which one to choose
def fields_conflicts_solver(field: generation.field_t, old_field: generation.field_t) -> bool:
    # care when replacing a typed field
    if old_field.has_type():
        # do not untype our field
        if not field.has_type():
            return False

        return old_field.replace(field)

    # default policy: replace
    return True


# when converting from var field to field
# which field size to use, between all possibilities
def field_size_solver(field: model.field_t) -> int:
    # default policy: minimum size
    return min(field.get_size())


# define less derived structure between multiple structs
# the less derived should be the nearest from their common base
def less_derived(candidates: List[Tuple[generation.structure_t, int]]) -> Tuple[generation.structure_t, int]:
    candidates.sort(key=lambda i: (i[1], i[0].get_size()))
    return candidates[0]


# find which class a vtable belongs to
# among multiple structures referencing this vtable
def vtable_owner_solver(candidates: List[Tuple[generation.structure_t, int]]) -> Tuple[generation.structure_t, int]:
    # find less derived candidate (smallest shift and smallest size)
    candidates.sort(key=lambda i: (i[1], i[0].get_size()))
    return candidates[0]


# get groups of structures that are conflicting
# i.e they flow through the same entries (with same shift) and can be duplicated
def get_conflicting_structures(
    entries: model.entry_record_t,
) -> Collection[Set[generation.structure_t]]:
    # list of every conflict by belligerent (structure & shift)
    conflict_per_struc: Dict[Tuple[int, generation.structure_t], Set[Tuple[int, generation.structure_t]]] = dict()

    # get conflicts for each entry
    for entry in entries.get_entries():
        # do not consider ep that may not represent a structure
        lower, upper = entry.get_boundaries()
        if lower == 0 and upper <= ida_utils.get_ptr_size():
            continue

        # get conflicting strucs & shift for entry
        flow = entry.get_flow()
        shifts = set([shift for shift, _ in flow])
        conflicts = [set([j for j in filter(lambda k: k[0] == i, flow)]) for i in shifts]

        # update conflicts record
        for conflict in conflicts:
            if len(conflict) <= 1:  # no conflict
                continue

            utils.g_logger.debug(
                f"conflicting strucs for {entry.entry_id()}: ({', '.join(['[%s:0x%x]' % (struc.get_name(), shift) for shift, struc in conflict])})"
            )

            # update conflict_per_struc record
            # regroup structures conflicting on same shift as potential duplicates
            cqueue = collections.deque(conflict)
            while len(cqueue) > 0:
                current = cqueue.pop()

                if current in conflict_per_struc:
                    previous = conflict_per_struc[current]
                    cqueue.extend(previous.difference(conflict))
                    conflict.update(previous)

                conflict_per_struc[current] = conflict

    # build conflict record
    out: Collection[Set[generation.structure_t]] = collections.deque()
    for conflict in conflict_per_struc.values():
        conflicts_strucs = set([struc for _, struc in conflict])  # conflicting strucs set

        # if conflict subset exists, update it
        no_subset = True
        for existing in out:
            if conflicts_strucs.issubset(existing):  # conflict already recorded
                pass
            elif existing.issubset(conflicts_strucs):  # update conflict
                existing.update(conflicts_strucs)
            else:
                continue

            no_subset = False
            break

        # else add conflict group to record
        if no_subset:
            out.append(conflicts_strucs)

    return out


# can we consider two structures to be duplicates & merge them
def are_structures_identical(one: generation.structure_t, other: generation.structure_t) -> bool:
    # even if computed size is not always right
    # consider different sized structures to be different
    if one.get_size() != other.get_size():
        return False

    i, j = 0, 0
    while i < len(one.range) and j < len(other.range):
        off_one, size_one = one.range[i][0], one.range[i][1]
        off_other, size_other = other.range[j][0], other.range[j][1]

        if off_one < off_other:
            # overlapping fields
            if off_one + size_one < off_other:
                return False

            i += 1

        elif off_one > off_other:
            # overlapping fields
            if off_other + size_other < off_one:
                return False

            j += 1

        else:
            f_field = one.get_field(off_one)
            s_field = other.get_field(off_other)

            # find most basic field
            if isinstance(f_field, s_field.__class__):
                base, oth = s_field, f_field

            elif isinstance(s_field, f_field.__class__):
                base, oth = f_field, s_field

            # the two fields have unrelated types
            else:
                return False

            # two fields types do not match
            if not base.match(oth):
                return False

            i += 1
            j += 1

    return True


# merge src struc into dst
def merge_structures(src: generation.structure_t, dst: generation.structure_t, entries: model.entry_record_t):
    utils.g_logger.info("Merging duplicated structures %s & %s" % (src.get_name(), dst.get_name()))

    # merge fields
    for field in src.get_fields():
        dst.set_field(field, fields_conflicts_solver)

    # merge root entries
    for shift, entry in src.associated_root():
        dst.associate_root(entry, shift)

    # replace associated structures in entries
    for entry in entries.get_entries():
        shift, struc = entry.get_structure()
        if struc == src:
            entry.set_structure(shift, dst)


# find & merge duplicated structures
def remove_dupes(entries: model.entry_record_t, structures: generation.structure_record_t):
    # find conflicting structures
    dupe_conflicts = get_conflicting_structures(entries)

    # merge duplicates
    for c in dupe_conflicts:
        conflict = list(c)

        utils.g_logger.debug("Found conflict between structures (%s)" % ", ".join([struc.get_name() for struc in c]))

        i = 0
        while i < len(conflict) - 1:
            dst = structures.get_structure(conflict[i])

            j = i + 1
            while j < len(conflict):
                src = structures.get_structure(conflict[j])

                # different strucs, to be merged
                if dst != src and are_structures_identical(src, dst):
                    merge_structures(src, dst, entries)
                    structures.replace_by(src, dst)
                    del conflict[j]
                    continue

                j += 1

            i += 1
