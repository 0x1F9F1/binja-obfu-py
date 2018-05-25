from binaryninja import ArchitectureHook
from collections import defaultdict

from obfu_utils import get_llil_view, eval_llil_tokens


def add_patches(view, addr, patch):
    session_data = view.session_data

    if 'obfu_patches' not in session_data:
        session_data['obfu_patches'] = dict()

    view.session_data['obfu_patches'][addr] = patch


def get_patches(view, addr):
    session_data = view.session_data

    if 'obfu_patches' not in session_data:
        session_data['obfu_patches'] = dict()

    return view.session_data['obfu_patches'].get(addr)


class ObfuArchHook(ArchitectureHook):
    def get_instruction_low_level_il(self, data, addr, il):
        view = get_llil_view(il)
        patch = get_patches(view, addr)

        if patch is not None:
            for tokens in patch:
                new_il = eval_llil_tokens(il, tokens)
                il.append(new_il)

            return self.get_instruction_info(data, addr).length

        return super(ObfuArchHook, self).get_instruction_low_level_il(data, addr, il)
