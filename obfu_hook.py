from binaryninja import ArchitectureHook, log
from obfu_utils import get_llil_view
from patch_builder import ILExpression, eval_llil_tokens
import pickle

OBFU_KEY = 'obfu_patches'

def get_all_patches(view):
    session_data = view.session_data

    if OBFU_KEY not in session_data:
        patches = dict()
        try:
            patches = pickle.loads(view.query_metadata(OBFU_KEY))
            log.log_info('Loaded {0} patches'.format(len(patches)))
        except:
            pass
        session_data[OBFU_KEY] = patches

    return session_data[OBFU_KEY]


def save_patches(view):
    patches = get_all_patches(view)

    if patches:
        log.log_info('Stored {0} patches to {1}'.format(len(patches), view))

        view.store_metadata(OBFU_KEY, pickle.dumps(patches))


def add_patches(view, addr, patch):
    patches = get_all_patches(view)

    patch = [ expr.flatten() if isinstance(expr, ILExpression) else expr for expr in patch ]

    patches[addr] = patch


def get_patches(view, addr):
    patches = get_all_patches(view)
    return patches.get(addr)


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
