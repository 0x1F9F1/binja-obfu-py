from binaryninja import *
from obfu_utils import *
from obfu_hook import add_patches, get_patches, save_patches

from patch_builder import expr, adjust_stack


def get_llil_xrefs(view, addr):
    return [ get_xref_llil(xref) for xref in view.get_code_refs(addr) ]


def check_tail_xrefs(view, func, tail):
    xrefs = get_llil_xrefs(view, tail.start)

    xrefs = set(xref.function for xref in xrefs if xref is not None)

    if func in xrefs:
        xrefs.remove(func)

    return len(xrefs) == 0


def fix_tails(view, func):
    llil = func.low_level_il
    count = 0

    for block in llil.basic_blocks:
        last = block[-1]
        tail = None

        if last.operation == LowLevelILOperation.LLIL_TAILCALL:
            tail = view.get_function_at(last.dest.value.value)
        elif last.operation == LowLevelILOperation.LLIL_JUMP:
            dest = last.dest.value
            if dest.type in [ RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue ]:
                tail = view.get_function_at(dest.value)
        else:
            continue

        if tail is None:
            continue
        if tail == func:
            continue
        if not tail.auto:
            log_info('Skipped user function {0}'.format(tail))
            continue

        if not check_tail_xrefs(view, func, tail):
            log_info('Tail {0} has too many xrefs'.format(tail))
            continue

        log_info('Removed Tail {0}'.format(tail))

        view.remove_user_function(tail)
        count += 1

    return count


def get_stack_contents(insn, offset, size):
    result = insn.get_stack_contents(offset, size)
    if result.type != RegisterValueType.UndeterminedValue:
        return result
    return insn.get_possible_stack_contents(offset, size)


def fix_jumps(view, func):
    arch = view.arch
    llil = func.low_level_il
    addr_size = arch.address_size
    stack_reg = arch.stack_pointer
    count = 0

    for block in llil.basic_blocks:
        insn = block[-1]

        if insn.operation not in [ LowLevelILOperation.LLIL_RET, LowLevelILOperation.LLIL_JUMP_TO, LowLevelILOperation.LLIL_TAILCALL, LowLevelILOperation.LLIL_JUMP ]:
            continue

        if get_patches(view, insn.address) is not None:
            continue

        stack_offset = get_stack_offset(arch, insn)

        if stack_offset is None:
            continue

        patches = [ ]

        dest = insn.dest

        if dest.operation == LowLevelILOperation.LLIL_LOAD:
            load_src = dest.src
            if dest.src.operation == LowLevelILOperation.LLIL_ADD:
                add_lhs = load_src.left
                add_rhs = load_src.right
                if (add_lhs.operation == LowLevelILOperation.LLIL_REG) and (add_lhs.src.name == stack_reg):
                    if add_rhs.operation == LowLevelILOperation.LLIL_CONST:
                        stack_adjustment = add_rhs.value.value
                        stack_offset += stack_adjustment

                        patches.append(adjust_stack(arch, stack_adjustment))

        good_pops = 0

        while good_pops < 16:
            currnet_offset = stack_offset + (good_pops * addr_size)
            contents = get_stack_contents(insn, currnet_offset, addr_size)
            if insn.address == 0x143865b40:
                log_error('Value {0} - 0x{1:X}'.format(contents, currnet_offset))
            if not are_values_executable(view, contents):
                break
            good_pops += 1
            if insn.address == 0x143865b40:
                log_error('Pops {0}'.format(good_pops))

        if not good_pops:
            continue

        if dest.operation in [ LowLevelILOperation.LLIL_REG, LowLevelILOperation.LLIL_CONST_PTR ]:
            patches.append(
                expr(LowLevelILOperation.LLIL_CALL, 0, dest)
            )

        for i in range(good_pops - 1, -1, -1):
            patches.append(
                expr(LowLevelILOperation.LLIL_SET_REG, addr_size, LLIL_TEMP(i),
                    expr(LowLevelILOperation.LLIL_POP, addr_size)
                )
            )

            patches.append(
                expr(LowLevelILOperation.LLIL_CALL if i else LowLevelILOperation.LLIL_JUMP, 0,
                    expr(LowLevelILOperation.LLIL_REG, addr_size, LLIL_TEMP(i))
                )
            )


        log_info('Fixed {0} pop rop @ 0x{1:X}'.format(good_pops, insn.address))

        add_patches(view, insn.address, patches)

        count += 1

    return count


# Allow setting the function pointer type when the source of a call is a load
def fix_calls(view, func):
    arch = view.arch
    llil = func.low_level_il
    addr_size = arch.address_size
    stack_reg = arch.stack_pointer
    count = 0
    for block in llil.basic_blocks:
        for insn in block:
            if get_patches(view, insn.address) is not None:
                continue
            if insn.operation != LowLevelILOperation.LLIL_CALL:
                continue
            dest = insn.dest
            if dest.operation != LowLevelILOperation.LLIL_LOAD:
                continue

            patches = [ ]

            patches.append(
                expr(LowLevelILOperation.LLIL_SET_REG, addr_size, LLIL_TEMP(0), dest)
            )

            patches.append(
                expr(LowLevelILOperation.LLIL_CALL, 0,
                    expr(LowLevelILOperation.LLIL_REG, addr_size, LLIL_TEMP(0))
                )
            )

            add_patches(view, insn.address, patches)

            log_info('Added temp register for call @ 0x{0:X}'.format(insn.address))

            count += 1

    return count


# https://github.com/Vector35/binaryninja-api/issues/1038
def fix_stack(view, func):
    arch = view.arch
    llil = func.low_level_il
    addr_size = arch.address_size
    stack_reg = arch.stack_pointer
    stack_reg_index = arch.get_reg_index(arch.stack_pointer)
    count = 0
    for block in llil.basic_blocks:
        for insn in block:
            if insn.operation != LowLevelILOperation.LLIL_SET_REG:
                continue
            if insn.src.operation != LowLevelILOperation.LLIL_POP:
                continue

            stack_before = insn.get_reg_value(stack_reg)

            if stack_before.type != RegisterValueType.StackFrameOffset:
                log_info('Failed to determine SP')
                continue

            # https://github.com/Vector35/binaryninja-api/issues/999
            # stack_after = insn.get_reg_value_after(stack_reg)
            stack_after = RegisterValue()
            stack_after.type = RegisterValueType.StackFrameOffset
            stack_after.offset = stack_before.offset + addr_size

            dest_reg = insn.dest

            if dest_reg.temp:
                continue

            dest_after = insn.get_reg_value_after(dest_reg.name)

            if dest_after.type != RegisterValueType.StackFrameOffset:
                continue

            patches = [ ]

            patches.append(
                adjust_stack(arch, stack_after.offset - stack_before.offset)
            )

            patches.append(
                expr(LowLevelILOperation.LLIL_SET_REG, addr_size, dest_reg,
                    expr(LowLevelILOperation.LLIL_ADD, addr_size,
                        expr(LowLevelILOperation.LLIL_REG, addr_size, stack_reg_index),
                        expr(LowLevelILOperation.LLIL_CONST, addr_size, dest_after.offset - stack_after.offset)
                    )
                )
            )

            add_patches(view, insn.address, patches)

            log_info('Patched Stack Pop @ 0x{0:X}'.format(insn.address))

            count += 1

    return count


def mlil_ssa_get_if_mov_source(mlil, var):
    if var.operation != MediumLevelILOperation.MLIL_VAR_PHI:
        log_info('Not MLIL_VAR_PHI')
        return None

    phis = var.src
    if len(phis) != 2:
        log_info('Not 2')
        return None

    defs = mlil_ssa_get_phi_defs(mlil, phis)
    for phi in defs:
        if phi.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
            log_info('Not MLIL_SET_VAR_SSA')
            return None

    branch, true_val, false_val = mlil_ssa_solve_branch_dependence(mlil, *defs)

    return mlil_ssa_trace_var(mlil, branch.condition), branch, true_val, false_val


def get_indirect_branch_condition(mlil, branch):
    if branch.operation != MediumLevelILOperation.MLIL_JUMP_TO:
        return None

    branches = branch.dest.possible_values
    if branches.type != RegisterValueType.InSetOfValues:
        return None

    if len(branches.values) != 2:
        log_info('Not 2 Branches')
        return None

    return mlil_ssa_get_if_mov_source(mlil, mlil_ssa_trace_var(mlil, branch.dest))


def label_indirect_branches(view, func):
    mlil = func.medium_level_il.ssa_form

    # Bug
    highlight_arch = func.arch.base_arch

    for basic_block in mlil:
        last = basic_block[-1]
        cond = get_indirect_branch_condition(mlil, last)
        if cond is not None:
            (cond_insn, cond_move_insn, true_val, false_val) = \
                (v.non_ssa_form for v in cond)
            func.set_comment_at(last.address,
                    '{0} @ {1:x}  if ({2}) then {3} else {4}'.format(cond_insn.instr_index,
                    cond_insn.address, cond_insn, true_val.src,
                    false_val.src))
            func.set_user_instr_highlight(last.address, HighlightStandardColor.BlueHighlightColor, arch = highlight_arch)
            func.set_user_instr_highlight(cond_insn.address, HighlightStandardColor.OrangeHighlightColor, arch = highlight_arch)

            if true_val.src.operation == MediumLevelILOperation.MLIL_CONST:
                func.set_user_instr_highlight(true_val.src.constant, HighlightStandardColor.GreenHighlightColor, arch = highlight_arch)

            if false_val.src.operation == MediumLevelILOperation.MLIL_CONST:
                func.set_user_instr_highlight(false_val.src.constant, HighlightStandardColor.RedHighlightColor, arch = highlight_arch)


def highlight_possible_tails(view, func):
    arch = func.arch
    llil = func.low_level_il
    addr_size = arch.address_size
    stack_reg = arch.stack_pointer
    highlight_arch = arch.base_arch
    for basic_block in llil:
        last = basic_block[-1]
        stack_offset = last.get_reg_value_after(stack_reg)
        if stack_offset.type != RegisterValueType.StackFrameOffset:
            continue

        if not stack_offset.offset:
            if not func.get_instr_highlight(last.address, arch = highlight_arch).alpha:
                func.set_user_instr_highlight(last.address, HighlightStandardColor.MagentaHighlightColor, arch = highlight_arch)


def fix_obfuscation(thread, view, func, auto_save = True):
    if thread is not None:
        thread.progress = 'Deobfuscating {0}, Initial Analysis'.format(func.name)

    view.update_analysis_and_wait()

    for i in range(100):
        if thread is not None:
            thread.progress = 'Deobfuscating {0}, Pass {1}'.format(func.name, i + 1)

        if fix_jumps(view, func) or fix_tails(view, func) or fix_stack(view, func) or fix_calls(view, func):
            func.reanalyze()
            view.update_analysis_and_wait()
        else:
            break

    if thread is not None:
        thread.progress = 'Deobfuscating {0}, Post Analysis'.format(func.name)

    label_indirect_branches(view, func)
    highlight_possible_tails(view, func)

    if auto_save:
        save_patches(view)
