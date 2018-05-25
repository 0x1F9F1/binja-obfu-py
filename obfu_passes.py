from binaryninja import *
from obfu_utils import *
from obfu_hook import add_patches, get_patches


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


def fix_jumps(view, func):
    arch = view.arch
    llil = func.low_level_il
    addr_size = arch.address_size
    stack_reg = arch.stack_pointer
    count = 0
    for block in llil.basic_blocks:
        insn = block[-1]

        func.set_auto_instr_highlight(insn.address, HighlightStandardColor.BlueHighlightColor)

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
                        stack_offset -= stack_adjustment
                        patches.append([
                            add_lhs.src.index,
                            add_lhs.src.index,
                            LowLevelILOperationAndSize(LowLevelILOperation.LLIL_REG, addr_size),
                            stack_adjustment,
                            LowLevelILOperationAndSize(LowLevelILOperation.LLIL_CONST, addr_size),
                            LowLevelILOperationAndSize(LowLevelILOperation.LLIL_SUB, addr_size),
                            LowLevelILOperationAndSize(LowLevelILOperation.LLIL_SET_REG, addr_size)
                        ])


        good_pops = 0

        while good_pops < 16:
            contents = insn.get_possible_stack_contents(stack_offset + addr_size * good_pops, 0)
            if not are_values_executable(view, contents):
                break
            good_pops += 1

        if good_pops == 0:
            continue

        orig_dest = None

        if dest.operation == LowLevelILOperation.LLIL_CONST_PTR:
            orig_dest = [ dest.constant, LowLevelILOperationAndSize(dest.operation, dest.size) ]
        elif dest.operation == LowLevelILOperation.LLIL_REG:
            orig_dest = [ dest.src.index, LowLevelILOperationAndSize(dest.operation, dest.size) ]

        if orig_dest is not None:
            patches.append(orig_dest + [ LowLevelILOperationAndSize(LowLevelILOperation.LLIL_CALL, 0) ])

        for i in range(good_pops):
            patches.extend([
                [
                    LLIL_TEMP(i),
                    LowLevelILOperationAndSize(LowLevelILOperation.LLIL_POP, addr_size),
                    LowLevelILOperationAndSize(LowLevelILOperation.LLIL_SET_REG, addr_size)
                ],
                [
                    LLIL_TEMP(i),
                   LowLevelILOperationAndSize(LowLevelILOperation.LLIL_REG, addr_size),
                   LowLevelILOperationAndSize(LowLevelILOperation.LLIL_CALL if i else LowLevelILOperation.LLIL_JUMP, 0)
                ]
            ])

        log_info('Fixed {0} pop rop'.format(good_pops))

        add_patches(view, insn.address, patches)

        count += 1

    return count


def mlil_ssa_get_if_mov_source(mlil, var):
    if var.operation != MediumLevelILOperation.MLIL_VAR_PHI:
        log_info('Not MLIL_VAR_PHI', var)
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

    (branch, true_val, false_val) = \
        mlil_ssa_solve_branch_dependence(mlil, *defs)

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

    return mlil_ssa_get_if_mov_source(mlil, mlil_ssa_trace_var(mlil,
                             branch.dest))


def label_indirect_branches(view, func):
    mlil = func.medium_level_il.ssa_form

    for basic_block in mlil:
        last = basic_block[-1]
        cond = get_indirect_branch_condition(mlil, last)
        if cond is not None:
            (cond_insn, cond_move_insn, true_val, false_val) = \
                (v.non_ssa_form for v in cond)
            mlil.source_function.set_comment_at(last.address,
                    '{0} @ {1:x}  if ({2}) then {3} else {4}'.format(cond_insn.instr_index,
                    cond_insn.address, cond_insn, true_val.src,
                    false_val.src))


def fix_obfuscation_task(thread, view, func):
    for i in range(100):
        thread.progress = 'Removing Obfuscation - Pass {0}'.format(i)

        if fix_jumps(view, func) or fix_tails(view, func):
            func.reanalyze()
            view.update_analysis_and_wait()
        else:
            break

    thread.progress = 'Labelling Indirect Branches'
    label_indirect_branches(view, func)


def fix_obfuscation(view, func):
    task = RunInBackground('Removing Obfuscation',
                           fix_obfuscation_task, view, func)
    task.start()
