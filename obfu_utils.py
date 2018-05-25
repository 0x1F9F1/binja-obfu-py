from binaryninja import *


class RunInBackground(BackgroundTaskThread):
    def __init__(self, msg, func, *args, **kwargs):
            BackgroundTaskThread.__init__(self, msg, True)
            self.func = func
            self.args = args
            self.kwargs = kwargs

    def run(self):
        self.func(self, *self.args, **self.kwargs)


# LowLevelILFunction isn't provided with a source_function during LLIL generation, but we need it to access the BinaryView.
# https://github.com/Vector35/binaryninja-api/issues/551
def get_llil_view(llil):
    return BinaryView(handle = core.BNGetFunctionData(core.BNGetLowLevelILOwnerFunction(llil.handle)))


def pop_args(stack, count):
    return list(reversed(list(stack.pop() for _ in range(count))))


# https://en.wikipedia.org/wiki/Reverse_Polish_notation
def eval_llil_tokens(llil, tokens):
    args = list()

    for token in tokens:
        if type(token) is LowLevelILOperationAndSize:
            operation = token.operation
            arg_count = len(LowLevelILInstruction.ILOperations[operation])
            args.append(llil.expr(operation, *pop_args(args, arg_count), size = token.size).index)
        else:
            args.append(token)

    return LowLevelILExpr(args.pop())


def mlil_ssa_trace_var(mlil, var):
    for _ in range(100):
        if var.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            index = mlil.get_ssa_var_definition(var.src)
            if index is None:
                return var
            var = mlil[index]
        elif var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
            var = var.src
        else:
            return var

    log_error('Failed to trace var {0} in {1}'.format(var, mlil))
    return None


def mlil_ssa_get_phi_defs(mlil, phis):
    return [ mlil[mlil.get_ssa_var_definition(phi)] for phi in phis ]


def mlil_ssa_solve_branch_dependence(mlil, lhs, rhs):
    lhs_branches = lhs.branch_dependence
    rhs_branches = rhs.branch_dependence
    for index, lhs_dependence in lhs_branches.items():
        if index not in rhs_branches:
            continue
        rhs_dependence = rhs_branches[index]
        if lhs_dependence == rhs_dependence:
            continue
        branch = mlil[index]
        if branch.operation != MediumLevelILOperation.MLIL_IF:
            continue
        if lhs_dependence == ILBranchDependence.FalseBranchDependent:
            lhs, rhs = rhs, lhs
        return branch, lhs, rhs
    return None


def get_raw_values(values):
    if values.type == RegisterValueType.ConstantValue:
        return [values.value]
    if values.type == RegisterValueType.ConstantPointerValue:
        return [values.value]
    if values.type == RegisterValueType.LookupTableValue:
        return [ v.to_value for v in values.table ]
    if values.type == RegisterValueType.InSetOfValues:
        return values.values


def get_xref_llil(xref):
    return xref.function.get_low_level_il_at(xref.address)


def get_stack_offset(arch, insn):
    value = insn.get_reg_value(arch.stack_pointer)

    if value.type != RegisterValueType.StackFrameOffset:
        return None

    return value.offset


def are_values_executable(view, values):
    raw_values = get_raw_values(values)
    return raw_values is not None and all(view.is_offset_executable(v) for v in raw_values)
