from binaryninja import *


def process_operand(operand):
    if type(operand) is ILRegister:
        return operand.index
    return operand


class ILExpression:
    def __init__(self, operation, size, operands):
        self.operation = operation
        self.operands = operands
        self.size = size

    def flatten(self):
        result = list()

        for operand in self.operands:
            if isinstance(operand, ILExpression):
                result.extend(operand.flatten())
            elif isinstance(operand, LowLevelILInstruction):
                result.extend((process_operand(operand) for operand in operand.postfix_operands))
            else:
                result.append(process_operand(operand))

        result.append(LowLevelILOperationAndSize(self.operation, self.size))

        return result


def pop_args(stack, count):
    if count:
        results = stack[-count:]
        del stack[-count:]
        return results
    return [ ]


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


def expr(operation, size, *operands):
    return ILExpression(operation, size, operands)


def adjust_stack(arch, amount):
    address_size = arch.address_size
    stack_pointer = arch.get_reg_index(arch.stack_pointer)

    return expr(LowLevelILOperation.LLIL_SET_REG, address_size, stack_pointer,
        expr(LowLevelILOperation.LLIL_ADD, address_size,
            expr(LowLevelILOperation.LLIL_REG, address_size, stack_pointer),
            expr(LowLevelILOperation.LLIL_CONST, address_size, amount)
        )
    )
