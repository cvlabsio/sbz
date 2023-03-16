# Deobfuscates strings and log messages present in SBZ samples.
# If module, MUST RUN sbz_module_fixup.py first.
# Contains code derived from https://github.com/HackOvert/GhidraSnippets#analyzing-function-call-arguments-at-cross-references

from ghidra.app.decompiler import DecompInterface
from ghidra.app.util import PseudoDisassembler
from ghidra.program.model.pcode import PcodeOp

STRING_ADDR = toAddr(0x27568)
MESSAGE_ADDR = toAddr(0x2ab5c)

COUNT = 0

def get_function_by_name(name):
    funcs = currentProgram.getFunctionManager().getFunctions(True)

    for func in funcs:
        if func.getName() == name:
            return func
        

def get_external_function_by_name(name):
    externs = currentProgram.getFunctionManager().getExternalFunctions()

    for extern in externs:
        if extern.getName() == name:
            return extern


def get_indirect_ptr(addr):
    dis = PseudoDisassembler(currentProgram)
    return dis.getIndirectAddr(addr)


def get_byte(addr):
    return getByte(addr)


def get_bytes(addr, size):
    return bytearray(getBytes(addr, size))


def strlen(addr):
    pos = 0

    while True:
        if get_byte(addr.add(pos)) == 0:
            break
        pos = pos + 1

    return pos


def resolve_string_loc(varnode):
    if varnode.isUnique():
        op = varnode.getDef()

        if op.getOpcode() == PcodeOp.COPY or op.getOpcode() == PcodeOp.MULTIEQUAL:
            inputs = op.getInputs()

            return get_indirect_ptr(inputs[0].getAddress())

        return None
    else:
        return get_indirect_ptr(varnode.getAddress())


def get_function_at(addr):
    return currentProgram.getFunctionManager().getFunctionAt(addr)


def get_function_callers(addr):
    callers = []

    references = getReferencesTo(addr)

    for xref in references:
        call_addr = xref.getFromAddress()
        caller = getFunctionContaining(call_addr)
        callers.append(caller)

    callers = list(set(callers))

    return callers


def handle_function_calls(target_addr, callers, handler):
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)

    for caller in callers:
        if caller == None:
            continue

        res = ifc.decompileFunction(caller, 30, monitor)
        high_func = res.getHighFunction()
        if high_func:
            opiter = high_func.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                if op.getOpcode() == PcodeOp.CALL:
                    inputs = op.getInputs()
                    addr = inputs[0].getAddress()
                    args = inputs[1:]
                    if addr == target_addr:
                        handler(op.getSeqnum().getTarget(), args)


def deobfuscate_string(buf, size):
    previous = buf[0]
    result = bytearray(size)

    if 1 < size + 1:
        counter = 1
        while True:
            current = buf[counter]
            result[counter - 1] = counter ^ current ^ 0x47 ^ previous
            counter += 1
            previous = (previous + current) & 0xff

            if counter >= size + 1:
                break

    return result.decode("ascii")


def deobfuscate_message_helper(key, buf, size):
    current = buf[0]
    counter = 0

    while True:
        current = (current * key) & 0xff
        buf[counter] = current
        counter += 1

        if counter == size:
            break

        current = buf[counter]


def deobfuscate_message(buf, size):
    counter = 1
    current = 0

    result = bytearray(size)

    while True:
        current = counter

        if counter >= size or buf[counter] == 0:
            break

        counter += 1

    while counter != 0:
        previous = current

        counter = counter - 1
        current = buf[counter]
        xv = previous ^ current

        result[counter] = xv
        if xv == 0:
            result[counter] = previous

    deobfuscate_message_helper(0x8b, result, size)

    return result.decode("ascii")


def set_comment(addr, string):
    listing = currentProgram.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    code_unit.setComment(code_unit.PLATE_COMMENT, string)
    code_unit.setComment(code_unit.PRE_COMMENT, string)


def handle_strings(xref, args):
    global COUNT

    if not args:
            print(
                "unable to resolve arguments for {:#x}".format(
                    xref.getOffset()
                )
            )
            return
    
    size = args[2]
    enc_buf_ptr = resolve_string_loc(args[1])

    if not size:
            print("unable to resolve size for {:#x}".format(xref.getOffset()))
            return

    if (
            not enc_buf_ptr or enc_buf_ptr.getOffset() == 0x5d408
        ):  # This specific string causes Ghidra's decompiler to freak out (appears to be invalid ascii?)
            print(
                "unable to resolve string location for {:#x}".format(
                    xref.getOffset()
                )
            )
            return
    
    enc_buf = get_bytes(enc_buf_ptr, size.getOffset() + 1)

    try:
        dec = deobfuscate_string(enc_buf, size.getOffset() - 1)
    except:
        print("failed to deobfuscate string at {:#x}".format(xref.getOffset()))
        return

    set_comment(xref, dec)
    print('{:#x} - "{}"'.format(xref.getOffset(), dec))

    COUNT += 1


def handle_messages(xref, args):
    global COUNT

    if not args or len(args) < 4:
            print(
                "unable to resolve arguments for {:#x}".format(
                    xref.getOffset()
                )
            )
            return

    enc_buf_ptr = resolve_string_loc(args[3])

    if not enc_buf_ptr:
        print(
            "unable to resolve string location for {:#x}".format(
                xref.getOffset()
            )
        )
        return

    size = strlen(enc_buf_ptr)
    enc_buf = get_bytes(enc_buf_ptr, size)

    try:
        dec = deobfuscate_message(enc_buf, size)
    except:
        print("failed to deobfuscate message at {:#x}".format(
            xref.getOffset()))
        return

    set_comment(xref, dec)
    print('{:#x} - "{}"'.format(xref.getOffset(), dec))

    COUNT += 1


# Implant core
if currentProgram.getExecutableSHA256() == "5cdfbfaad93f79d42feecf08a9c7afa5363c847d3e9cb18c3d6188a757b292c6":
    string_callers = get_function_callers(STRING_ADDR)

    handle_function_calls(STRING_ADDR, string_callers, handle_strings)
else:  # Implant plugins
    MESSAGE_ADDR = get_external_function_by_name("90163d70").getFunctionThunkAddresses()[1]

    try:
        STRING_ADDR = get_function_by_name("deobfuscate_string").getEntryPoint()

        string_callers = get_function_callers(STRING_ADDR)

        handle_function_calls(STRING_ADDR, string_callers, handle_strings)
    except:
        pass



message_callers = get_function_callers(MESSAGE_ADDR)

handle_function_calls(MESSAGE_ADDR, message_callers, handle_messages)  

print("{} items deobfuscated".format(COUNT))

