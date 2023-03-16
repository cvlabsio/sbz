# Fixes up SBZ modules for analysis (function names, thunks).

from ghidra.app.util import PseudoDisassembler
from ghidra.program.model.symbol import SourceType

FUNC_MAPPINGS = {
    "406e3f09": "framework_buf_alloc",
    "f3088391": "framework_buf_free",
    "cdf85450": "framework_buf_ptr",
    "c1615be2": "framework_buf_size",
    "95f853f8": "framework_list_init",
    "8be492eb": "framework_list_destroy",
    "3bd47671": "framework_list_insert",
    "0ff81cb5": "framework_list_is_empty",
    "42109bad": "framework_list_iterate_callback",
    "0a324445": "framework_default_serializer",
    "5e337e35": "framework_init_deserialize",
    "7ce6c368": "framework_destroy_deserialize",
    "e3aee120": "framework_deserialize",
    "e4174cc6": "framework_deserialize_bool",
    "0d7dcae0": "framework_deserialize_u8",
    "f4b823fa": "framework_deserialize_u16",
    "254c2227": "framework_deserialize_u32",
    "ac93726d": "framework_deserialize_u64",
    "aaeb6641": "framework_deserialize_i8",
    "936626d4": "framework_deserialize_i16",
    "e7e66770": "framework_deserialize_i32",
    "25ed7159": "framework_deserialize_i64",
    "69d59a82": "framework_deserialize_buffer",
    "00c5fb6d": "framework_init_serialize",
    "bb1337a4": "framework_destroy_serialize",
    "dccaadd5": "framework_serialize",
    "55121976": "framework_serialize_bool",
    "6444673a": "framework_serialize_u8",
    "4782a8b0": "framework_serialize_u16",
    "db9d762d": "framework_serialize_u32",
    "a88b7a3c": "framework_serialize_u64",
    "dff8a1a2": "framework_serialize_i8",
    "e8a0262b": "framework_serialize_i16",
    "d71e79e5": "framework_serialize_i32",
    "21451236": "framework_serialize_i64",
    "8b5ffdca": "framework_serialize_buffer",
    "bb9a8675": "default_log_callback",
    "227ffec5": "system_calloc",
    "500b288d": "system_cond_broadcast",
    "9d2e940a": "system_cond_destroy",
    "35ed46eb": "system_cond_init",
    "9a79a116": "system_cond_signal",
    "37d03e4a": "system_cond_timedwait",
    "3d8cec3c": "system_cond_wait",
    "bebff213": "system_malloc",
    "8201388c": "system_memcmp",
    "79873eff": "system_memmove",
    "bf3146c2": "system_memset",
    "44611a64": "system_memzero_and_free",
    "602ea300": "system_mutex_destroy",
    "25587075": "system_mutex_init",
    "8233aa7c": "system_mutex_lock",
    "0009b0da": "system_mutex_trylock",
    "16a15934": "system_mutex_unlock",
    "5419924c": "system_strlen_with_nul",
    "fba9dc07": "system_thread_create",
    "64ecdf11": "system_thread_equal",
    "1a2b7e85": "system_thread_exit",
    "fb0cd6be": "system_thread_get_self",
    "133ae05b": "system_thread_join",
    "120a77b3": "system_yield",
    "a00beae3": "system_sleep",
    "fd1f1670": "log_message_decrypt",
    "91fd0a4c": "log_message_decrypt_and_crop",
    "90163d70": "sbz_log",
    "b63a18ca": "sbz_register_log_callback",
}

dis = PseudoDisassembler(currentProgram)
func_manager = currentProgram.getFunctionManager()

matches = findBytes(currentProgram.getImageBase(), ".{4}\\x30\\xbf.{2}\\x01\\x00\\x00\\x00", 500)

for match in matches:
    referenced_addr = dis.getIndirectAddr(match)

    print("{}".format(match))

    referenced_func = func_manager.getFunctionAt(referenced_addr)

    try:
        other_func = referenced_func.getThunkedFunction(True)
    except:
        print("thunked function for {} not found".format(match))
        continue

    if other_func:
        referenced_func = other_func
    
    referenced_name = referenced_func.getName()

    thunk_func = func_manager.getFunctionAt(match)

    # probably an "internal thunk" - seems to result from static linking
    if not thunk_func:
        createFunction(match, "")
        thunk_func = func_manager.getFunctionAt(match)

    thunk_func.setThunkedFunction(referenced_func)

    if referenced_name in FUNC_MAPPINGS:
        thunk_func.setName(FUNC_MAPPINGS[referenced_name], SourceType.USER_DEFINED)

try:
    deobfuscate_string = findBytes(currentProgram.getImageBase(), "\\x9a\\x18\\xe0\\x47\\x9a\\x1b\\x40\\x01\\x9a\\x18\\x80\\x0d", 1)[0].add(-0x20)

    print(deobfuscate_string)

    func = func_manager.getFunctionAt(deobfuscate_string)

    func.setName("deobfuscate_string", SourceType.USER_DEFINED)
except:
    print("string deobfuscation function not found")

