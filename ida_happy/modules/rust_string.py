import ida_hexrays
import ida_segment
import ida_bytes
import ida_lines
import idc
from ida_happy.miscutils import tag_text

class HexraysRustStringHook(ida_hexrays.Hexrays_Hooks):
    """fixup rust string display for better decompile experience"""
    def __init__(self):
        super().__init__()
        self.enable = self.detect_rust_binary()

    def func_printed(self, cfunc):
        if self.enable:
            self.convert_rust_string(cfunc)
        return 0

    def detect_rust_binary(self):
        ea = idc.get_name_ea_simple("rust_begin_unwind")
        if ea != idc.BADADDR:
            return True

        segment = ida_segment.get_segm_by_name(".rodata") or \
                        ida_segment.get_segm_by_name("__const")
        if segment:
            start = segment.start_ea
            end = segment.end_ea

            ea = ida_bytes.find_bytes(b'rustc-', start, end - start)
            return ea != idc.BADADDR

        return False

    def convert_rust_string(self, cf):
        ci = ida_hexrays.ctree_item_t()
        ccode = cf.get_pseudocode()
        for line_idx in range(cf.hdrlines, len(ccode)):
            sl = ccode[line_idx]
            char_idx = 0

            # use a dictionary to handle cases where multiple labels reference to the same cexpr_t
            # we only replace the variable name reference to string
            target = {}
            line_len = len(ida_lines.tag_remove(sl.line))
            for char_idx in range(line_len):
                if not cf.get_line_item(sl.line, char_idx, True, None, ci, None):
                    continue

                if not (ci.it.is_expr() and ci.e.op == ida_hexrays.cot_obj):
                    continue

                ea = ci.e.obj_ea
                if not idc.is_strlit(ida_bytes.get_full_flags(ea)):
                    continue

                varname = ci.e.dstr()
                if varname[0] == '"':
                    continue

                orig_string = ci.e.print1(None)
                if orig_string in target:
                    continue

                length = ida_bytes.get_item_size(ea)
                string = ida_bytes.get_bytes(ea, length).decode()
                color_string = ida_lines.COLSTR(f'"{string}"', ida_lines.SCOLOR_CREF)
                tagged_string = tag_text(color_string, ci.e.index)
                target[orig_string] = tagged_string

            for orig, mod in target.items():
                sl.line = sl.line.replace(orig, mod)
