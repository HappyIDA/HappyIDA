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

        segment = (
            ida_segment.get_segm_by_name(".rodata")
            or ida_segment.get_segm_by_name(".rdata")
            or ida_segment.get_segm_by_name("__const")
        )
        if segment:
            start = segment.start_ea
            end = segment.end_ea

            ea = ida_bytes.find_bytes(b'rustc-', start, end - start)
            return ea != idc.BADADDR

        return False

    def convert_rust_string(self, cf):
        ccode = cf.get_pseudocode()

        # use a dictionary to handle cases where multiple labels reference to the same cexpr_t
        # we only replace the variable name reference to string
        line_targets = {}

        for item in cf.treeitems:
            if not item.is_expr() or item.op != ida_hexrays.cot_obj:
                continue

            e = item.cexpr
            ea = e.obj_ea
            if not idc.is_strlit(ida_bytes.get_full_flags(ea)):
                continue

            varname = e.dstr()
            if varname.startswith(('"', 'L"')):
                continue

            _, y = cf.find_item_coords(item)
            if y is None or y < cf.hdrlines:
                continue

            orig_string = e.print1(None)
            if orig_string in line_targets.get(y, {}):
                continue

            length = ida_bytes.get_item_size(ea)
            string = ida_bytes.get_bytes(ea, length).decode()
            color_string = ida_lines.COLSTR(f'"{string}"', ida_lines.SCOLOR_CREF)
            tagged_string = tag_text(color_string, e.index)
            if y not in line_targets:
                line_targets[y] = {}
            line_targets[y][orig_string] = tagged_string

        for line_idx, target in line_targets.items():
            sl = ccode[line_idx]
            for orig, mod in target.items():
                sl.line = sl.line.replace(orig, mod)