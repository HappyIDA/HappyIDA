import idaapi
import ida_hexrays
import ida_lines
from ida_happy.miscutils import tag_text

class HexraysParamLabelHook(ida_hexrays.Hexrays_Hooks):
    """make decompiler display swift-like parameter label"""
    def func_printed(self, cfunc):
        self.add_parameter_labels(cfunc)
        return 0

    def add_parameter_labels(self, cf):
        ci = ida_hexrays.ctree_item_t()
        ccode = cf.get_pseudocode()
        target = {}
        for line_idx in range(cf.hdrlines, len(ccode)):
            sl = ccode[line_idx]
            for char_idx in range(len(sl.line)):
                if cf.get_line_item(sl.line, char_idx, True, None, ci, None):
                    if ci.it.is_expr() and ci.e.op == ida_hexrays.cot_call:
                        if ci.e.x.op == ida_hexrays.cot_helper:
                            #TODO: build known helper dictionary
                            pass
                        else:
                            args = self.get_func_params(ci.e.x)
                            if not args:
                                continue

                            for a, arg in zip(ci.e.a, args):
                                name = arg.name
                                ty = arg.type
                                # filter same name cases
                                # TODO: add support to hide tag if A: B->A ? (should filter A: [*&]B->A cases / or not? no sense to do that actually...)
                                if a.dstr() == name:
                                    continue

                                idx = a.index
                                tag = a.print1(None)
                                target[tag] = (idx, name)
            for item in list(target.keys()):
                if item in sl.line:
                    (index, name) = target.pop(item)
                    if name == '':
                        name = "unk"
                    label = ida_lines.COLSTR(name, ida_lines.SCOLOR_HIDNAME)
                    tagged = tag_text(label, index)
                    sl.line = sl.line.replace(item, tagged + ": " + item)

    def get_func_params(self, f):
        tinfo = f.type
        func_data = idaapi.func_type_data_t()

        if tinfo.is_funcptr():
            func_type = tinfo.get_pointed_object()
        elif tinfo.is_func():
            func_type = tinfo
        else:
            return None

        assert(func_type.is_func())
        func_type.get_func_details(func_data)

        return func_data


