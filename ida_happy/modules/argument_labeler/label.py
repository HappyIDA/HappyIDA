import idaapi
import ida_hexrays
import ida_lines
import ida_typeinf
import ida_kernwin
from ida_happy.miscutils import tag_text, info

class HexraysToggleParamLabelAction(idaapi.action_handler_t):
    ACTION_NAME = "happyida:hx_toggle_param_label"

    def activate(self, ctx):
        HexraysParamLabelHook.active = not HexraysParamLabelHook.active
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if vu:
            vu.refresh_ctext()
        info("Toggle parameter labels: {}".format("Enable" if HexraysParamLabelHook.active else "Disable"))
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET

class HexraysParamLabelHook(ida_hexrays.Hexrays_Hooks):
    """make decompiler display swift-like parameter label"""
    active = True

    def func_printed(self, cfunc):
        if not self.active:
            return 0
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
                            args = self.get_func_params(ci.e)
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

    def get_func_params(self, fcall):
        func_ea = fcall.x.obj_ea

        # function pointer call (not IAT functions)
        if func_ea == idaapi.BADADDR:
            if fcall.x.op != idaapi.cot_var:
                return None

            tif = fcall.x.v.getv().tif
        else:
            tif = ida_typeinf.tinfo_t()
            if not idaapi.get_tinfo(tif, func_ea):
                return None

        # handle function pointer (IAT function call)
        if tif.is_funcptr():
            pi = ida_typeinf.ptr_type_data_t()
            if not tif.get_ptr_details(pi):
                return None
            tif = pi.obj_type

        func_data = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(func_data):
            return None

        return func_data
