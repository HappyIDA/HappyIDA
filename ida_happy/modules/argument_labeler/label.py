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
        ccode = cf.get_pseudocode()

        line_calls = {}
        for item in cf.treeitems:
            if not item.is_expr() or item.op != ida_hexrays.cot_call:
                continue
            _, y = cf.find_item_coords(item)
            if y is None or y < cf.hdrlines:
                continue
            if y not in line_calls:
                line_calls[y] = []
            line_calls[y].append(item.cexpr)

        for line_idx, calls in line_calls.items():
            sl = ccode[line_idx]
            target = {}

            for call in calls:
                if call.x.op == ida_hexrays.cot_helper:
                    #TODO: build known helper dictionary
                    continue
                args = self.get_func_params(call)
                if not args:
                    continue
                for a, arg in zip(call.a, args):
                    name = arg.name
                    # filter same name cases
                    # TODO: add support to hide tag if A: B->A ? (should filter A: [*&]B->A cases / or not? no sense to do that actually...)
                    if a.dstr() == name:
                        continue
                    idx = a.index
                    tag = a.print1(None)
                    target[tag] = (idx, name)

            for item_str, (index, name) in target.items():
                if item_str not in sl.line:
                    continue
                if name == '':
                    name = "unk"
                label = ida_lines.COLSTR(name, ida_lines.SCOLOR_HIDNAME)
                tagged = tag_text(label, index)
                sl.line = sl.line.replace(item_str, tagged + ": " + item_str)

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
