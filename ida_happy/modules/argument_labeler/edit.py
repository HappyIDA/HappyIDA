import idaapi
import ida_hexrays
import ida_typeinf
import ida_kernwin
from ida_happy.undoutils import undoable, HandleStatus
from ida_happy.miscutils import info, error, parse_type

class HexraysLabelEditHook(ida_hexrays.Hexrays_Hooks):
    """retype or rename function parameter label"""
    def __init__(self):
        super().__init__()

        # decompile view won't handle 'N' keyboard event, so we have to hook it here
        class UIFuncArgsHooks(ida_kernwin.UI_Hooks):
            def preprocess_action(self, action):
                if HexraysLabelEditHook.label_actions(action):
                    return 1

                return 0

        self.ui_hooks = UIFuncArgsHooks()
        self.ui_hooks.hook()

    def __del__(self):
        self.ui_hooks.unhook()

    def keyboard(self, vu, key_code, shift_state):
        if key_code == ord('Y') and self.label_actions('hx:SetType'):
            return 1

        return 0

    # TODO: fix `sub_1004FC80(this: internal->gapB00);` sometimes will unable to change the field name (this callback unintentionally triggered
    # the order here makes both obj.method() and cls.method() works
    @staticmethod
    @undoable
    def label_actions(action):
        if action not in ['hx:Rename', 'hx:SetType']:
            return HandleStatus.NOT_HANDLED

        widget = ida_kernwin.get_current_widget()
        vdui = idaapi.get_widget_vdui(widget)
        item = vdui.item

        if not item.is_citem():
            return HandleStatus.NOT_HANDLED

        # check if our cursor locate inside the function call
        # drop: [A]->B and [F](a, b, c)
        # (the parent of the selection is B cot_memptr)
        pit = vdui.cfunc.body.find_parent_of(item.it)
        if not pit.is_expr() or pit.op != ida_hexrays.cot_call or pit.cexpr.x == item.e:
            return HandleStatus.NOT_HANDLED

        fcall = pit.cexpr
        argidx = 0
        for i in range(len(fcall.a)):
            arg = fcall.a[i]
            if arg.index == item.it.index:
                argidx = i
                break
        else:
            error('Unable to find the selected ctree node')
            return HandleStatus.NOT_HANDLED

        func_ea = fcall.x.obj_ea

        # function pointer call (not IAT functions)
        if func_ea == idaapi.BADADDR:
            if fcall.x.op != idaapi.cot_var:
                error('Unexpected function call')
                return HandleStatus.FAILED

            tif = fcall.x.v.getv().tif
        else:
            # NOTE: when working with large IDBs,
            # we often can't get type information without decompiling functions first.
            func = idaapi.get_func(func_ea)
            ida_hexrays.decompile_func(func)

            tif = ida_typeinf.tinfo_t()
            if not idaapi.get_tinfo(tif, func_ea):
                error(f'Failed to retrieve the function type for {hex(func_ea)}')
                return HandleStatus.NOT_HANDLED

        # handle function pointer (IAT function call)
        if tif.is_funcptr():
            pi = ida_typeinf.ptr_type_data_t()
            if not tif.get_ptr_details(pi):
                error(f'Failed to retrieve the function pointer type for {hex(func_ea)}')
                return HandleStatus.NOT_HANDLED
            tif = pi.obj_type

        func_data = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(func_data):
            error('Failed to retrieve function details.')
            return HandleStatus.NOT_HANDLED

        ret = ida_kernwin.get_highlight(vdui.ct)
        if not ret:
            error('Failed to retrieve highlighted variable name')
            return HandleStatus.NOT_HANDLED

        sel_name = ret[0]

        # drop any non-argument named variables
        # A: ...[B]...
        if func_data[argidx].name != sel_name and \
           not (func_data[argidx].name == '' and sel_name == 'unk'):
            return HandleStatus.NOT_HANDLED

        if func_ea == idaapi.BADADDR:
            info('Function pointer calls are not supported yet')
            return HandleStatus.HANDLED

        # TODO: we somehow cannot handle A: B->[A] since we mapped both variable to the same item
        # should we untag it if they're the same?

        if action == 'hx:Rename':
            newname = ida_kernwin.ask_str(func_data[argidx].name, ida_kernwin.HIST_IDENT, 'Please enter variable name')
            if not newname:
                return HandleStatus.HANDLED

            func_data[argidx].name = newname
        else:
            newtype = ida_kernwin.ask_str(func_data[argidx].type.dstr(), ida_kernwin.HIST_TYPE, 'Please enter the type declaration')
            if not newtype:
                return HandleStatus.HANDLED

            newtif = ida_typeinf.tinfo_t()
            if not parse_type(newtif, newtype):
                return HandleStatus.FAILED

            func_data[argidx].type = newtif

        # Recreate the function type with the modified argument names
        if not tif.create_func(func_data):
            error('Failed to create the modified function type.')
            return HandleStatus.FAILED

        # Apply the modified type back to the function
        # NOTE: function pointer in IAT will be directly set type as a function
        if not ida_typeinf.apply_tinfo(func_ea, tif, idaapi.TINFO_DEFINITE):
            error(f'Failed to apply the modified function type to {hex(func_ea)}.')
            return HandleStatus.FAILED

        vdui.refresh_view(False)
        return HandleStatus.HANDLED
