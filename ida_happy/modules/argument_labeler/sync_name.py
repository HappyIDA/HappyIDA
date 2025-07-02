import idaapi
import ida_hexrays
import ida_typeinf
import ida_kernwin
from ida_happy.undoutils import undoable, HandleStatus
from ida_happy.miscutils import error

class HexraysLabelNameSyncHook(ida_hexrays.Hexrays_Hooks):
    """double click to synchronize argument and label name"""
    def double_click(self, vdui, shift_state):
        if self.double_click_to_rename(vdui):
            return 1

        return 0

    @undoable
    def double_click_to_rename(self, vdui) -> HandleStatus:
        item = vdui.item
        if not item.is_citem():
            return HandleStatus.NOT_HANDLED

        # both "arg: var" are mapped to a citem_t node (the argument, not necessary a cot_var)
        if item.it.op != idaapi.cot_var:
            return HandleStatus.NOT_HANDLED

        # ensure user double clicked on the function argument
        pit = vdui.cfunc.body.find_parent_of(item.it)
        if not pit.is_expr() or pit.op != ida_hexrays.cot_call:
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
            return HandleStatus.FAILED

        func_ea = fcall.x.obj_ea
        tif = ida_typeinf.tinfo_t()
        if not idaapi.get_tinfo(tif, func_ea):
            error(f'Failed to retrieve the real function type for {hex(func_ea)}')
            return HandleStatus.FAILED

        func_data = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(func_data):
            error('Failed to retrieve function details.')
            return HandleStatus.FAILED

        lvar = item.e.v.getv()
        sel_name, success = ida_kernwin.get_highlight(vdui.ct)
        if not success:
            error('Failed to retrieve highlighted variable name')
            return HandleStatus.FAILED

        # for unk case, we want to set the variable name to function argument
        if func_data[argidx].name == '' or lvar.name == sel_name:
            # if arg and var name already the same
            if func_data[argidx].name == lvar.name:
                return HandleStatus.NOT_HANDLED

            func_data[argidx].name = lvar.name

            # Recreate the function type with the modified argument names
            if not tif.create_func(func_data):
                error('Failed to create the modified function type.')
                return HandleStatus.FAILED

            # Apply the modified type back to the function
            if not ida_typeinf.apply_tinfo(func_ea, tif, idaapi.TINFO_DEFINITE):
                error(f'Failed to apply the modified function type to {hex(func_ea)}.')
                return HandleStatus.FAILED
        else:
            if not vdui.rename_lvar(lvar, func_data[argidx].name, True):
                error(f'Failed to rename variable to "{func_data[argidx].name}"')
                return HandleStatus.FAILED

        # not working
        # vdui.refresh_ctext()
        # idaapi.refresh_idaview_anyway()
        # ida_hexrays.mark_cfunc_dirty(func_ea)
        vdui.refresh_view(False)
        return HandleStatus.HANDLED
