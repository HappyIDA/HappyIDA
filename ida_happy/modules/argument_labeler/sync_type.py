import idaapi
import idc
import ida_hexrays
import ida_typeinf
import ida_kernwin
from ida_happy.undoutils import undoable, HandleStatus
from ida_happy.miscutils import info, error

class HexraysLabelTypeSyncHook(ida_hexrays.Hexrays_Hooks):
    """double click to synchronize argument and label type"""
    def double_click(self, vdui, shift_state):
        if self.double_click_to_retype(vdui):
            return 1

        return 0

    @undoable
    def double_click_to_retype(self, vdui) -> HandleStatus:
        item = vdui.item
        if not item.is_citem():
            return HandleStatus.NOT_HANDLED

        e = item.e

        # sanity check
        if e.op != ida_hexrays.cot_cast:
            return HandleStatus.NOT_HANDLED

        # check if cursor located inside type cast expr
        sel_name, success = ida_kernwin.get_highlight(vdui.ct)
        if not success:
            error('Failed to retrieve highlighted variable name')
            return HandleStatus.NOT_HANDLED

        # * will be dropped, so at least check the prefix
        if not str(e.type).startswith(sel_name):
            return HandleStatus.NOT_HANDLED

        # CASE: (type)var
        if (e.op == ida_hexrays.cot_cast and
            e.x and e.x.op == ida_hexrays.cot_var):
            func = idaapi.get_func(idaapi.get_screen_ea())
            lvar = e.x.v.getv()

            self.retype_pseudocode_var(func.start_ea, lvar.name, e.type)
            vdui.refresh_view(True)
            return HandleStatus.HANDLED

        # CASE: (type *)&var->field[const idx]
        # TODO: support *(int *)&this[4].gap4[12] = 1
        # TODO: support *(int *)&this->field[2] = 1
        if (e.op == ida_hexrays.cot_cast and
            e.x and e.x.op == ida_hexrays.cot_ref and
            e.x.x and e.x.x.op == ida_hexrays.cot_idx and
            e.x.x.x and e.x.x.x.op == ida_hexrays.cot_memptr and
            e.x.x.y and e.x.x.y.op == ida_hexrays.cot_num and
            e.x.x.x.x and e.x.x.x.x.op == ida_hexrays.cot_var):

            to_byte = lambda n: n // 8
            cast_type = e.type.get_pointed_object()
            lvar = e.x.x.x.x.v.getv()
            tif = lvar.type().get_pointed_object()
            udm = self.get_member(tif, e.x.x.x.m)
            if not udm:
                error(f'Unable to get member of offset {e.x.x.x.m}')
                return HandleStatus.HANDLED

            arr_idx = e.x.x.y.n._value
            from_offset = to_byte(udm.offset) + udm.type.get_ptrarr_objsize() * arr_idx
            to_offset = from_offset + cast_type.get_size()

            # first deal with the cropped array
            spare_bytes = from_offset - to_byte(udm.offset)
            array_size = spare_bytes // udm.type.get_ptrarr_objsize()

            arr_tif = udm.type.get_array_element()
            arr_tif.create_array(arr_tif, array_size)

            # if it's a user defined field, delete it (will make it a gapXXXXX char array)
            # NOTE: always revert after this
            idc.del_struc_member(tif.get_tid(), to_byte(udm.offset))

            # if it's gapXXXXX, add member will fail due to duplicate name
            if not udm.name.startswith('gap'):
                ret = idc.add_struc_member(tif.get_tid(), udm.name, to_byte(udm.offset), 0, -1, arr_tif.get_size())
                if ret:
                    error('Failed to crop array')
                    return HandleStatus.FAILED

            # sequentially delete all structures preceding the to_offset
            udmidx = tif.find_udm(udm, ida_typeinf.STRMEM_NEXT)
            while udmidx >= 0 and to_offset >= to_byte(udm.offset + udm.size):
                idc.del_struc_member(tif.get_tid(), to_byte(udm.offset))
                udmidx = tif.find_udm(udm, ida_typeinf.STRMEM_NEXT)

            # the end exceeds the structure size
            # or falls into padding area, but we already got the next udm
            if udmidx < 0 or to_offset <= to_byte(udm.offset):
                pass
            # we are inside a bytes array -> nobody cares
            elif udm.type.is_array() and udm.type.get_ptrarr_objsize() == 1:
                idc.del_struc_member(tif.get_tid(), to_byte(udm.offset))
            else:
                error('Retype conflicted with other structure')
                return HandleStatus.FAILED

            # ida is smart enough to let us add into any offset we want without alignment (will auto set aligned(1))
            # we can only add into the free padding space
            newname = ida_kernwin.ask_str('', ida_kernwin.HIST_IDENT, 'Please enter the field name')
            if not newname:
                error('Failed to receive the new structure field name')
                return HandleStatus.FAILED

            # TODO: we should handle the case where the cast type is not a structure: `*(_DWORD *)&this->gap10[8]`
            ret = idc.add_struc_member(tif.get_tid(), newname, from_offset, idaapi.FF_STRUCT, cast_type.get_tid(), cast_type.get_size())
            if ret:
                error('Failed to add new structure field')
                return HandleStatus.FAILED

            info('Retyping successfully')
            vdui.refresh_view(False)

            return HandleStatus.HANDLED

        return HandleStatus.NOT_HANDLED

    def retype_pseudocode_var(self, func_ea, varname, tinfo):
        # Rename variable to make it into user modified list
        ida_hexrays.rename_lvar(func_ea, varname, varname)

        # Locate user modified variable
        loc = ida_hexrays.lvar_locator_t()
        uservec = ida_hexrays.lvar_uservec_t()
        ida_hexrays.restore_user_lvar_settings(uservec, func_ea)
        ida_hexrays.locate_lvar(loc, func_ea, varname)
        saved_info = uservec.find_info(loc)

        # Set the type & apply it to idb
        saved_info.type = tinfo
        ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_TYPE, saved_info)

    def get_member(self, tif, offset):
        if not tif.is_struct():
            return None

        udm = ida_typeinf.udm_t()
        udm.offset = offset * 8
        idx = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
        if idx != -1:
            return udm

        return None
