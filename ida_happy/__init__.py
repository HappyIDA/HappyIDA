import idaapi
import idautils
import idc
import ida_hexrays
import ida_typeinf
import ida_kernwin
import ida_lines
import ida_segment
import ida_bytes
from .undoutils import undoable, HandleStatus

from PyQt5.QtWidgets import QApplication

ACTION_HX_COPYNAME = "happyida:hx_copyname"
ACTION_HX_PASTENAME = "happyida:hx_pastename"
ACTION_HX_COPYTYPE = "happyida:hx_copytype"
ACTION_HX_PASTETYPE = "happyida:hx_pastetype"
ACTION_HX_EDITTYPE = "happyida:hx_edittype"

def info(msg):
    print(f'[HappyIDA] {msg}')

def error(msg):
    print(f'[HappyIDA] Error: {msg}')

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def get_clip_text():
    return QApplication.clipboard().text()

def parse_type(tif, typename):
    typename += " ;"
    # we have to distinguish None from empty string, since parse_decl returns the parsed variable name
    if ida_typeinf.parse_decl(tif, ida_typeinf.get_idati(), typename, ida_typeinf.PT_SIL) == None:
        error(f"Unable to parse declaration: {typename}")
        return False

    return True

def tag_text(text, tag):
    # address tagging doesn't have COLOR_OFF pair
    FMT = '%c%c%' + '0%dX' % ida_lines.COLOR_ADDR_SIZE + '%s'
    return FMT % (ida_lines.COLOR_ON, ida_lines.COLOR_ADDR, tag, text)

class FuncChooser(idaapi.Choose):
    def __init__(self, title, cols, items):
        super(FuncChooser, self).__init__(title, cols, flags=idaapi.Choose.CH_MODAL)
        self.items = items
        self.icon  = 5

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        return True
    
class HexraysFuncLabelHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()

        # decompile view won't handle 'N' keyboard event, so we have to hook it here
        class UIFuncArgsHooks(ida_kernwin.UI_Hooks):
            def preprocess_action(self, action):
                if HexraysFuncLabelHook.label_actions(action):
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
        # drop A: [A]->B
        # (the parent of the selection is B cot_memptr)
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
            return HandleStatus.NOT_HANDLED

        func_ea = fcall.x.obj_ea
        tif = ida_typeinf.tinfo_t()
        if not idaapi.get_tinfo(tif, func_ea):
            error(f'Failed to retrieve the real function type for {hex(func_ea)}')
            return HandleStatus.NOT_HANDLED

        func_data = ida_typeinf.func_type_data_t()
        if not tif.get_func_details(func_data):
            error('Failed to retrieve function details.')
            return HandleStatus.NOT_HANDLED

        sel_name, success = ida_kernwin.get_highlight(vdui.ct)
        if not success:
            error('Failed to retrieve highlighted variable name')
            return HandleStatus.NOT_HANDLED

        # drop any non-argument named variables
        # A: ...[B]...
        if func_data[argidx].name != sel_name and \
        not (func_data[argidx].name == '' and sel_name == 'unk'):
            return HandleStatus.NOT_HANDLED

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
        if not ida_typeinf.apply_tinfo(func_ea, tif, idaapi.TINFO_DEFINITE):
            error(f'Failed to apply the modified function type to {hex(func_ea)}.')
            return HandleStatus.FAILED

        vdui.refresh_view(False)
        return HandleStatus.HANDLED

class HexraysDoubleClickHook(ida_hexrays.Hexrays_Hooks):
    def double_click(self, vdui, shift_state):
        if self.double_click_to_rename(vdui):
            return 1

        if self.double_click_to_retype(vdui):
            return 1

        if self.double_click_to_navigate(vdui):
            return 1
        
        return 0

    @undoable
    def double_click_to_rename(self, vdui) -> HandleStatus:
        item = vdui.item
        if not item.is_citem():
            return HandleStatus.NOT_HANDLED

        # both "arg: var" are mapped to a citem_t node (the argument, not necessary a cot_var)
        if item.it.op != idaapi.cot_var:
            return 0

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
            return HandleStatus.FAILED

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
                return HandleStatus.FAILED

            arr_idx = e.x.x.y.n._value
            from_offset = to_byte(udm.offset) + udm.type.get_ptrarr_objsize() * arr_idx
            to_offset = from_offset + cast_type.get_size()

            # first deal with the cropped array
            spare_bytes = from_offset - to_byte(udm.offset)
            array_size = spare_bytes // udm.type.get_ptrarr_objsize()

            arr_tif = udm.type.get_array_element()
            arr_tif.create_array(arr_tif, array_size)

            # if it's a user defined field, delete it (will make it a gapXXXXX char array)
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

    @undoable
    def double_click_to_navigate(self, vdui) -> HandleStatus:
        
        if not vdui.get_current_item(ida_hexrays.USE_MOUSE) or not vdui.in_ctree():
            return HandleStatus.NOT_HANDLED

        if vdui.item.citype == idaapi.VDI_EXPR and vdui.item.e.is_expr():
            expr = idaapi.tag_remove(vdui.item.e.print1(None))
            if "->" in expr:
                name = expr.split("->")[-1].strip()
                addr = idc.get_name_ea_simple(name)
                if addr != idaapi.BADADDR:
                    idc.jumpto(addr)
                    return HandleStatus.HANDLED
                else:
                    funcs = [ (ea, idc.get_name(ea, idc.GN_VISIBLE | idc.GN_DEMANGLED)) for ea in idautils.Functions() ]
                    #TODO: user can limit output size
                    #TODO: make this fuzzy search, like abc::vector will also match bac::cde::vector
                    matches = [ pair for pair in funcs if name in pair[1] ]
                    if matches:
                        items = [(func_name, "%08X" % ea) for (ea ,func_name) in matches]
                        cols = [
                            ["Name",    40 | idaapi.Choose.CHCOL_PLAIN],
                            ["Address", 16 | idaapi.Choose.CHCOL_HEX],
                        ]
                        chooser = FuncChooser("Function matches for '%s'" % name, cols, items)
                        idx = chooser.Show(True)
                        if idx not in (idaapi.Choose.NO_SELECTION, idaapi.Choose.EMPTY_CHOOSER):
                            sel_name, sel_addr_str = items[idx]
                            idc.jumpto(int(sel_addr_str, 16))
                            info("Jump to '%s'" % sel_name)
                            return HandleStatus.HANDLED
                    else:
                        error("No close matches for '%s'" % name)
                        return HandleStatus.FAILED
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

class HexraysRustStringHook(ida_hexrays.Hexrays_Hooks):
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

class HexraysParamLabelHook(ida_hexrays.Hexrays_Hooks):
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

class HexraysCopyNameAction(idaapi.action_handler_t):
    def activate(self, ctx):
        return self.copy_name(ctx)

    def copy_name(self, ctx):
        highlight = idaapi.get_highlight(idaapi.get_current_viewer())
        name = highlight[0] if highlight else None
        if name:
            copy_to_clip(name)
            info(f"{name} has been copied to clipboard")

        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET

class HexraysPasteNameAction(idaapi.action_handler_t):
    def activate(self, ctx):
        return self.paste_name(ctx)

    def paste_name(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)

        item = vdui.item
        if item.is_citem() and item.it.is_expr():
            new_name = get_clip_text()
            if not new_name:
                info("Clipboard is empty or could not read clipboard.")
                return 0
            self.rename_item(vdui, item, new_name)

        elif item.citype == ida_hexrays.VDI_FUNC:
            func_addr = item.f.entry_ea
            new_name = get_clip_text()
            idaapi.set_name(func_addr, new_name, idaapi.SN_NOWARN)
            vdui.refresh_view(True)

        elif item.l:
            lvar = item.l
            new_name = get_clip_text()
            if vdui.rename_lvar(lvar, new_name, True):
                info(f"Renamed variable to '{new_name}'")
                vdui.refresh_ctext(True)
            else:
                error(f"Failed to rename variable to '{new_name}'")
                return 0

        return 1

    def rename_item(self, vdui, item, new_name):
        if item.e.v is not None:
            lvar = item.e.v.getv()
            if vdui.rename_lvar(lvar, new_name, True):
                info(f"Renamed variable to '{new_name}'")
            else:
                # handle the case if rename failed
                info(f"Failed to rename variable to '{new_name}', rename it manually")
                vdui.ui_rename_lvar(lvar)

        elif item.e.obj_ea != idaapi.BADADDR:
            idc.set_name(item.e.obj_ea, new_name, idc.SN_NOWARN)
            info(f"Renamed name of {hex(item.e.obj_ea)} to '{new_name}'")

        elif item.it.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
            if not self.rename_member(item, new_name):
                return 0

        else:
            error("No variable under cursor or not a valid lvar item.")
            return 0

        vdui.refresh_ctext()

    def rename_member(self, item, new_name):
        # Prepare buffers
        udm_data = idaapi.udm_t()
        parent_tinfo = idaapi.tinfo_t()
        # Assuming item, udm_data, and parent_tinfo are defined
        index = item.get_udm(udm_data, parent_tinfo, None)

        if index == -1:
            error("Failed to get UDM information.")
            return 0

        # Print information
        return self.rename_member_name(parent_tinfo, udm_data.offset, new_name)

    def rename_member_name(self, tinfo, offset, new_name):
        # Check if the type is a structure
        if not tinfo.is_struct():
            error("Provided type is not a structure")
            return None

        # Get the structure ID
        struct_type_data = idaapi.udt_type_data_t()

        if not tinfo.get_udt_details(struct_type_data):
            error("Failed to get UDT details")
            return None

        # Iterate through the members to find the one at the specified offset
        for idx, member in enumerate(struct_type_data):
            if member.offset == offset:
                if member.can_rename():
                    member.name = new_name
                    if tinfo.rename_udm(idx, new_name) == 0:
                        info(f"Member at offset {offset} renamed to {new_name}")
                        return new_name
                    else:
                        error(f"Failed to rename member at offset {offset}")
                        return None

        error("No member found at the specified offset")
        return None

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET

class HexraysCopyTypeAction(idaapi.action_handler_t):
    def activate(self, ctx):
        return self.copy_type(ctx)

    def copy_type(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        item = vdui.item
        if not item.is_citem():
            return 0

        if not item.it.is_expr():
            error("No variable under cursor or not a valid lvar item.")
            return 0

        if item.e.v is not None:
            lvar = item.e.v.getv()
            type_name = lvar.tif.dstr()
            copy_to_clip(type_name)
            info(f"{type_name} has been copied to clipboard")

        elif item.it.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
            udm_data = idaapi.udm_t()
            parent_tinfo = idaapi.tinfo_t()
            item.get_udm(udm_data, parent_tinfo, None)
            type_name = udm_data.type.dstr()
            copy_to_clip(type_name)
            info(f"{type_name} has been copied to clipboard")

        elif item.e.obj_ea != idaapi.BADADDR:
            type_name = idc.get_type(item.e.obj_ea)
            copy_to_clip(type_name)
            info(f"{type_name} has been copied to clipboard")

        else:
            error("Nothing")
            return 0

        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET

class HexraysPasteTypeAction(idaapi.action_handler_t):
    def activate(self, ctx):
        return self.paste_type(ctx)

    def paste_type(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)

        item = vdui.item
        if not item.is_citem():
            return 0

        if not item.it.is_expr():
            error("No variable under cursor or not a valid lvar item.")
            return 0

        if item.e.v is not None:
            lvar = item.e.v.getv()
            if not self.assign_type_to_lvar(vdui, lvar):
                return 0

        elif item.e.obj_ea != idaapi.BADADDR:
            type_name = get_clip_text()
            if not idc.SetType(item.e.obj_ea, type_name + " ;"):
                error("Failed to set type: {type_name};")
                return 0

            info(f"{type_name} has been assigned to variable")
            vdui.refresh_view(True)

        elif item.it.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
            udm_data = idaapi.udm_t()
            parent_tinfo = idaapi.tinfo_t()
            item.get_udm(udm_data, parent_tinfo, None)

            # Get the udm array
            struct_type_data = idaapi.udt_type_data_t()
            if not parent_tinfo.get_udt_details(struct_type_data):
                error("Failed to get UDT details")
                return 0

            # find the udm index in udm array
            # TODO: item.get_udm actually return the index
            index = 0
            for member in struct_type_data:
                if member.offset == udm_data.offset:
                    break
                index += 1

            # Create new type
            type_name = get_clip_text()
            new_tif = idaapi.tinfo_t()
            if not new_tif.get_named_type(ida_typeinf.get_idati(), type_name):
                if not parse_type(new_tif, type_name):
                    return 0

            parent_tinfo.set_udm_type(index, new_tif)
            info(f"{type_name} has been assigned to variable")

        else:
            error("Nothing")
            return 0

        return 1

    def assign_type_to_lvar(self, vdui, lvar):
        new_tif = idaapi.tinfo_t()
        typename = get_clip_text()
        if not new_tif.get_named_type(ida_typeinf.get_idati(), typename):
            if not parse_type(new_tif, typename):
                return False

        lsi = ida_hexrays.lvar_saved_info_t()
        lsi.ll = lvar
        lsi.type = new_tif
        if not ida_hexrays.modify_user_lvar_info(vdui.cfunc.entry_ea, ida_hexrays.MLI_TYPE, lsi):
            error(f"Could not modify lvar type for {lvar.name}")
            return False

        info(f"{new_tif} has been assigned to variable")
        vdui.refresh_view(True)
        return True

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET

# TODO: fix error: "Type info leak has been detected and fixed (refcnt=2; idx=48)"
class HexraysEditTypeAction(idaapi.action_handler_t):
    ACTION_DOEDIT = "happyida:doedittype"
    def __init__(self):
        super().__init__()

        # internal subclass only for triggering the action
        class menu_action_handler_t(idaapi.action_handler_t):
            def __init__(self):
                idaapi.action_handler_t.__init__(self)
                self.ordinal = 0

            def activate(self, ctx):
                ida_kernwin.open_loctypes_window(self.ordinal)
                idautils.ProcessUiActions("TilEditType")

                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        # ugly hack to make it work
        self.handler = menu_action_handler_t()
        self.action = idaapi.action_desc_t(HexraysEditTypeAction.ACTION_DOEDIT, "Really do edit", self.handler, None, None, 0x10)
        idaapi.register_action(self.action)

    def __del__(self):
        idaapi.unregister_action(self.action.name)

    def activate(self, ctx):
        return self.edit_type(ctx)

    def edit_type(self, ctx):
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)

        item = vdui.item
        if not item.is_citem():
            return 0

        if not item.it.is_expr():
            error("No variable under cursor or not a valid lvar item.")
            return 0

        tif = None

        if item.e.v is not None:
            tif = item.e.v.getv().type()

        elif item.it.op in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
            udm_data = idaapi.udm_t()
            parent_tinfo = idaapi.tinfo_t()
            item.get_udm(udm_data, parent_tinfo, None)
            tif = udm_data.type

        elif item.e.obj_ea != idaapi.BADADDR:
            type_name = idc.get_type(item.e.obj_ea)
            new_tif = idaapi.tinfo_t()
            if not new_tif.get_named_type(ida_typeinf.get_idati(), type_name):
                if not parse_type(new_tif, type_name):
                    return 0

            tif = new_tif

        self._edit_type(tif)
        return 1

    def _edit_type(self, t):
        while t.is_ptr_or_array():
            t.remove_ptr_or_array()

        ordinal = t.get_ordinal()
        if ordinal != 0:
            """
            We have to put the following line into a new action
            not sure why, because if we run the following script in script window, it's fine
            but if we put them here, we'll land on other structure then edit the wrong type.
            ```
            ida_kernwin.open_loctypes_window(ordinal)
            idautils.ProcessUiActions("TilEditType")
            ```
            """
            self.handler.ordinal = ordinal
            idautils.ProcessUiActions(HexraysEditTypeAction.ACTION_DOEDIT)

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET

        return idaapi.AST_DISABLE_FOR_WIDGET

class HappyIDAPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "HappyIDA"
    help = ""
    wanted_name = "HappyIDA"
    wanted_hotkey = ""

    def init(self):
        self.hexrays_inited = False
        self.registered_actions = []
        self.registered_hx_actions = []

        # Add hexrays ui callback
        if idaapi.init_hexrays_plugin():
            addon = idaapi.addon_info_t()
            addon.id = "tw.happyida.happyida"
            addon.name = "HappyIDA"
            addon.producer = "HappyIDA"
            addon.url = "https://github.com/HappyIDA/HappyIDA"
            addon.version = "0.9.0"
            idaapi.register_addon(addon)

            hx_actions = [
                idaapi.action_desc_t(ACTION_HX_COPYNAME, "Copy name", HexraysCopyNameAction(), "C"),
                idaapi.action_desc_t(ACTION_HX_PASTENAME, "Paste name", HexraysPasteNameAction(), "V"),
                idaapi.action_desc_t(ACTION_HX_COPYTYPE, "Copy type", HexraysCopyTypeAction(), "Ctrl-Alt-C"),
                idaapi.action_desc_t(ACTION_HX_PASTETYPE, "Paste type", HexraysPasteTypeAction(), "Ctrl-Alt-V"),
                idaapi.action_desc_t(ACTION_HX_EDITTYPE, "Edit type", HexraysEditTypeAction(), "E"),
            ]
            for action in hx_actions:
                idaapi.register_action(action)
                self.registered_hx_actions.append(action.name)

            # Register hexrays hooks
            self.hx_hooks = [
                HexraysParamLabelHook(),
                HexraysRustStringHook(),
                HexraysDoubleClickHook(),
                HexraysFuncLabelHook()
            ]
            for hook in self.hx_hooks:
                hook.hook()

            self.hexrays_inited = True

        info('Plugin initialized')
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)

        if self.hexrays_inited:
            # Unregister hexrays actions
            for action in self.registered_hx_actions:
                idaapi.unregister_action(action)

            # Unregister hexrays hook
            for hook in self.hx_hooks:
                hook.unhook()

            # TODO: what is this?
            idaapi.term_hexrays_plugin()

        info('Plugin terminated')