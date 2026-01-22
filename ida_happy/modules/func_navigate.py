import idaapi
import idautils
import idc
import ida_hexrays
from ida_happy.undoutils import undoable, HandleStatus
from ida_happy.miscutils import info, error

class FuncChooser(idaapi.Choose):
    def __init__(self, title, cols, items):
        super(FuncChooser, self).__init__(title, cols, flags=idaapi.Choose.CH_MODAL)
        self.items = items
        self.icon  = 41

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        return True

class HexraysFuncNavigateHook(ida_hexrays.Hexrays_Hooks):
    """double click on vtable name to navigate to corresponding function"""
    def double_click(self, vdui, shift_state):
        if self.double_click_to_navigate(vdui):
            return 1

        return 0
    
    @undoable
    def double_click_to_navigate(self, vdui) -> HandleStatus:
        if not vdui.get_current_item(ida_hexrays.USE_MOUSE) or not vdui.in_ctree():
            return HandleStatus.NOT_HANDLED

        if vdui.item.citype == idaapi.VDI_EXPR and vdui.item.e.is_expr():
            expr = idaapi.tag_remove(vdui.item.e.print1(None))
            if "->" in expr:
                name = expr.split("->")[-1].strip()
                if "." in name:
                    name = name.split(".")[-1].strip()
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
                        return HandleStatus.NOT_HANDLED
        return HandleStatus.NOT_HANDLED