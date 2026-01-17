import idaapi
import idc
import ida_hexrays
import ida_kernwin
import ida_tryblks
import ida_range
from ida_settings import PluginSettings
from ida_happy.miscutils import info

class HexraysMarkSEHHook(ida_hexrays.Hexrays_Hooks):
    """highlight the SEH try blocks"""
    active = True

    def __init__(self):
        super().__init__()

        ACTION_SEHHOOK_LIST = "happyida:SEHHookList"
        ACTION_SEHHOOK_TOGGLE = "happyida:SEHHookToggle"

        class UIMarkSEHHook(idaapi.UI_Hooks):
            def finish_populating_widget_popup(self, widget, popup):
                widget_type = idaapi.get_widget_type(widget)
                if widget_type != idaapi.BWN_PSEUDOCODE:
                    return

                ea = idc.get_screen_ea()
                if ea != idaapi.BADADDR and ida_tryblks.is_ea_tryblks(ea, ida_tryblks.TBEA_ANY):
                    idaapi.attach_action_to_popup(widget, popup, ACTION_SEHHOOK_LIST, None)

                idaapi.attach_action_to_popup(widget, popup, ACTION_SEHHOOK_TOGGLE, None)

        class SEHHookToggleHandler(idaapi.action_handler_t):
            def activate(self, ctx):
                HexraysMarkSEHHook.active = not HexraysMarkSEHHook.active
                vu = ida_hexrays.get_widget_vdui(ctx.widget)
                if vu:
                    vu.refresh_ctext()
                info("Toggle SEH block coloring: {}".format("Enable" if HexraysMarkSEHHook.active else "Disable"))
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        class SEHHookListHandler(idaapi.action_handler_t):
            def activate(self, ctx):
                ea = idc.get_screen_ea()
                func = idaapi.get_func(ea)
                tbks = ida_tryblks.tryblks_t()

                r = ida_range.range_t(func.start_ea, func.end_ea)
                ida_tryblks.get_tryblks(tbks, r)
                seh_list = HexraysMarkSEHHook.get_seh(ea, tbks)

                if len(seh_list) > 0:
                    chooser = SEHListChooser("Handler Locations", seh_list)
                    chooser.Show(True)
                else:
                    info("The selected address 0x{:X} is not in a try-catch block.".format(ea))
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        class SEHListChooser(idaapi.Choose):
            def __init__(self, title, data):
                super().__init__(title, [["Handler Location", 20]])
                self.data = data

            def OnGetSize(self):
                return len(self.data)

            def OnGetLine(self, n):
                return ["{:X}".format(self.data[n])]

            def OnRefresh(self, n):
                return n

            def OnClose(self):
                pass

            def OnSelectLine(self, n):
                selected_address = self.data[n]

                widget = ida_kernwin.find_widget("IDA View-A")
                ida_kernwin.activate_widget(widget, True)
                ida_kernwin.jumpto(selected_address)

        self.enable = self.is_pe_binary()
        settings = PluginSettings("HappyIDA")
        self.bgcolor = int(settings.get_setting("seh_bgcolor"), 16)

        if self.enable:
            self.actions = [
                idaapi.action_desc_t(ACTION_SEHHOOK_TOGGLE, "Toggle SEH block coloring", SEHHookToggleHandler(), None),
                idaapi.action_desc_t(ACTION_SEHHOOK_LIST, "List SEH handler blocks", SEHHookListHandler(), None),
            ]

            for action in self.actions:
                idaapi.register_action(action)

            self.ui_hook = UIMarkSEHHook()
            self.ui_hook.hook()

    def __del__(self):
        if self.enable:
            for action in self.actions:
                idaapi.unregister_action(action.name)

            self.ui_hook.unhook()

    def is_pe_binary(self):
        return idaapi.inf_get_filetype() == idaapi.f_PE

    def func_printed(self, cfunc):
        if not self.enable or not self.active:
            return 0

        func = idaapi.get_func(cfunc.entry_ea)
        tbks = ida_tryblks.tryblks_t()

        r = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tbks, r)

        self.apply_xray_filter(cfunc, tbks)
        return 0

    def apply_xray_filter(self, cfunc, tbks):
        pc = cfunc.get_pseudocode()

        ci = ida_hexrays.ctree_item_t()
        for line_idx in range(cfunc.hdrlines, len(pc)):
            sl = pc[line_idx]
            for char_idx in range(len(sl.line)):
                # colorize SEH try block
                if cfunc.get_line_item(sl.line, char_idx, True, None, ci, None) \
                   and len(self.get_seh(ci.it.ea, tbks)) > 0 \
                   and ci.it.op != ida_hexrays.cot_num:
                    sl.bgcolor = self.bgcolor
                    break

    @staticmethod
    def get_seh(ea, tbks):
        except_handler = []
        for tryblock in tbks:
            is_in_tryblock = False
            for rge in tryblock:
                if rge.contains(ea):
                    is_in_tryblock = True
                    break

            if is_in_tryblock:
                if not tryblock.is_cpp() and tryblock.is_seh():
                    ehs = tryblock.seh()
                    for eh in ehs:
                        except_handler.append(eh.start_ea)

        return except_handler
