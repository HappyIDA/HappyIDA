import idaapi
import idc
import ida_hexrays
import ida_kernwin
import ida_tryblks
import ida_range
from ida_settings import get_current_plugin_setting
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

                seh_info = HexraysMarkSEHHook.parse_seh_info(tbks)
                seh_list = []
                for ranges, handlers in seh_info:
                    if any(s <= ea < e for s, e in ranges):
                        seh_list.extend(handlers)

                if len(seh_list) > 0:
                    chooser = SEHListChooser("SEH Handler Locations", seh_list)
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
                return ["0x{:X}".format(self.data[n])]

            def OnRefresh(self, n):
                return n

            def OnClose(self):
                pass

            def OnSelectLine(self, n):
                selected_address = self.data[n]
                def _jump():
                    widget = ida_kernwin.find_widget("IDA View-A")
                    ida_kernwin.activate_widget(widget, True)
                    ida_kernwin.jumpto(selected_address)
                ida_kernwin.execute_ui_requests((_jump,))

        self.enable = self.is_pe_binary()
        self.bgcolor = int(get_current_plugin_setting("seh_bgcolor"), 16)

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

        seh_info = self.parse_seh_info(tbks)
        self.apply_seh_filter(cfunc, seh_info)
        return 0

    def apply_seh_filter(self, cfunc, seh_info):
        if not seh_info:
            return

        pc = cfunc.get_pseudocode()
        all_ranges = [(s, e) for ranges, handlers in seh_info if handlers for s, e in ranges]

        def in_seh(ea):
            return any(s <= ea < e for s, e in all_ranges)

        for i in range(len(cfunc.treeitems)):
            item = cfunc.treeitems[i]
            if item.op != ida_hexrays.cot_num and in_seh(item.ea):
                _, y = cfunc.find_item_coords(item)
                if y is not None and y >= cfunc.hdrlines:
                    pc[y].bgcolor = self.bgcolor

    @staticmethod
    def parse_seh_info(tbks):
        result = []
        for tryblock in tbks:
            if not tryblock.is_cpp() and tryblock.is_seh():
                ranges = [(rge.start_ea, rge.end_ea) for rge in tryblock]
                handlers = [eh.start_ea for eh in tryblock.seh()]
                result.append((ranges, handlers))
        return result
