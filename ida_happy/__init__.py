import idaapi
import idautils
import idc
import ida_hexrays
import ida_typeinf
import ida_kernwin
from ida_settings import PluginSettings
from .modules import (
    HexraysParamLabelHook,
    HexraysLabelEditHook,
    HexraysLabelNameSyncHook,
    HexraysLabelTypeSyncHook,
    HexraysFuncNavigateHook,
    HexraysRustStringHook,
    HexraysMarkSEHHook,
    HexraysRebuildSEHHook
)
from .miscutils import info, error, parse_type

try:
    from PySide6.QtWidgets import QApplication
except ImportError:
    from PyQt5.QtWidgets import QApplication

ACTION_HX_COPYNAME = "happyida:hx_copyname"
ACTION_HX_PASTENAME = "happyida:hx_pastename"
ACTION_HX_COPYTYPE = "happyida:hx_copytype"
ACTION_HX_PASTETYPE = "happyida:hx_pastetype"
ACTION_HX_EDITTYPE = "happyida:hx_edittype"

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def get_clip_text():
    return QApplication.clipboard().text()

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

        if t is None:
            return

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
        self.hook_manager = None
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

            # Register hexrays hooks (gated by settings, default enabled)
            settings = PluginSettings("HappyIDA")
            enable_param_label = settings.get_setting("enable_param_label")
            hook_configs = [
                (HexraysParamLabelHook, enable_param_label),
                (HexraysLabelEditHook, enable_param_label and settings.get_setting("enable_param_edit")),
                (HexraysLabelNameSyncHook, enable_param_label and settings.get_setting("enable_param_sync_name")),
                (HexraysLabelTypeSyncHook, enable_param_label and settings.get_setting("enable_param_sync_type")),
                (HexraysFuncNavigateHook, settings.get_setting("enable_func_navigate")),
                (HexraysRustStringHook, settings.get_setting("enable_rust_string")),
                (HexraysMarkSEHHook, settings.get_setting("enable_seh_highlight")),
                (HexraysRebuildSEHHook, settings.get_setting("enable_seh_rebuild")),
            ]
            
            self.hx_hooks = []
            for hook_class, is_enabled in hook_configs:
                if not is_enabled:
                    info(f"Hook {hook_class.__name__} is disabled in settings")
                    continue

                hook = hook_class()
                hook.hook()
                self.hx_hooks.append(hook)

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
