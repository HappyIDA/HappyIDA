import idaapi
import idautils
import idc
import ida_hexrays
import ida_typeinf
import ida_kernwin
from ida_settings import get_current_plugin_setting
from .modules import (
    HexraysParamLabelHook, HexraysToggleParamLabelAction,
    HexraysLabelEditHook,
    HexraysLabelNameSyncHook,
    HexraysLabelTypeSyncHook,
    HexraysFuncNavigateHook,
    HexraysRustStringHook,
    HexraysMarkSEHHook,
    HexraysRebuildSEHHook
)
from .actions import (
    CopyEAAction,
    HexraysCopyNameAction,
    HexraysPasteNameAction,
    HexraysCopyTypeAction,
    HexraysPasteTypeAction,
    HexraysEditTypeAction,
    HexraysCopyEAAction,
)
from .miscutils import info, error, parse_type


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

        actions = [
            idaapi.action_desc_t(CopyEAAction.ACTION_NAME, "Copy address", CopyEAAction(), "W"),
        ]
        for action in actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

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
                idaapi.action_desc_t(HexraysCopyNameAction.ACTION_NAME, "Copy name", HexraysCopyNameAction(), "C"),
                idaapi.action_desc_t(HexraysPasteNameAction.ACTION_NAME, "Paste name", HexraysPasteNameAction(), "V"),
                idaapi.action_desc_t(HexraysCopyTypeAction.ACTION_NAME, "Copy type", HexraysCopyTypeAction(), "Ctrl-Alt-C"),
                idaapi.action_desc_t(HexraysPasteTypeAction.ACTION_NAME, "Paste type", HexraysPasteTypeAction(), "Ctrl-Alt-V"),
                idaapi.action_desc_t(HexraysEditTypeAction.ACTION_NAME, "Edit type", HexraysEditTypeAction(), "E"),
                idaapi.action_desc_t(HexraysCopyEAAction.ACTION_NAME, "Copy address", HexraysCopyEAAction(), "W"),
                idaapi.action_desc_t(HexraysToggleParamLabelAction.ACTION_NAME, "Toggle parameter label", HexraysToggleParamLabelAction(), "`"),
            ]
            for action in hx_actions:
                idaapi.register_action(action)
                self.registered_hx_actions.append(action.name)

            # Register hexrays hooks (gated by settings, default enabled)
            enable_param_label = get_current_plugin_setting("enable_param_label")
            hook_configs = [
                (HexraysParamLabelHook, enable_param_label),
                (HexraysLabelEditHook, enable_param_label and get_current_plugin_setting("enable_param_edit")),
                (HexraysLabelNameSyncHook, enable_param_label and get_current_plugin_setting("enable_param_sync_name")),
                (HexraysLabelTypeSyncHook, enable_param_label and get_current_plugin_setting("enable_param_sync_type")),
                (HexraysFuncNavigateHook, get_current_plugin_setting("enable_func_navigate")),
                (HexraysRustStringHook, get_current_plugin_setting("enable_rust_string")),
                (HexraysMarkSEHHook, get_current_plugin_setting("enable_seh_highlight")),
                (HexraysRebuildSEHHook, get_current_plugin_setting("enable_seh_rebuild")),
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
