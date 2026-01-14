import ida_kernwin
import importlib
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QColor

class HookType(Enum):
    HEXRAYS_EVENT = "hexrays_event"
    UI_EVENT = "ui_event"

@dataclass
class HookInfo:
    name: str
    description: str
    hook_type: HookType
    hook_instance: object
    module_name: Optional[str] = None  # Auto-detected from instance
    class_name: Optional[str] = None   # Auto-detected from instance
    enabled: bool = False

class HookManagerUI(object):
    """Standalone popup window UI for managing hooks"""

    def __init__(self, manager):
        self.manager = manager
        self.window = None

    def show(self):
        """Show the hook manager as a standalone popup window"""
        # Create main window
        self.window = QtWidgets.QMainWindow()
        self.window.setWindowTitle("Hook Manager")
        self.window.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.WindowStaysOnTopHint)
        self.window.resize(600, 400)

        # Center the window
        screen = QtWidgets.QApplication.desktop().screenGeometry()
        x = (screen.width() - 600) // 2
        y = (screen.height() - 400) // 2
        self.window.move(x, y)

        # Create central widget
        central_widget = QtWidgets.QWidget()
        self.window.setCentralWidget(central_widget)

        # Main layout
        layout = QtWidgets.QVBoxLayout(central_widget)

        # Title
        title = QtWidgets.QLabel("Hook Manager")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px; color: #2c3e50;")
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)

        # Hook list
        self.hook_list = QtWidgets.QListWidget()
        self.hook_list.setAlternatingRowColors(True)
        self.hook_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                background-color: white;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #ecf0f1;
            }
            QListWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        self.hook_list.itemDoubleClicked.connect(self.on_item_double_click)
        layout.addWidget(self.hook_list)

        # Button layout
        button_layout = QtWidgets.QHBoxLayout()

        # Style for buttons
        button_style = """
            QPushButton {
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                opacity: 0.8;
            }
            QPushButton:pressed {
                opacity: 0.6;
            }
        """

        # Toggle button
        self.toggle_btn = QtWidgets.QPushButton("Toggle Selected")
        self.toggle_btn.setStyleSheet(button_style + "QPushButton { background-color: #f39c12; color: white; }")
        self.toggle_btn.clicked.connect(self.on_toggle_selected)
        button_layout.addWidget(self.toggle_btn)

        # Enable all button
        self.enable_all_btn = QtWidgets.QPushButton("Enable All")
        self.enable_all_btn.setStyleSheet(button_style + "QPushButton { background-color: #27ae60; color: white; }")
        self.enable_all_btn.clicked.connect(self.on_enable_all)
        button_layout.addWidget(self.enable_all_btn)

        # Disable all button
        self.disable_all_btn = QtWidgets.QPushButton("Disable All")
        self.disable_all_btn.setStyleSheet(button_style + "QPushButton { background-color: #e74c3c; color: white; }")
        self.disable_all_btn.clicked.connect(self.on_disable_all)
        button_layout.addWidget(self.disable_all_btn)

        # Reload button
        self.reload_btn = QtWidgets.QPushButton("Reload Selected")
        self.reload_btn.setStyleSheet(button_style + "QPushButton { background-color: #9b59b6; color: white; }")
        self.reload_btn.clicked.connect(self.on_reload_selected)
        button_layout.addWidget(self.reload_btn)

        # Refresh button
        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.refresh_btn.setStyleSheet(button_style + "QPushButton { background-color: #34495e; color: white; }")
        self.refresh_btn.clicked.connect(self.refresh_list)
        button_layout.addWidget(self.refresh_btn)

        layout.addLayout(button_layout)

        # Hook list
        for _ in range(len(self.manager.hooks)):
            item = QtWidgets.QListWidgetItem()
            self.hook_list.addItem(item)

        # Status bar
        self.status_label = QtWidgets.QLabel("")
        self.status_label.setStyleSheet("color: #7f8c8d; font-size: 12px; padding: 5px;")
        self.status_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # Refresh and show
        self.refresh_list()
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def refresh_list(self):
        """Refresh the hook list"""
        for i, (hook_name, hook_info) in enumerate(self.manager.hooks.items()):
            item = self.hook_list.item(i)

            status_icon = "✅" if hook_info.enabled else "❌"
            item_text = f"{status_icon} {hook_info.name} ({hook_info.hook_type.value})"
            item.setText(item_text)

            # Add tooltip with description
            reload_status = "✨ Reloadable" if hook_info.module_name and hook_info.class_name else "❌ Not reloadable"
            module_info = f"{hook_info.module_name}.{hook_info.class_name}" if hook_info.module_name and hook_info.class_name else "N/A"
            item.setToolTip(f"Description: {hook_info.description}\nType: {hook_info.hook_type.value}\nStatus: {'Enabled' if hook_info.enabled else 'Disabled'}\nReload: {reload_status}\nModule: {module_info}")

            # Color coding
            if hook_info.enabled:
                item.setBackground(QColor(212, 237, 218))  # Light green
                item.setForeground(QColor(21, 87, 36))    # Dark green
            else:
                item.setBackground(QColor(248, 215, 218))  # Light red
                item.setForeground(QColor(114, 28, 36))   # Dark red

        # Update status
        total_hooks = len(self.manager.hooks)
        enabled_hooks = sum(1 for h in self.manager.hooks.values() if h.enabled)
        reloadable_hooks = sum(1 for h in self.manager.hooks.values() if h.module_name and h.class_name)
        self.status_label.setText(f"📊 Total: {total_hooks} | ✅ Enabled: {enabled_hooks} | ❌ Disabled: {total_hooks - enabled_hooks} | ✨ Reloadable: {reloadable_hooks}")

    def on_item_double_click(self, item):
        """Handle double-click on item"""
        self.on_toggle_selected()

    def on_toggle_selected(self):
        """Toggle selected hook"""
        current_row = self.hook_list.currentRow()
        if current_row >= 0:
            hook_name = list(self.manager.hooks.keys())[current_row]
            self.manager.toggle_hook(hook_name)
            self.refresh_list()

    def on_enable_all(self):
        """Enable all hooks"""
        self.manager.enable_all_hooks()
        self.refresh_list()

    def on_disable_all(self):
        """Disable all hooks"""
        self.manager.disable_all_hooks()
        self.refresh_list()

    def on_reload_selected(self):
        """Reload selected hook"""
        current_row = self.hook_list.currentRow()
        if current_row >= 0:
            hook_name = list(self.manager.hooks.keys())[current_row]
            success = self.manager.reload_hook(hook_name)
            if success:
                QtWidgets.QMessageBox.information(self.window, "Success", f"Hook '{hook_name}' reloaded successfully!")
            else:
                QtWidgets.QMessageBox.warning(self.window, "Error", f"Failed to reload hook '{hook_name}'. Check console for details.")
            self.refresh_list()

class HookManager:
    """Central manager for IDA Pro hooks"""

    def __init__(self):
        self.hooks: Dict[str, HookInfo] = {}
        self.ui = None
        self.action_name = "hook_manager:show_ui"
        self._register_actions()
        print("[HookManager] Hook Manager loaded. Access via Edit -> Plugins -> Show Hook Manager")

    def __del__(self):
        """Cleanup when manager is deleted"""
        self._cleanup_actions()

    def _detect_hook_metadata(self, hook_instance: object) -> tuple[Optional[str], Optional[str]]:
        """Auto-detect module name and class name from hook instance

        Returns:
            Tuple of (module_name, class_name) or (None, None) if detection fails
        """
        try:
            # Get the class of the instance
            hook_class = hook_instance.__class__

            # Get module name
            module_name = hook_class.__module__

            # Get class name
            class_name = hook_class.__name__

            # Skip built-in modules and __main__
            if module_name in ('__main__', '__builtin__', 'builtins'):
                print(f"[HookManager] Hook from built-in or current script - not reloadable")
                return None, None

            # Verify the module is actually importable and in sys.modules
            if module_name not in sys.modules:
                print(f"[HookManager] Module '{module_name}' not found in sys.modules - not reloadable")
                return None, None

            # Verify we can get the class from the module
            module = sys.modules[module_name]
            if not hasattr(module, class_name):
                print(f"[HookManager] Class '{class_name}' not found in module '{module_name}' - not reloadable")
                return None, None

            print(f"[HookManager] Auto-detected reloadable hook: {module_name}.{class_name}")
            return module_name, class_name

        except Exception as e:
            print(f"[HookManager] Failed to detect hook metadata: {e}")
            return None, None

    def register_hook(self,
                     name: str,
                     description: str,
                     hook_type: HookType,
                     hook_instance: object) -> bool:
        """Register a hook with the manager

        Args:
            name: Unique name for the hook
            description: Description of what the hook does
            hook_type: Type of hook (from HookType enum)
            hook_instance: The actual hook instance
        """

        if name in self.hooks:
            print(f"[HookManager] Hook '{name}' already registered")
            return False

        # Verify the hook instance has the required methods
        if not hasattr(hook_instance, 'hook') or not hasattr(hook_instance, 'unhook'):
            print(f"[HookManager] Hook instance '{name}' must have 'hook()' and 'unhook()' methods")
            return False

        # Auto-detect module and class information for reloading
        module_name, class_name = self._detect_hook_metadata(hook_instance)

        hook_info = HookInfo(
            name=name,
            description=description,
            hook_type=hook_type,
            hook_instance=hook_instance,
            module_name=module_name,
            class_name=class_name,
            enabled=True
        )

        self.hooks[name] = hook_info
        print(f"[HookManager] Registered hook: {name}")
        if module_name and class_name:
            print(f"[HookManager] Hook '{name}' is reloadable from {module_name}.{class_name}")
        else:
            print(f"[HookManager] Hook '{name}' is not reloadable")
        return True

    def unregister_hook(self, name: str) -> bool:
        """Unregister a hook"""
        if name not in self.hooks:
            return False

        # Disable if enabled
        if self.hooks[name].enabled:
            self.disable_hook(name)

        del self.hooks[name]
        print(f"[HookManager] Unregistered hook: {name}")
        return True

    def enable_hook(self, name: str) -> bool:
        """Enable a specific hook"""
        if name not in self.hooks:
            print(f"[HookManager] Hook '{name}' not found")
            return False

        hook_info = self.hooks[name]
        if hook_info.enabled:
            print(f"[HookManager] Hook '{name}' already enabled")
            return True

        try:
            hook_info.hook_instance.hook()
            hook_info.enabled = True
            print(f"[HookManager] Enabled hook: {name}")
            return True
        except Exception as e:
            print(f"[HookManager] Failed to enable hook '{name}': {e}")
            return False

    def disable_hook(self, name: str) -> bool:
        """Disable a specific hook"""
        if name not in self.hooks:
            print(f"[HookManager] Hook '{name}' not found")
            return False

        hook_info = self.hooks[name]
        if not hook_info.enabled:
            print(f"[HookManager] Hook '{name}' already disabled")
            return True

        try:
            hook_info.hook_instance.unhook()
            hook_info.enabled = False
            print(f"[HookManager] Disabled hook: {name}")
            return True
        except Exception as e:
            print(f"[HookManager] Failed to disable hook '{name}': {e}")
            return False

    def toggle_hook(self, name: str) -> bool:
        """Toggle hook state"""
        if name not in self.hooks:
            return False

        if self.hooks[name].enabled:
            return self.disable_hook(name)
        else:
            return self.enable_hook(name)

    def toggle_hook_by_index(self, index: int) -> bool:
        """Toggle hook by UI index"""
        if 0 <= index < len(self.hooks):
            hook_name = list(self.hooks.keys())[index]
            return self.toggle_hook(hook_name)
        return False

    def enable_all_hooks(self):
        """Enable all registered hooks"""
        for name in self.hooks:
            self.enable_hook(name)

    def disable_all_hooks(self):
        """Disable all registered hooks"""
        for name in self.hooks:
            self.disable_hook(name)

    def get_hook_status(self, name: str) -> Optional[bool]:
        """Get hook enabled status"""
        if name in self.hooks:
            return self.hooks[name].enabled
        return None

    def list_hooks(self) -> List[str]:
        """Get list of registered hook names"""
        return list(self.hooks.keys())

    def reload_hook(self, name: str) -> bool:
        """Reload a hook from its source module"""
        if name not in self.hooks:
            print(f"[HookManager] Hook '{name}' not found")
            return False

        hook_info = self.hooks[name]

        if not hook_info.module_name or not hook_info.class_name:
            print(f"[HookManager] Hook '{name}' is not reloadable (no module/class information)")
            return False

        # Remember if it was enabled
        was_enabled = hook_info.enabled

        try:
            # Disable the hook first if it's enabled
            if was_enabled:
                self.disable_hook(name)

            # Reload the module
            if hook_info.module_name in sys.modules:
                print(f"[HookManager] Reloading module: {hook_info.module_name}")
                importlib.reload(sys.modules[hook_info.module_name])
            else:
                print(f"[HookManager] Importing module: {hook_info.module_name}")
                importlib.import_module(hook_info.module_name)

            # Get the class from the reloaded module
            module = sys.modules[hook_info.module_name]
            hook_class = getattr(module, hook_info.class_name)

            # Create new instance
            print(f"[HookManager] Creating new instance of {hook_info.class_name}")
            new_instance = hook_class()

            # Verify the new instance has the required methods
            if not hasattr(new_instance, 'hook') or not hasattr(new_instance, 'unhook'):
                print(f"[HookManager] Reloaded hook instance '{name}' must have 'hook()' and 'unhook()' methods")
                return False

            # Replace the old instance
            hook_info.hook_instance = new_instance
            hook_info.enabled = False  # Reset to disabled state

            # Re-detect metadata in case something changed
            new_module_name, new_class_name = self._detect_hook_metadata(new_instance)
            hook_info.module_name = new_module_name
            hook_info.class_name = new_class_name

            # Re-enable if it was enabled before
            if was_enabled:
                self.enable_hook(name)

            print(f"[HookManager] Successfully reloaded hook: {name}")
            return True

        except Exception as e:
            print(f"[HookManager] Failed to reload hook '{name}': {e}")
            import traceback
            traceback.print_exc()
            return False

    def show_ui(self):
        """Show the hook manager UI as a true popup window"""
        if self.ui is None:
            self.ui = HookManagerUI(self)

        # Show as standalone popup window
        self.ui.show()

    def _register_actions(self):
        """Register UI actions"""
        # Create action handler class
        class ShowHookManagerHandler(ida_kernwin.action_handler_t):
            def __init__(self, manager):
                ida_kernwin.action_handler_t.__init__(self)
                self.manager = manager

            def activate(self, ctx):
                self.manager.show_ui()
                return 1

            def update(self, ctx):
                return ida_kernwin.AST_ENABLE_ALWAYS

        # Register the main UI action
        registered_actions = ida_kernwin.get_registered_actions()
        if self.action_name not in registered_actions:
            handler = ShowHookManagerHandler(self)
            action_desc = ida_kernwin.action_desc_t(
                self.action_name,
                "Show Hook Manager",
                handler,
                "Ctrl+Shift+H",
                "Open the Hook Manager UI",
                160  # icon
            )
            ida_kernwin.register_action(action_desc)

            # Add to menu
            ida_kernwin.attach_action_to_menu(
                "Edit/Plugins/", self.action_name, ida_kernwin.SETMENU_APP
            )

    def force_refresh_menu(self):
        """Force refresh the menu - call after loading"""
        ida_kernwin.refresh_idaview_anyway()

    def _cleanup_actions(self):
        """Cleanup registered actions"""
        try:
            # Detach from menu first
            ida_kernwin.detach_action_from_menu("Edit/Plugins/", self.action_name)

            # Unregister the action
            registered_actions = ida_kernwin.get_registered_actions()
            if self.action_name in registered_actions:
                ida_kernwin.unregister_action(self.action_name)
                print(f"[HookManager] Unregistered action: {self.action_name}")
        except Exception as e:
            print(f"[HookManager] Error during cleanup: {e}")

    def cleanup(self):
        """Manually cleanup the manager (call this before deleting)"""
        # Cleanup actions
        self._cleanup_actions()

        print("[HookManager] Manager cleanup completed")
