import idaapi
import functools
from enum import Enum

class HandleStatus(Enum):
    HANDLED = 1
    NOT_HANDLED = 0
    FAILED = -1

# modified from https://gist.github.com/0xeb/a538abe26bc44f5e8f77676c161fe251
class undo_handler_t(idaapi.action_handler_t):
    '''Helper internal class to execute the undo-able user function'''
    id = 0
    def __init__(self, callable, *args, **kwargs):
        super().__init__()

        self.id = undo_handler_t.id
        self.callable = callable
        self.args = args
        self.kwargs = kwargs
        self.result = None

        undo_handler_t.id += 1

    def activate(self, ctx):
        self.result = self.callable(*self.args, **self.kwargs)
        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

def undoable(func):
    '''
    undoable wrapper invokes the user's function via
    process_ui_actions(). This will create an undo point and
    hence making the function 'undoable'
    '''

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ah = undo_handler_t(func, *args, **kwargs)
        desc = idaapi.action_desc_t(
            f'ida_undo_{func.__name__}_{ah.id}',
            f'IDAPython: {func.__name__}',
            ah)

        if not idaapi.register_action(desc):
            raise Exception(f'[-] Failed to register action {desc.name}')

        idaapi.process_ui_action(desc.name)
        idaapi.unregister_action(desc.name)

        if ah.result == HandleStatus.HANDLED:
            return 1
        elif ah.result == HandleStatus.NOT_HANDLED:
            return 0
        elif ah.result == HandleStatus.FAILED:
            print(f'[-] Failed to run hook {func.__qualname__}(), undo all changes')
            idaapi.process_ui_action('Undo')
            return 1

    return wrapper
