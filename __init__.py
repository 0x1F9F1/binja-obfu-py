from binaryninja import Architecture, PluginCommand, log
from obfu_hook import ObfuArchHook
from obfu_passes import fix_obfuscation
from obfu_utils import RunInBackground


def fix_obfuscation_command(view, func):
    task = RunInBackground('Remove Obfuscation', fix_obfuscation, view, func)
    task.start()


def load_arch_hook_command(view):
    ObfuArchHook(view.arch).register()
    log.log_info('Loaded ObfuArchHook for {0}'.format(view.arch.name))


PluginCommand.register_for_function(
    'Fix Obfuscation',
    'Fix certain obfuscation methods',
    lambda view, func: fix_obfuscation_command(view, func),
    lambda view, func: type(view.arch) == ObfuArchHook
)

PluginCommand.register(
    'Load ObfuArchHook',
    'Loads ObfuArchHook',
    lambda view: load_arch_hook_command(view),
    lambda view: type(view.arch) != ObfuArchHook
)
