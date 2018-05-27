from binaryninja import Architecture, PluginCommand
from obfu_hook import ObfuArchHook
from obfu_passes import fix_obfuscation
from obfu_utils import RunInBackground

obfu_arches = [
    'x86',
    'x86_64'
]

for arch in obfu_arches:
    ObfuArchHook(Architecture[arch]).register()


def fix_obfuscation_command(view, func):
    task = RunInBackground('Remove Obfuscation', fix_obfuscation, view, func)
    task.start()


PluginCommand.register_for_function(
    'Fix Obfuscation',
    'Fix certain obfuscation methods',
    lambda view, func: fix_obfuscation_command(view, func),
    lambda view, func: view.arch.name in obfu_arches
)
