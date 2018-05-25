from binaryninja import Architecture, PluginCommand
from obfu_hook import ObfuArchHook
from obfu_passes import fix_obfuscation

obfu_arches = [
    'x86',
    'x86_64'
]

for arch in obfu_arches:
    ObfuArchHook(Architecture[arch]).register()

PluginCommand.register_for_function(
    'Fix Obfuscation',
    'Fix certain obfuscation methods',
    lambda bv, func: fix_obfuscation(bv, func),
    lambda bv, func: bv.arch.name in obfu_arches
)
