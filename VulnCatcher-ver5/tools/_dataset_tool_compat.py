"""Load the canonical dataset tool for a legacy entry point."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


def forward(namespace, name):
    target = Path(namespace["__file__"]).resolve().with_name(name + ".py")
    package = namespace.get("__package__")
    key = (package + "." if package else "") + name
    module = sys.modules.get(key)
    if module is not None and Path(module.__file__).resolve() != target:
        version = target.parent.parent.name.replace("-", "_")
        key = "_" + version + "_" + name
        module = sys.modules.get(key)
    if module is None:
        spec = spec_from_file_location(key, target)
        module = module_from_spec(spec)
        sys.modules[key] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(key, None)
            raise
    if namespace["__name__"] == "__main__":
        raise SystemExit(module.main())
    sys.modules[namespace["__name__"]] = module
    namespace.update(module.__dict__)
