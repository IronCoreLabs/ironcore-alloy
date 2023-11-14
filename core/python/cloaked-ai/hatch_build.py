from hatchling.builders.hooks.plugin.interface import BuildHookInterface
import sys
import os
from packaging.tags import sys_tags


# Forms a Python Platform Compatibility Tag based on where our cdylib was compiled
# See https://packaging.python.org/en/latest/specifications/platform-compatibility-tags/ for info on each tag.
def get_cdylib_specific_tag(cdylib_platform: str) -> str:
    print(cdylib_platform)
    # our generated python code uses python 3.7 features, so we don't actually support all py3. We're depending
    # on the `requires-python` value in our `pyproject.toml` to make sure earlier incompatible interpreters don't
    # install us.
    python_tag = "py3"
    # since we aren't compiling a CPython extension, only being called _from_ Python, the Python ABI doesn't seem to
    # matter for us
    python_abi_tag = "none"
    # github actions uses glibc 2.39 right now, so 2.17 is a guess based on other packages
    platform_tag = ""
    if cdylib_platform == "linux-x86-64":
        platform_tag = "manylinux_2_17_x86_64.manylinux2014_x86_64"
    elif cdylib_platform == "linux-arm":
        platform_tag = "manylinux_2_17_aarch64.manylinux2014_aarch64"
    elif cdylib_platform == "darwin-x86-64":
        platform_tag = "macosx_10_9_x86_64"
    elif cdylib_platform == "darwin-aarch64":
        platform_tag = "macosx_11_0_arm64"
    else:
        platform_tag = "unknown"
    return "-".join([python_tag, python_abi_tag, platform_tag])


# set the `.whl` filename so when uploaded to PyPi it's pulled down correctly on install
class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        # expects our CI to set `CDYLIB_PLATFORM` to something like
        # "linux-x86-64", "linux-arm", "darwin-x86-64", "darwin-aarch64"
        cdylib_platform = os.environ.get("CDYLIB_PLATFORM")
        if cdylib_platform is not None:
            build_data["tag"] = get_cdylib_specific_tag(cdylib_platform)
        else:
            build_data["infer_tag"] = True
