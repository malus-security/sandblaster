# SandBlaster: Reversing the Apple Sandbox

SandBlaster is a tool for reversing (decompiling) binary Apple sandbox profiles. Apple sandbox profiles are written in SBPL (*Sandbox Profile Language*), a Scheme-like language, and are then compiled into an undocumented binary format and shipped. Primarily used on iOS, sandbox profiles are present on macOS as well. SandBlaster is, to our knowledge, the first tool that reverses binary sandbox profiles to their original SBPL format. SandBlaster works on iOS from version 7 onwards including iOS 11.

The technical report [SandBlaster: Reversing the Apple Sandbox](https://arxiv.org/abs/1608.04303) presents extensive (though a bit outdated) information on SandBlaster internals.

SandBlaster relied on previous work by [Dionysus Blazakis](https://github.com/dionthegod/XNUSandbox) and Stefan Esser's [code](https://github.com/sektioneins/sandbox_toolkit) and [slides](https://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements).

The reverser (in the `reverse-sandbox/` folder) runs on any Python running platform. The helper tools in `tools/sandbox_toolkit/` run on macOS only.

SandBlaster may be installed and run standalone, though we recommend installing and running it from within [iExtractor](https://github.com/malus-security/iExtractor). Check the [iExtractor documentation](https://github.com/malus-security/iExtractor/blob/master/README.md) for information.

## Installation

SandBlaster requires Python for the reverser (in `reverse-sandbox/`), Bash for helper scripts (in `helpers/`) and tools from the [sandbox_toolkit](https://github.com/sektioneins/sandbox_toolkit) (in `tools/`).

After cloning the SandBlaster repository, you have to clone required tools as submodules:

```
git submodule update --init tools/sandbox_toolkit
```

Then you build the `extract_sbops` and `extract_sbprofiles` tools:

```
cd tools/sandbox_toolkit/extract_sbops
make
cd ../extract_sbprofiles
make
```

## Usage

In order to use SandBlaster you need access to the binary sandbox profiles and the sandbox operations, a set of strings that define sandbox-specific actions. Sandbox operations are extracted from the kernelcache using the `helpers/extract_sandbox_operations` script, which in turn calls `tools/sandbox_toolkit/extract_sbops/extract_sbops`. Sandbox profiles are extracted either from the kernel sandbox extension (as a bundle from iOS >= 9) or from the `sandboxd` file in the iOS filesystem (for iOS <= 8) using the `helpers/extract_sandbox_profiles` script, which in turn calls `tools/sandbox_toolkit/extract_sbprofiles/extract_sbprofiles`.

So, as input data, SandBlaster requires the kernelcache, the kernel sandbox extension and the `sandboxd` file. Information and scripts on extracting them from a publicly available IPSW (*iPhone Software*) file is presented by [iExtractor](https://github.com/malus-security/iExtractor).

Below are the steps and commands to reverse the sandbox profiles for iOS 8.4.1, assuming the kernelcache and the `sandboxd` file are available:

```
# Extract sandbox operations from kernelcache.
cd helpers/
./extract_sandbox_operations iPad2,1_8.4.1_12H321.kernelcache.mach.arm 8.4.1 > iPad2,1_8.4.1_12H321.sb_ops
# Extract binary sandbox profile files from sandboxd.
mkdir iPad2,1_8.4.1_12H321.sandbox_profiles
./extract_sandbox_profiles iPad2,1_8.4.1_12H321.sandboxd 8.4.1 iPad2,1_8.4.1_12H321.sandbox_profiles/
# Reverse all binary sandbox profiles.
cd ../reverse-sandbox/
mkdir iPad2,1_8.4.1_12H321.reversed_profiles
for i in ../helpers/iPad2,1_8.4.1_12H321.sandbox_profiles/*; do python reverse_sandbox.py -r 8.4.1 -o ../helpers/iPad2,1_8.4.1_12H321.sb_ops -d iPad2,1_8.4.1_12H321.reversed_profiles/ "$i"; done
```

Below are the steps and commands to reverse the sandbox profiles for iOS 9.3, assuming the kernelcache and the kernel sandbox extension (`com.apple.security.sandbox.kext`) are available:

```
# Extract sandbox operations from kernelcache.
cd helpers/
./extract_sandbox_operations iPhone5,1_9.3_13E237.kernelcache.mach.arm 9.3 > iPhone5,1_9.3_13E237.sb_ops
# Extract sandbox profile bundle from kernel sandbox extension.
./extract_sandbox_profiles iPhone5,1_9.3_13E237.com.apple.security.sandox.kext 9.3
cd ../reverse-sandbox/
# Reverse all binary sandbox profiles in sandbox bundle.
mkdir iPhone5,1_9.3_13E237.reversed_profiles
# Print all sandbox profiles in bundle.
python reverse_sandbox.py -r 9.3 -o ../helpers/iPhone5,1_9.3_13E237.sb_ops -d iPhone5,1_9.3_13E237.reversed_profiles/ ../helpers/sandbox_bundle -psb
# Do actual reversing.
python reverse_sandbox.py -r 9.3 -o ../helpers/iPhone5,1_9.3_13E237.sb_ops -d iPhone5,1_9.3_13E237.reversed_profiles/ ../helpers/sandbox_bundle
```

The extraction of the binary sandbox profiles differs between iOS <= 8 and iOS >= 9. For iOS 7 and iOS 8 the binary sandbox profiles are stored in the `sandboxd` file. Since iOS >= 9 the binary sandbox profiles are stored in a sandbox bundle in the kernel sandbox extension. The `helpers/extract_sandbox_profiles` script extracts them appropriately depending on the iOS version.

The `-psb` option for `reverse_sandbox.py` prints out the sandbox profiles part of a sandbox bundle without doing the actual reversing.

The `reverse_sandbox.py` script needs to be run in its directory (`reverse-sandbox/`) since it needs the other Python modules and the `logger.config` file.

## Internals

The `tools/` subfolder in the repository stores external tools, in this case [sandbox_toolkit](https://github.com/sektioneins/sandbox_toolkit) used for extracting the sandbox operations and the binary sandbox profiles.

The `helpers/` subfolder contains helper scripts that provide a nicer interface for the external tools.

The actual reverser is part of the `reverse-sandbox/` folder. Files here can be categorized as follows:

  * The main script is `reverse_sandbox.py`. It parses the command line arguments, does basic parsing of the input binary file (extracts sections) and calls the appropriate functions from the other modules.
  * The core of the implementation is `operation_node.py`. It provides functions to build the rules graph corresponding to the sandbox profile and to convert the graph to SBPL. It is called by `reverse_sandbox.py`.
  * Sandbox filters (i.e. match rules inside sandbox profiles) are handled by the implementation in `sandbox_filter.py` and the configuration in `filters.json`, `filter_list.py` and `filters.py`. Filter specific functions are called by `operation_node.py`.
  * Regular expression reversing is handled by `sandbox_regex.py` and `regex_parse.py`. `regex_parse.py` is the back end parser that converts the binary representation to a basic graph. `sandbox_regex.py` converts the graph representation (an automaton) to an actual regular expression (i.e. a string of characters and metacharacters). It is called by `reverse_sandbox.py` for parsing regular expressions, with the resulting regular expression list being passed to the functions exposed by `operation_node.py`; `operation_node.py` passes them on to sandbox filter handling files.
  * The new format for storing strings since iOS 10 is handled by `reverse_string.py`. The primary `SandboxString` class in `reverse_string.py` is used in `sandbox_filter.py`.
  * Logging is configured in the `logger.config` file. By default, `INFO` and higher level messages are printed to the console, while `DEBUG` and higher level messages are printed to the `reverse.log` file.

## Supported iOS Versions

SandBlaster works for iOS version 7 onwards including iOS 11. Apple has been making updates to the binary format of the sandbox profiles: since iOS 9 sandbox profiles are stored in a bundle, since iOS 10 strings are aggregated together in a specialied binary format. iOS 11 didn't bring any change to the format.

Earlier version of iOS (<= 6) use a different format that SandBlaster doesn't (yet) support. Contributions are welcome.
