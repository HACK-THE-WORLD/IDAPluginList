## WARNING: THIS CODE IS VERY RAW AND PROBABLY VERY BUGGY!

## Introduction

This is the blc (Binary Lifting Contraption) plugin for IDA Pro. It is the Bastard
love child of Ghidra's decompiler with Ida Pro.

The plugin integrates Ghidra's decompiler code into an Ida plugin an provides a 
basic decompiler capability for all platforms support by both Ida and Ghidra. It
provides a basic source code display that attempts to mimic that of the Hex-Rays
decompiler. It has only been written with Ida 7.x in mind.

## BUILDING:

On all platforms you should clone blc into your IDA SDK's plugins sub-directory
so that you end up with `<sdkdir>/plugins/blc`. This is because the build files
all use relative paths to find necessary IDA header files and link libraries.

### Build blc for Linux / OS X:

Use the include Makefile to build the plugin. You may need to adjust the paths
that get searched to find your IDA installation (`/Applications/IDA Pro N.NN` is
assumed on OSX and `/opt/ida-N.NN` is assumed on Linux, were N.NN is derived from
the name of your IDA SDK directory eg `idasdk75` associates with `7.5` and should
match your IDA version number). This is required to successfully link the plugin.

```
$ cd <sdkdir>/plugins/blc
$ make
```

Compiled binaries will end up in `<sdkdir>/plugins/blc/bin`

```
LINUX
         -------------------------------------------
         |        ida        |        ida64        |
         -------------------------------------------
IDA 7.x  |                   |                     |
 plugin  |     blc.so        |      blc64.so       |
         -------------------------------------------

OS/X
         -------------------------------------------
         |        ida        |        ida64        |
         -------------------------------------------
IDA 7.x  |                   |  |                  |
 plugin  |     blc.dylib     |      blc64.dylib    |
         -------------------------------------------
```

Copy the plugin(s) into your `<IDADIR>/plugins` directory and blc should be
listed as an available plugin for all architectures supported both Ida
and Ghidra.

### Build blc for Windows

Build with Visual Studio C++ 2017 or later using the included solution (`.sln`)
file (`blc.sln`). Two build targets are available depending on which version
of IDA you are using:

```
         -----------------------------------------
         |        ida        |        ida64      |
         -----------------------------------------
IDA 7.x  |    Release/x64    |   Release64/x64   |
 plugin  |       blc.dll     |       blc64.dll   |
         -----------------------------------------
```

Copy the plugin(s) into your `<IDADIR>/plugins` directory and blc should be
listed as an available plugin for all architectures supported by both Ida
and Ghidra.

## INSTALLATION

Assuming you have installed IDA to `<idadir>`, install the plugin by copying the
compiled binaries from `<sdkdir>/plugins/blc/bin` to `<idadir>/plugins` (Linux/Windows)
or `<idadir>/idabin/plugins` (OS X).

The plugin is dependent on Ghira processor specifications which you will need to
copy over from your own Ghidra installation. 

Installing Ghidra is a simple matter of unzipping the latest Ghidra release, for example:
<https://ghidra-sre.org/ghidra_9.2_PUBLIC_20201113.zip>
Within the extracted Ghidra folder, you will find a `Ghidra` subdirectory which,
in turn, contains a `Processors` subdirectory. The decompiler needs access to
files contained under `Ghidra/Processors`. By default the plugin looks for the 
environment variable `$GHIDRA_DIR` which it expects to point at your Ghidra
installation folder such that `$GHIDRA_DIR/Ghidra/Processors` exists. If
`$GHIDRA_DIR` is not set, then the plugin expects to find `<idadir>/plugins/Ghidra/Processors`
which you may create with a symlink or by copying the approprate directories
from your Ghidra installation.

### A NOTE ABOUT .SLA FILES

Ghidra uses a language called `sleigh` to define processor modules. Sleigh sources are typically
saved in .slaspec and .sinc (include) files. A sleigh compiler is used to build the .sla files used
by Ghidra. A fresh Ghidra installation includes no .sla file. Instead, as the need arises, Ghidra
generates required .sla files for a given architecture by invoking the sleigh compiler to generate
the correct .sla file for the architecture. This is why you may have noticed that Ghidra may take a
while to analyze the first file you open for a given architecture, but seems to be faster for all 
subsequent files (because the necessary .sla file is already available).

blc needs compiled .sla files for reasons similar to Ghidra's, however blc does not automatically generate
the .sla files for you. Fortunately a Ghidra install contains the sleigh compiler which can be used to generate
all of the required .sla files. Before using blc, you will need to do something like the following (assuming you are
on a Windows box, but similarly by referencing the correct sleigh binary on Linux or Mac):

    $ cd <my ghidra install>
    $ Ghidra/Features/Decompiler/os/win64/sleigh.exe -a Ghidra/Processors

When finished, all of the required .sla files should have been built in each of the arch specific subdirectories
under Ghidra/Processors (see Ghidra/Processors/<arch>/data/languages if you are really curious).
Copying the Processors directory to <idadir>/Ghidra at this point should get you what you need.

blc generally uses the latest git version of ghidra available at the time of a blc update. Occasionally changes to
the sleigh tool will result in the sleigh files from the current release version of Ghidra being outdated
and unusable. One solution is to build the sleigh component of Ghidra using git sources, then compile the 
current git .sla files found under ghidra/Ghidra/Processors. Alternatively, the blc project now contains the
archive blc_sleigh_files.tgz which contains Ghidra/Processors files that are compatible with the latest version of blc.
Simply extract the contents of this archive, including its directory structure into your <idadir>/plugins directory.

### Pre-built binaries:

As an alternative to building the plugin yourself, pre-built binaries for 
IDA 7.x (Windows, Linux, OS X) are available in the `blc/bins` directory.

## USING THE PLUGIN

With the plugin installed, open a binary of interest in IDA. In order for the
plugin to be become available, the binary's architecture must be supported by
both Ida and Ghidra.

With the cursor placed inside the body of an Ida function, select
`Edit/Plugins/Ghidra Decompiler`. A successful decompilation (which may take a bit
of time, will open a new window containing the C source generated by Ghidra's
decompiler. Within the source window, you may double click on a function name to
decompile tht function. Double clicking on a global data name will navigate you 
to that symbol in the Ida disassembly view. The `ESC` key will navigate back to a 
previous function, or close the source viewer if there is no previous function.

The `N` hot key may be used to rename any symbol in the source view. When a symbol
in the source view corresponds to a symbol in the Ida disassembly, the symbol will
also be renamed in the disassembly.

## POTENTIAL FUTURE WORK

* Allow user to set data types for symbols in the source view
* Provide IDA derived type information to the decompiler so that it can 
  do a better job with things like structures and pointer dereferencing
* Better (at least some) support for string literals
* Investigate what settings/info are necessary to get this standalone decompiler
  to yield results identical to Ghidra's. Is this symbol information? Type information?
  arch/platform/compiler settings?