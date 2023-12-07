# Symless

Automatic structures recovering plugin for IDA. Able to reconstruct structures/classes and virtual tables used in a binary.

### Features
* Automatic creation of identified structures (c++ classes, virtual tables and others)
* Xrefs on structures usages
* Functions typing using gathered information

Two modes are available: **Pre-Analysis** and **Plugin**.

## Plugin mode
Interactive IDA plugin. Uses static analysis from an entry point selected by the user to build and propagate a structure.

<p align="center">
    <kbd>
        <img src="img/plugin-demo.gif" alt="Plugin demo"/>
    </kbd>
</p>


### Installation
```
$ python plugin/install.py [-u]
```

**Manual installation**: copy the [symless](symless/) directory and [symless_plugin.py](plugin/symless_plugin.py) into IDA plugins folder.

### Usage
While in IDA disassembly view:
- Right-click a register that contains a structure pointer
- Select **Propagate structure**
- Select which structure & shift to apply

Symless will then propagate the structure, build it and type untyped functions / operands with the harvested information. This action can be undone with **Ctrl-Z**. A new structure can be created, an existing one can be completed.

## Pre-Analysis mode

### Before use

#### Specify your IDA installation:

```
export IDA_DIR="$HOME/idapro-M.m"
```

#### Edit the config file to suit your case:

Specify the memory allocation functions used in your executable in the [imports.csv](symless/config/imports.csv) file. Syntax is discussed there.

Symless uses those to find structures creations from memory allocations. C++ classes can also be retrieved from their virtual tables.

### Usage
```
    $ python3 symless.py [-c config.csv] <target(s)>
```

* ```config.csv``` - configuration to be used (defaults to [imports.csv](symless/config/imports.csv))
* ```target(s)``` - one or more binaries / IDA bases

Symless will create a new IDA base when given an executable as an argument. Otherwise keep in mind it may overwrite user-modifications on existing bases.

Once done the IDA base will be populated with information about identified structures.

## Support
Both stripped and non-stripped binaries are supported. Symbols are only used to name the created structures.

**x64** and **i386** binairies using the following calling conventions are supported:
* Windows x64 (```__fastcall```)
* Windows i386 (```__stdcall``` & ```__thiscall```)
* System V x64 (```__fastcall```)
* System V i386 (```__stdcall```)

**IDA Pro 7.6** or newer &  **python 3**

## Disclaimer
Symless is still in development and might not fit every use cases.
