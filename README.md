# GMod x64 Offset Dumper

Educational Garry's Mod x64 offset dumper for exploring module layouts, pattern scanning, and RecvTable / NetVar structures.

## About

This project was built for educational and research purposes.

The goal is to study how a running x64 `gmod.exe` process exposes:

- module information such as `client.dll` and `engine.dll`
- static offsets resolved through pattern scanning
- client class / RecvTable trees
- generated NetVar output in a C++-friendly format

This repository is not meant as a production-ready framework. It is a small learning project focused on understanding memory layout, pattern resolution, and data table traversal in a real x64 game process.

## What It Does

- Finds the running `win64` Garry's Mod process
- Enumerates remote modules from the target process
- Scans selected x64 patterns for curated static offsets
- Walks client classes and RecvTables to dump NetVars
- Generates a `gmod_offsets.hpp` header with:
  - `namespace Offsets`
  - `namespace NetVars`

## Included Files

Main repository contents:

- `GModOffsetDumper.cpp`
- `GModOffsetDumper.h`
- `main.cpp`
- Visual Studio solution / project files
- `debug_offsets.py`

`debug_offsets.py` is included only as a lightweight validation helper for the generated values.

Local one-off helper scripts, temporary logs, and personal test files are not intended to be part of the published project.

## Build

Environment used:

- Windows
- Visual Studio
- x64 target

Build configuration:

- `Debug | x64`
or
- `Release | x64`

## Usage

1. Start Garry's Mod in `win64` mode.
2. Build and run the dumper.
3. Let it resolve static offsets and RecvTables.
4. Check the generated `gmod_offsets.hpp` output.

## Notes

- This project currently targets the x64 version of Garry's Mod.
- Static offsets are intentionally curated, not fully auto-discovered.
- NetVars are dumped more broadly by walking RecvTables.
- Results may change across game updates.

## Educational Scope

This repository is shared as a learning resource for:

- reverse-engineering practice
- x64 pattern scanning practice
- process/module inspection
- C++ tooling around generated offsets

If you publish it on GitHub, it is best described as an educational dumper rather than a finished tool.
