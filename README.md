# dumpybin

A small open source port of the popular Microsoft DumpBin executable.

The reason for this tool's creation is that it's a little inconvenient needing to install the Microsoft development tools just to dump the exports and ordinals of functions in a DLL, this little Python file runs standalone with no external dependencies.

**Forks and pull requests are more than welcome.**


## Note -
Only works with 32 bit PE files for now unfortunately, 64 bit support will be added eventually™.


## Usage - 

```
usage: dumpybin.py [-h] [--debug] [-s] [-i] [-e] DLL

Processes a DLL file and outputs the exported functions and function ordinals, just like the Big Boy Dumpbin does.

positional arguments:
  DLL             The path to the DLL which should be processed by dumpybin.

optional arguments:
  -h, --help      show this help message and exit
  --debug         supply this option to output a bunch of debugging data for nerds.
  -s, --sections  Dump out section data
  -i, --imports   Dump out import data
  -e, --exports   Dump out export data
```

To dump out the ordinals, names and RVAs of all exported functions in a DLL you'd use:

```
python3 dumpybin.py -e path_to_dll_file.dll
```

This script also works correctly on general Windows EXE files too. There won't be any exported functions (because that's a DLL concept), but sections and imports can be dumped correctly with:

```
python3 dumpybin.py -i -s path_to_exe_file.exe
```

---