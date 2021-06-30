# dumpybin

A small open source port of the popular Microsoft DumpBin executable.

The reason for this tool's creation is that it's a little inconvenient needing to install the Microsoft development tools just to dump the exports and ordinals of functions in a DLL, this little Python file runs standalone with no external dependencies.

**Forks and pull requests are more than welcome.**


## Usage - 

```
usage: dumpybin.py [-h] [--debug | --no-debug] DLL

Processes a DLL file and outputs the exported functions and function ordinals, just like the Big Boy Dumpbin does.

positional arguments:
  DLL                  The path to the DLL which should be processed by dumpybin.

optional arguments:
  -h, --help           show this help message and exit
  --debug, --no-debug  supply this option to output a bunch of debugging data for nerds. (default: --no-debug)
```

---

