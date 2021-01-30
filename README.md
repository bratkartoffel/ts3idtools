# ts3idtools

Various command line tools to work with teamspeak 3 identities. Inspired by
the [TSIdentityTool](https://github.com/landave/TSIdentityTool) from landave (thanks!)

If you'd like to know what the identity exactly is and how it works, please take a look at the
excellent [README](https://github.com/landave/TSIdentityTool/blob/master/README.md#faq) from landave.

This tool uses (and the precompiled binaries contain) the crypto library
from [libressl](https://github.com/libressl-portable/portable).

## ts3idgen

Generate a new identity.

```
Usage: ./ts3idgen [options]
Options:
  -h, --help             Print this usage information
  -i, --name=STRING      Name of the generated identity
                         Has to be at most 30 chars, defaults to 'New identity'
  -n, --nickname=STRING  Nickname for identity
                         Has to be between 3 and 30 characters, defaults to 'anonymous'
  -o, --output=FILE      Output filename
                         If set to '-' then the identity will be printed to stdout
  -v, --verbose          Enable debug output
```

Example:

```
#> ./ts3idgen --name="Generated" --nickname="bratkartoffel" --output=ts3_identity.ini
#> cat ts3_identity.ini
[Identity]
id=Generated
identity="351Ve8FwO31c7udTp1AEaFUcBipYaf1fCQBKCHAAZxNABkA9AUFQen1FUxsFNTYAB39TMVxgXQACYjUwQn0GYHBjfUFnQUFfMgFRUAdoEhM5DAtHWAR/N1B+Kxg0emBWUHhGKmhcXU9VVUNJUUN2aW5EOFl5R0VYOFBrMmw1MDlKZ1VIQjUwK3BMSkZESStXdk9FTE9YMDZnPT0="
nickname=bratkartoffel
```

The identity line contains a counter (used for the security level calculation) and the encoded and obfuscated private
key. Both are separated by a literal 'V'. In this example, the counter is currently at `351`.

## ts3iddump

This tool can be used to extract and show information from exported identities. Only the value of the `identity` line
from the export is used.

```
Usage: ./ts3iddump [options]
Options:
  -h, --help             Print this usage information
  -i, --identity=STRING  Identity (Starts with a number followed by a 'V')
  -s, --secret           Also print out secret key (DO NOT SHARE THIS!)
  -v, --verbose          Enable debug output
```

Example:

```
#> ./ts3iddump --identity="351Ve8FwO31c7udTp1AEaFUcBipYaf1fCQBKCHAAZxNABkA9AUFQen1FUxsFNTYAB39TMVxgXQACYjUwQn0GYHBjfUFnQUFfMgFRUAdoEhM5DAtHWAR/N1B+Kxg0emBWUHhGKmhcXU9VVUNJUUN2aW5EOFl5R0VYOFBrMmw1MDlKZ1VIQjUwK3BMSkZE
SStXdk9FTE9YMDZnPT0=" --secret

UUID=v3OXI7tHArV98DTDJPgGTcC8waQ=
PublicKey=MEsDAgcAAgEgAiBuIdUrjo1z1DaVpq3uX6ugIOr1x7SS5cJbRiQo00QSUwIgRHSOqVqqkW8a1cYvrXmnvh3JSeMI/POWg3KvOXjnOUU=
  x=6E21D52B8E8D73D43695A6ADEE5FABA020EAF5C7B492E5C25B462428D3441253
  y=44748EA95AAA916F1AD5C62FAD79A7BE1DC949E308FCF3968372AF3978E73945
PrivateKey=MG4DAgeAAgEgAiBuIdUrjo1z1DaVpq3uX6ugIOr1x7SS5cJbRiQo00QSUwIgRHSOqVqqkW8a1cYvrXmnvh3JSeMI/POWg3KvOXjnOUUCIQCvinD8YyGEX8Pk2l509JgUHB50+pLJFDI+WvOELOX06g==
  z=AF8A70FC6321845FC3E4DA5E74F498141C1E74FA92C914323E5AF3842CE5F4EA
Counter=351
SecurityLevel=8
```

## ts3idcrunch

This tool can be used to increase the security level of an identity much faster than with the teamspeak3 client.

```
Usage: ./ts3idcrunch [options]
Options:
  -b, --blocksize=NUMBER       Blocksize for the worker threads
                               Power to 2, defaults to 20 (= 1,048,576)
  -c, --counter=NUMBER         Starting value for counter
  -h, --help                   Print this usage information
  -p, --publickey=STRING       Public key of identity (usually starts with 'MEw')
  -l, --level=NUMBER           Minimum security level to print out
                               Should not be too small, defaults to 24
  -n, --nice=NUMBER            Priority of process (nice value)
                               Between -20 and 19, defaults to 10
  -o, --one-shot               Stop when the given level was found
  -s, --stats-interval=NUMBER  Interval (in seconds) to print statistics
                               When not set, no statistics are printed
  -t, --threads=NUMBER         Count of parallel worker threads to spawn
                               Should be lesser than the number of cores, defaults to 2
  -v, --verbose                Enable debug output
```

Example:

```
#> ./ts3idcrunch --publickey="MEsDAgcAAgEgAiBuIdUrjo1z1DaVpq3uX6ugIOr1x7SS5cJbRiQo00QSUwIgRHSOqVqqkW8a1cYvrXmnvh3JSeMI/POWg3KvOXjnOUU=" --level=28 --one-shot --threads=6

Start crunching...
Thread[0]: Found level=28 with counter 274687375!
-------------------
Results:      {28=274687375}
Last counter: 278921216
Runtime:      4.02 s
Performance:  69.31 mh/s
Per Thread:   11.55 mh/s
```

The counter value shown (`274687375`) can be directly set in the identity file created by the `ts3idgen` tools and raise
the security level directly to 28.

## Development

Besides libressl there isn't anything special about building this project. Just clone the repository (or download the
tarball). Extract and initialize the libressl submodule.

The next step is to prepare the libressl sources. Just run `update.sh` within the libressl folder to do so. You should
have an C compiler in your path, but this is no strict requirement as far as I know. This is also needed for every
update of this library.

```bash
git clone https://github.com/bratkartoffel/ts3idtools.git
git submodule init
git submodule update
cd libressl
./update.sh
```

After that, you can create a build directory and build with cmake as you're probably used to anyways.

```bash
mkdir cmake-build
cd cmake-build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j8
```
