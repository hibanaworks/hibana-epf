# hibana-epf

`hibana-epf` is the optional EPF appliance crate extracted from `hibana` core.

It owns:

- bytecode image headers and verification
- slot-scoped host installation and scratch leasing
- VM execution through `run_with(...)`

The crate depends on `hibana` through the public GitHub repository at an
immutable revision rather than a filesystem path dependency. Downstreams should
consume the same immutable GitHub revision boundary or coordinated release
tags, not edit this manifest back to a path dependency.
