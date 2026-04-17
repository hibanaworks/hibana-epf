# hibana-epf

`hibana-epf` is the optional EPF appliance crate extracted from `hibana` core.

It owns:

- bytecode image headers and verification
- slot-scoped host installation and scratch leasing
- VM execution through `run_with(...)`

The crate depends on `hibana` through the public GitHub repository rather than a
filesystem path dependency. Until crates.io releases are cut for the split
repos, downstreams should depend on the same GitHub origin or use a local Cargo
patch override without editing this manifest back to a path dependency.
