# Go 0.4 baseline fixtures

`catalog.json` is the unmodified JSON from `bin/godseye-go-baseline.exe lab catalog` on Windows, captured on 18 October 2026. It contains the effective 26 tool descriptions, 26 assessment capabilities and 14 import format IDs. Installed Nmap was unavailable. This file records the comparison target, not capabilities implemented by Python.

Application source is unchanged between the planned baseline `4d27de83ad087703b197432ccbf2870a5ea6164c` and implementation starting commit `9482391`. The newly compiled baseline executable reports `godseye 0.4.0` and has SHA256 `df85bffbbdd867ab10e4891e7431ae8f8c0045cccf916e58e3d4f43ac2096399` on this machine. The executable is ignored under `bin/` and can be rebuilt from Git with Go 1.27.2.

Scanner and HTTP parity tests generate their synthetic fixtures in temporary directories and drive the real Go executable and Python entry point. They do not read or prune the user's inventory, uploads, evidence or feed cache. Random IDs, observation timestamps and run timestamps have explicit field-level normalization in the tests. Fingerprints, producer digests, locations, counts, errors, statuses and coverage gaps are compared without normalization.
