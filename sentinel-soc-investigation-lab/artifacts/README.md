# Generated evidence

`latest/` is generated locally and ignored. `example/` contains the stable, committed output produced by the verified synthetic dataset. Run `python -m soclab analyze` followed by `python -m soclab build-report` to rebuild `latest/`. CI regenerates the full set and compares it byte-for-byte with `example/`, so a source or fixture change must intentionally refresh every affected example file after review.
