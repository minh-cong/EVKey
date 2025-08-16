# Tests

This repository includes basic tests for the `split_wstring` helper. The tests
use the standard C++ `assert` facility and can be built and executed with
`make`.

## Running the tests

From the repository root:

```bash
make test
```

This command builds the test binary and executes it. A successful run produces
no output and returns with exit code `0`. Any assertion failure will abort the
test program.
