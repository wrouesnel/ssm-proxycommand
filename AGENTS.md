Use README.md files to understand program intent and structure.

Binary outputs must build via `go run mage.go binary`.

Build without CGO.

Use the [afero package](https://github.com/spf13/afero) to abstract filesystem
access, ideally via the [pathlib package](https://github.com/chigopher/pathlib)
except in application startup entrypoints where no configuration has been loaded
yet.

If a web application is being developed then implement all endpoints using OpenAPI 3
and use `oapi-codegen` to build Echo v5 (`go get github.com/labstack/echo/v5`) based
servers.

Use the [zap logger](https://go.uber.org/zap) for logging and favor using the
[logutil package](https://github.com/wrouesnel/go.logutil). Any function taking
a `context.Context` should use `logutil.FromCtx` to get a context-aware logger.

Implement all binary applications as exportable packages under `pkg/entrypoints/<binary name>`
and keep code under `cmd/` to an absolute minimum. Replace `-` with `_` in the binary name to
get the package name, e.g. `cmd/foo-bar` is implemented by `pkg/entrypoints/foo_bar`. Each new
binary also needs an entry in `.gitignore` for the symlink `go run mage.go binary` creates.

Test entrypoints by calling `Entrypoint(ctx, args)` directly, as in
`pkg/entrypoints/application_sample/entrypoint_test.go`.

## Build commands

Run all build commands from the repository root. `go run mage.go -l` lists every target.

* `go run mage.go binary` - build for the current platform into `bin/` and symlink it into
  the repository root.
* `go run mage.go test` - run the tests. `go run mage.go coverage` merges coverage into
  `.cover.out` afterwards.
* `go run mage.go lint` - run golangci-lint (configured by `.golangci.yml`).
* `go run mage.go style` - check formatting. `go run mage.go fmt` fixes it.

CI runs `style`, `lint`, `test` and `binary`, all of which must pass.

## Web interface

A web interface is optional. If `web/package.json` exists, the build installs the Node.js
version in `.nvmrc` and builds `web/` into `web/dist` for embedding. Otherwise the web build
is skipped. Set `SKIP_WEB=1` to skip it regardless.
