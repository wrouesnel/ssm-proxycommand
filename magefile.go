//go:build mage

// Self-contained go-project magefile.

//nolint:deadcode,gochecknoglobals,gochecknoinits,wrapcheck,varnamelen,gomnd,forcetypeassert,forbidigo,funlen,gocognit,cyclop,nolintlint
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/bits"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	archiver "github.com/mholt/archiver"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"

	"github.com/integralist/go-findroot/find"
	"github.com/pkg/errors"

	"github.com/samber/lo"
	"golang.org/x/mod/modfile"
)

var (
	errAutogenMultipleScriptSections       = errors.New("found multiple managed script sections")
	errAutogenUnknownPreCommitScriptFormat = errors.New("unknown pre-commit script format")
	errPlatformNotSupported                = errors.New("current platform is not supported")
	errParallelBuildFailed                 = errors.New("parallel build failed")
	errLintBisect                          = errors.New("error during lint bisect")
)

var curDir = func() string {
	name, _ := os.Getwd()
	return name
}()

//nolint:revive,stylecheck
const (
	OS_READ        = 04
	OS_WRITE       = 02
	OS_EX          = 01
	OS_USER_SHIFT  = 6
	OS_GROUP_SHIFT = 3
	OS_OTH_SHIFT   = 0

	OS_USER_R   = OS_READ << OS_USER_SHIFT
	OS_USER_W   = OS_WRITE << OS_USER_SHIFT
	OS_USER_X   = OS_EX << OS_USER_SHIFT
	OS_USER_RW  = OS_USER_R | OS_USER_W
	OS_USER_RWX = OS_USER_RW | OS_USER_X

	OS_GROUP_R   = OS_READ << OS_GROUP_SHIFT
	OS_GROUP_W   = OS_WRITE << OS_GROUP_SHIFT
	OS_GROUP_X   = OS_EX << OS_GROUP_SHIFT
	OS_GROUP_RW  = OS_GROUP_R | OS_GROUP_W
	OS_GROUP_RWX = OS_GROUP_RW | OS_GROUP_X

	OS_OTH_R   = OS_READ << OS_OTH_SHIFT
	OS_OTH_W   = OS_WRITE << OS_OTH_SHIFT
	OS_OTH_X   = OS_EX << OS_OTH_SHIFT
	OS_OTH_RW  = OS_OTH_R | OS_OTH_W
	OS_OTH_RWX = OS_OTH_RW | OS_OTH_X

	OS_ALL_R   = OS_USER_R | OS_GROUP_R | OS_OTH_R
	OS_ALL_W   = OS_USER_W | OS_GROUP_W | OS_OTH_W
	OS_ALL_X   = OS_USER_X | OS_GROUP_X | OS_OTH_X
	OS_ALL_RW  = OS_ALL_R | OS_ALL_W
	OS_ALL_RWX = OS_ALL_RW | OS_ALL_X
)

const (
	constCoverageDir = ".coverage"
	constToolBinDir  = ".bin"
	constGitHookDir  = "githooks"
	constBinDir      = "bin"
	constReleaseDir  = "release"
	constCmdDir      = "cmd"
	constCoverFile   = ".cover.out"
	constJunitDir    = ".junit"
	constNodeDir     = ".node"
)

const (
	constManagedScriptSectionHead = "## ++ BUILD SYSTEM MANAGED - DO NOT EDIT ++ ##"
	constManagedScriptSectionFoot = "## -- BUILD SYSTEM MANAGED - DO NOT EDIT -- ##"
)

// normalizePath turns a path into an absolute path and removes symlinks.
func normalizePath(name string) string {
	absPath := must(filepath.Abs(name))
	return absPath
}

// binRootName is set to the name of the directory by default.
var binRootName = func() string {
	repo, err := find.Repo()
	if err != nil {
		// Couldn't find a repo. Look for mage.go instead which should be at
		// the root of the source tree.
		currentDir := must(filepath.Abs(must(os.Getwd())))
		for {
			if _, err := os.Stat(filepath.Join(currentDir, "mage.go")); os.IsNotExist(err) {
				currentDir = filepath.Dir(currentDir)
			} else {
				return currentDir
			}
			if strings.HasSuffix(currentDir, strconv.QuoteRune(os.PathSeparator)) {
				panic("Could not locate repo root nor mage.go")
			}
		}
	}
	return repo.Path
}()

// dockerImageName is set to the name of the directory by default.
//
//nolint:unused,varcheck
var dockerImageName = func() string {
	return binRootName
}()

var coverageDir = normalizePath(path.Join(curDir, constCoverageDir))
var toolsBinDir = normalizePath(path.Join(curDir, constToolBinDir))
var gitHookDir = normalizePath(path.Join(curDir, constGitHookDir))
var binDir = normalizePath(path.Join(curDir, constBinDir))
var releaseDir = normalizePath(path.Join(curDir, constReleaseDir))
var cmdDir = normalizePath(path.Join(curDir, constCmdDir))
var junitDir = normalizePath(path.Join(curDir, constJunitDir))
var nodeDir = normalizePath(path.Join(curDir, constNodeDir))

var outputDirs = []string{binDir, releaseDir, coverageDir, junitDir}

//nolint:unused,varcheck
var containerName = func() string {
	if name := os.Getenv("CONTAINER_NAME"); name != "" {
		return name
	}
	return dockerImageName
}()

type Platform struct {
	OS        string
	Arch      string
	BinSuffix string
}

func (p *Platform) String() string {
	return fmt.Sprintf("%s-%s", p.OS, p.Arch)
}

func (p *Platform) PlatformDir() string {
	platformDir := path.Join(binDir, fmt.Sprintf("%s_%s_%s", productName, versionShort, p.String()))
	return platformDir
}

func (p *Platform) PlatformBin(cmd string) string {
	platformBin := fmt.Sprintf("%s%s", cmd, p.BinSuffix)
	return path.Join(p.PlatformDir(), platformBin)
}

func (p *Platform) ArchiveDir() string {
	return fmt.Sprintf("%s_%s_%s", productName, versionShort, p.String())
}

func (p *Platform) ReleaseBase() string {
	return path.Join(releaseDir, fmt.Sprintf("%s_%s_%s", productName, versionShort, p.String()))
}

// platforms is the list of platforms we build for.
var platforms []Platform = []Platform{
	{"linux", "arm", ""},
	{"linux", "arm64", ""},
	{"linux", "amd64", ""},
	{"linux", "386", ""},
	{"darwin", "amd64", ""},
	{"darwin", "arm64", ""},
	{"windows", "amd64", ".exe"},
	{"windows", "386", ".exe"},
	{"freebsd", "amd64", ""},
}

// platformsLookup is the lookup map of the above list by <OS>/<Arch>.
var platformsLookup map[string]Platform = func() map[string]Platform {
	ret := make(map[string]Platform, len(platforms))
	for _, platform := range platforms {
		ret[platform.String()] = platform
	}
	return ret
}()

// productName is the Name constant from version/version.go, so release archives are named
// the same as the application. It can be overridden by environ product name.
var productName = func() string {
	if name := os.Getenv("PRODUCT_NAME"); name != "" {
		return name
	}
	if name := versionName(); name != "" {
		return name
	}
	name, _ := os.Getwd()
	return path.Base(name)
}()

// versionName reads the Name constant from version/version.go, or returns "" if it
// can't be found.
func versionName() string {
	file, err := parser.ParseFile(token.NewFileSet(), path.Join(curDir, "version", "version.go"), nil, 0)
	if err != nil {
		return ""
	}
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec := spec.(*ast.ValueSpec)
			for i, ident := range valueSpec.Names {
				if ident.Name != "Name" || i >= len(valueSpec.Values) {
					continue
				}
				if lit, ok := valueSpec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if name, err := strconv.Unquote(lit.Value); err == nil {
						return name
					}
				}
			}
		}
	}
	return ""
}

// Source files.
var goSrc []string
var goDirs []string

// Due to go:generate and asset embedding interaction, this is now an on demand function
var goPkgs func() []string
var goCmds []string

// Function to calculate the version symbol
var versionSymbol = func() string {
	gomodBytes := lo.Must(os.ReadFile("go.mod"))
	parsedGoMod := lo.Must(modfile.ParseLax("go.mod", gomodBytes, nil))
	return parsedGoMod.Module.Mod.Path + "/version.Version"
}

// gitOutput runs git and returns its trimmed stdout, or "" on failure. Unlike sh.Output
// it discards stderr, since a repository without tags is a normal state for git describe.
func gitOutput(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

var version = func() string {
	if v := os.Getenv("VERSION"); v != "" {
		return v
	}
	out := gitOutput("describe", "--dirty")

	if out == "" {
		// Try and at least describe the git commit.
		out = gitOutput("describe", "--dirty", "--always")
		if out != "" {
			//nolint:perfsprint
			return fmt.Sprintf("v0.0.0-0-%s", out)
		}
		return "v0.0.0"
	}

	return out
}()

var versionShort = func() string {
	if v := os.Getenv("VERSION_SHORT"); v != "" {
		return v
	}
	out := gitOutput("describe", "--abbrev=0")

	if out == "" {
		return "v0.0.0"
	}

	return out
}()

var concurrency = func() int {
	if v := os.Getenv("CONCURRENCY"); v != "" {
		pv, err := strconv.ParseUint(v, 10, bits.UintSize)
		if err != nil {
			panic(err)
		}

		// Ensure we always have at least 1 process
		if int(pv) < 1 {
			return 1
		}

		return int(pv)
	}
	return runtime.NumCPU()
}()

var linterDeadline = func() time.Duration {
	if v := os.Getenv("LINTER_DEADLINE"); v != "" {
		d, _ := time.ParseDuration(v)
		if d != 0 {
			return d
		}
	}
	return time.Minute
}()

func Log(args ...interface{}) {
	if mg.Verbose() {
		fmt.Println(args...)
	}
}

var concurrencyQueue chan struct{}
var concurrencyWg *sync.WaitGroup

// concurrentRun calls a function while respecting concurrency limits, and
// returns a promise-like function which will resolve to the value.
func concurrentRun[T any](fn func() T) func() T {
	concurrencyQueue <- struct{}{} // Acquire a job
	concurrencyWg.Add(1)           // Ensure we can wait

	rCh := make(chan T)
	go func() {
		rCh <- fn()
		<-concurrencyQueue   // Release a job
		concurrencyWg.Done() // Mark job finished
	}()

	return func() T {
		return <-rCh
	}
}

// waitResults accepts a map of operations and waits for them all to complete.
func waitResults(m map[string]func() error) func() error {
	type dispatch struct {
		k string
		v error
	}

	resultQueue := make(chan dispatch, len(m))
	for k, fn := range m {
		go func(k string, fn func() error) {
			resultQueue <- dispatch{
				k: k,
				v: fn(),
			}
		}(k, fn)
	}

	return func() error {
		buildError := false

		for range len(m) {
			result := <-resultQueue
			if result.v != nil {
				buildError = true
				fmt.Printf("Error: %s: %s\n", result.k, result.v)
			}
		}

		if buildError {
			return errParallelBuildFailed
		}
		return nil
	}
}

func init() {
	// Initialize concurrency queue
	concurrencyQueue = make(chan struct{}, concurrency)
	concurrencyWg = &sync.WaitGroup{}

	// Set environment
	os.Setenv("PATH", fmt.Sprintf("%s:%s", toolsBinDir, os.Getenv("PATH")))
	os.Setenv("GOBIN", toolsBinDir)
	Log("Build PATH: ", os.Getenv("PATH"))
	Log("Concurrency:", concurrency)
	goSrc = func() []string {
		results := new([]string)
		err := filepath.Walk(".", func(relpath string, info os.FileInfo, _ error) error {
			// Ensure absolute path so globs work
			path, err := filepath.Abs(relpath)
			if err != nil {
				panic(err)
			}

			// Look for files
			if info.IsDir() {
				return nil
			}

			// Exclusions
			for _, exclusion := range []string{toolsBinDir, binDir, releaseDir, coverageDir} {
				if strings.HasPrefix(path, exclusion) {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}

			if strings.Contains(path, "/vendor/") || strings.Contains(path, "/node_modules/") {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if strings.Contains(path, ".git") {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			// The build scripts themselves are excluded by build constraints.
			if filepath.Dir(path) == curDir && (info.Name() == "magefile.go" || info.Name() == "mage.go") {
				return nil
			}

			*results = append(*results, path)
			return nil
		})
		if err != nil {
			panic(err)
		}
		return *results
	}()
	goDirs = func() []string {
		resultMap := make(map[string]struct{})
		for _, path := range goSrc {
			absDir, err := filepath.Abs(filepath.Dir(path))
			if err != nil {
				panic(err)
			}
			resultMap[absDir] = struct{}{}
		}
		results := []string{}
		for k := range resultMap {
			results = append(results, k)
		}
		return results
	}()
	goPkgs = func() []string {
		results := []string{}
		out, err := sh.Output("go", "list", "./...")
		if err != nil {
			panic(err)
		}
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "/vendor/") {
				results = append(results, line)
			}
		}
		return results
	}
	goCmds = func() []string {
		results := []string{}

		finfos, err := os.ReadDir(cmdDir)
		if err != nil {
			panic(err)
		}
		for _, finfo := range finfos {
			// Each binary is a directory - skip files such as README.md
			if !finfo.IsDir() {
				continue
			}
			results = append(results, finfo.Name())
		}
		return results
	}()

	// Ensure output dirs exist
	for _, dir := range outputDirs {
		panicOnError(os.MkdirAll(dir, os.FileMode(OS_ALL_RWX)))
	}
}

// must consumes an error from a function.
func must[T any](result T, err error) T {
	if err != nil {
		panic(err)
	}
	return result
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// concurrencyLimitedBuild executes a certain number of commands limited by concurrency.
func concurrencyLimitedBuild(buildCmds ...interface{}) error {
	resultsCh := make(chan error, len(buildCmds))
	concurrencyControl := make(chan struct{}, concurrency)
	for _, buildCmd := range buildCmds {
		go func(buildCmd interface{}) {
			concurrencyControl <- struct{}{}
			resultsCh <- buildCmd.(func() error)()
			<-concurrencyControl
		}(buildCmd)
	}
	// Doesn't work at the moment
	//	mg.Deps(buildCmds...)
	results := []error{}
	var resultErr error = nil
	for len(results) < len(buildCmds) {
		err := <-resultsCh
		results = append(results, err)
		if err != nil {
			fmt.Println(err)
			resultErr = errors.Wrap(errParallelBuildFailed, "concurrencyLimitedBuild command failure")
		}
		fmt.Printf("Finished %v of %v\n", len(results), len(buildCmds))
	}

	return resultErr
}

// Tools builds build tools of the project and is depended on by all other build targets.
func Tools() (err error) {
	// Catch panics and convert to errors
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
	}()

	toolBuild := func(toolType string, tools ...[]string) error {
		toolTargets := []interface{}{}
		for _, toolImport := range tools {
			binName := toolImport[0]
			localToolImport := toolImport[1]

			if binName != "" {
				if _, err := os.Stat(path.Join(toolsBinDir, binName)); err == nil {
					// Skip named binary which we already have
					continue
				}
			}

			f := func() error {
				return sh.Run("go", "install", "-v", localToolImport)
			}
			toolTargets = append(toolTargets, f)
		}

		Log("Build", toolType, "tools")
		if berr := concurrencyLimitedBuild(toolTargets...); berr != nil {
			return berr
		}
		return nil
	}

	if berr := toolBuild("static", []string{"golangci-lint", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2"},
		[]string{"gocovmerge", "github.com/wadey/gocovmerge@latest"},
		[]string{"oapi-codegen", "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest"},
	); berr != nil {
		return berr
	}

	return nil
}

//nolint:perfsprint
func lintArgs(args ...string) []string {
	returnedArgs := []string{"-j", strconv.Itoa(concurrency), fmt.Sprintf(
		"--timeout=%s", linterDeadline.String())}
	returnedArgs = append(returnedArgs, args...)
	return returnedArgs
}

// Lint runs golangci-lint for code quality. CI will run this before accepting PRs.
func Lint() error {
	mg.Deps(Tools)
	extraArgs := lintArgs("run")
	extraArgs = append(extraArgs, goDirs...)
	return sh.RunV("golangci-lint", extraArgs...)
}

// LintBisect runs the linters one directory at a time.
// It is useful for finding problems where golangci-lint won't compile and
// doesn't emit an error message.
func LintBisect() error {
	errs := []error{}
	for _, goDir := range goDirs {
		fmt.Println("Linting:", goDir)
		err := sh.RunV("golangci-lint", lintArgs("run", goDir)...)
		if err != nil {
			fmt.Println("LINT ERROR IN:", goDir)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errLintBisect
	}
	return nil
}

// listLinters gets the golangci-lint config
func listLinters() ([]string, error) {
	cmd := exec.Command("golangci-lint", "linters")
	output, err := cmd.Output()
	if err != nil {
		return []string{}, errors.Wrap(err, "golangci-lint linters failed to run")
	}
	bio := bufio.NewReader(bytes.NewBuffer(output))
	linters := []string{}
	for {
		line, _ := bio.ReadString('\n')
		line = strings.Trim(line, " \n\t")
		if line == "" {
			continue
		}
		if line == "Enabled by your configuration linters:" {
			continue
		}
		if line == "Disabled by your configuration linters:" {
			// Done
			break
		}
		linter := strings.Split(line, ":")[0]
		linter = strings.Split(linter, "(")[0]
		linter = strings.Trim(linter, " \n\t")
		linters = append(linters, linter)
	}
	return linters, nil
}

// LintersBisect runs all linters in golangci-lint one at a time.
// It is useful find broken linters.
func LintersBisect() error {
	linters, err := listLinters()
	if err != nil {
		return errors.Wrap(err, "LintersBisect: listLinters failed")
	}
	errs := map[string]error{}

	//nolint:perfsprint
	for _, linter := range linters {
		// --enable-only overrides the configured linter set while keeping
		// the rest of the configuration.
		extraArgs := lintArgs("run", fmt.Sprintf("--enable-only=%s", linter))
		extraArgs = append(extraArgs, goDirs...)
		err := sh.RunV("golangci-lint", extraArgs...)
		if err != nil {
			errs[linter] = err
		}
	}

	if len(errs) > 0 {
		for linter := range errs {
			fmt.Println("FAILED LINTER:", linter)
		}

		return errLintBisect
	}
	return nil
}

// formattingLinter runs the golangci-lint formatters and style linters,
// either reporting or fixing problems.
func formattingLinter(doFixes bool) error {
	mg.Deps(Tools)
	fmtArgs := []string{"fmt", "--no-config", "--enable=gofmt", "--enable=goimports"}
	runArgs := []string{"run", "--no-config", "--default=none", "--enable=godot", "--enable=tagalign"}
	if doFixes {
		runArgs = append(runArgs, "--fix")
	} else {
		fmtArgs = append(fmtArgs, "--diff")
	}
	if err := sh.RunV("golangci-lint", fmtArgs...); err != nil {
		return err
	}
	return sh.RunV("golangci-lint", runArgs...)
}

// Style checks formatting of the file. CI will run this before acceptiing PRs.
func Style() error {
	return formattingLinter(false)
}

// Fmt automatically formats all source code files.
func Fmt() error {
	return formattingLinter(true)
}

func listCoverageFiles() ([]string, error) {
	result := []string{}
	finfos, derr := os.ReadDir(coverageDir)
	if derr != nil {
		return result, derr
	}
	for _, finfo := range finfos {
		result = append(result, path.Join(coverageDir, finfo.Name()))
	}
	return result, nil
}

// Test run test suite.
func Test() error {
	mg.Deps(Tools)
	mg.Deps(GoGenerate)

	// Ensure coverage directory exists
	if err := os.MkdirAll(coverageDir, os.FileMode(OS_ALL_RWX)); err != nil {
		return err
	}

	// Clean up coverage directory
	coverFiles, derr := listCoverageFiles()
	if derr != nil {
		return derr
	}
	for _, coverFile := range coverFiles {
		if err := sh.Rm(coverFile); err != nil {
			return err
		}
	}

	// Run tests
	//coverProfiles := []string{}
	//nolint:perfsprint
	for _, pkg := range goPkgs() {
		coverProfile := path.Join(coverageDir,
			fmt.Sprintf("%s%s", strings.ReplaceAll(pkg, "/", "-"), ".out"))
		testErr := sh.Run("go", "test", "-v", "-covermode", "count", fmt.Sprintf("-coverprofile=%s", coverProfile),
			pkg)
		if testErr != nil {
			return testErr
		}
		//coverProfiles = append(coverProfiles, coverProfile)
	}

	return nil
}

// Coverage sums up the coverage profiles in .coverage. It does not clean up after itself or before.
func Coverage() error {
	// Clean up coverage directory
	coverFiles, derr := listCoverageFiles()
	if derr != nil {
		return derr
	}

	mergedCoverage, err := sh.Output("gocovmerge", coverFiles...)
	if err != nil {
		return err
	}
	return os.WriteFile(constCoverFile, []byte(mergedCoverage), os.FileMode(OS_ALL_RWX))
}

// All runs a full suite suitable for CI
//
//nolint:unparam
func All() error {
	mg.SerialDeps(Style, Lint, Test, Coverage, ReleaseAll)
	return nil
}

// GithubReleaseMatrix emits a line to setup build matrix jobs for release builds.
//
//nolint:unparam
func GithubReleaseMatrix() error {
	output := make([]string, 0, len(platforms))
	for _, platform := range platforms {
		output = append(output, platform.String())
	}
	jsonData := must(json.Marshal(output))
	line := fmt.Sprintf("release-matrix=%s\n", string(jsonData))

	// GitHub Actions reads step outputs from the file named by GITHUB_OUTPUT.
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		fmt.Print(line)
		return nil
	}
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// GoGenerate runs go generate.
func GoGenerate() error {
	return sh.Run("go", "generate", "./...")
}

// webDir holds any embedded web interface.
var webDir = normalizePath(path.Join(curDir, "web"))

// nodeDistURL is where Node.js releases are downloaded from.
const nodeDistURL = "https://nodejs.org/dist"

// nodeVersionStamp records the Node.js version installed in nodeDir.
var nodeVersionStamp = path.Join(nodeDir, ".version")

// nodeBinDir holds the node and npm executables of the project's Node.js.
var nodeBinDir = path.Join(nodeDir, "bin")

// Node installs the Node.js version named by .nvmrc into nodeDir. The version
// may be exact, such as 22.23.3, or a prefix, such as 22, which selects the
// newest matching release. An installed version matching .nvmrc is kept.
func Node() error {
	want, err := nodeWantedVersion()
	if err != nil {
		return err
	}
	if installed, err := os.ReadFile(nodeVersionStamp); err == nil && nodeVersionMatches(string(installed), want) {
		return nil
	}

	version, err := nodeResolveVersion(want)
	if err != nil {
		return err
	}
	platform, err := nodePlatform()
	if err != nil {
		return err
	}
	archiveName := fmt.Sprintf("node-v%s-%s.tar.gz", version, platform)
	Log("Installing Node.js", version, "into", nodeDir)

	sums, err := httpGet(fmt.Sprintf("%s/v%s/SHASUMS256.txt", nodeDistURL, version))
	if err != nil {
		return err
	}
	wantSum, err := nodeArchiveChecksum(sums, archiveName)
	if err != nil {
		return err
	}
	archive, err := httpGet(fmt.Sprintf("%s/v%s/%s", nodeDistURL, version, archiveName))
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(archive); hex.EncodeToString(sum[:]) != wantSum {
		return fmt.Errorf("%s: checksum mismatch: got %x, want %s", archiveName, sum, wantSum)
	}

	// Extract beside nodeDir and swap it in, so a failed install leaves no
	// partial tree behind.
	tmpDir := nodeDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return err
	}
	if err := extractTarGz(archive, tmpDir, 1); err != nil {
		_ = os.RemoveAll(tmpDir)
		return fmt.Errorf("extracting %s: %w", archiveName, err)
	}
	if err := os.WriteFile(path.Join(tmpDir, ".version"), []byte(version), 0o644); err != nil {
		return err
	}
	if err := os.RemoveAll(nodeDir); err != nil {
		return err
	}
	return os.Rename(tmpDir, nodeDir)
}

// nodeWantedVersion reads the Node.js version from .nvmrc, without any "v".
func nodeWantedVersion() (string, error) {
	data, err := os.ReadFile(path.Join(curDir, ".nvmrc"))
	if err != nil {
		return "", fmt.Errorf("reading .nvmrc: %w", err)
	}
	want := strings.TrimPrefix(strings.TrimSpace(string(data)), "v")
	for _, part := range strings.Split(want, ".") {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return "", fmt.Errorf(".nvmrc: unsupported Node.js version %q: want a version such as 22 or 22.23.3",
				strings.TrimSpace(string(data)))
		}
	}
	return want, nil
}

// nodeVersionMatches reports whether version is want or a release of it.
func nodeVersionMatches(version, want string) bool {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	return version == want || strings.HasPrefix(version, want+".")
}

// nodeResolveVersion resolves a version prefix to the newest matching
// release.
func nodeResolveVersion(want string) (string, error) {
	if strings.Count(want, ".") == 2 {
		return want, nil
	}
	data, err := httpGet(nodeDistURL + "/index.json")
	if err != nil {
		return "", err
	}
	var releases []struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &releases); err != nil {
		return "", fmt.Errorf("parsing Node.js release index: %w", err)
	}
	// The index lists the newest releases first.
	for _, r := range releases {
		if nodeVersionMatches(r.Version, want) {
			return strings.TrimPrefix(r.Version, "v"), nil
		}
	}
	return "", fmt.Errorf("no Node.js release matches %s", want)
}

// nodePlatform names the Node.js release build for the host.
func nodePlatform() (string, error) {
	arch, ok := map[string]string{
		"amd64":   "x64",
		"arm64":   "arm64",
		"ppc64le": "ppc64le",
		"s390x":   "s390x",
	}[runtime.GOARCH]
	if !ok || (runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		return "", fmt.Errorf("%w: no Node.js build for %s/%s", errPlatformNotSupported, runtime.GOOS, runtime.GOARCH)
	}
	return runtime.GOOS + "-" + arch, nil
}

// nodeArchiveChecksum finds the SHA-256 of name in a SHASUMS256.txt file.
func nodeArchiveChecksum(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[1] == name {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum published for %s", name)
}

func httpGet(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec,noctx // URLs are built from nodeDistURL
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	return data, nil
}

// extractTarGz extracts a gzipped tarball into dir, dropping the first strip
// components of each path.
func extractTarGz(archive []byte, dir string, strip int) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		parts := strings.Split(strings.Trim(hdr.Name, "/"), "/")
		if len(parts) <= strip {
			continue
		}
		rel := filepath.Join(parts[strip:]...)
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		target := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode().Perm())
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr) //nolint:gosec // the archive's checksum was verified
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			if filepath.IsAbs(hdr.Linkname) {
				return fmt.Errorf("unsafe symlink in archive: %s -> %s", hdr.Name, hdr.Linkname)
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		}
	}
}

// npm runs the project's npm. Its bin directory is put first on the PATH, as
// npm and package scripts start node through it.
func npm(args ...string) error {
	mg.Deps(Node)
	env := map[string]string{"PATH": nodeBinDir + string(os.PathListSeparator) + os.Getenv("PATH")}
	return sh.RunWith(env, path.Join(nodeBinDir, "npm"), args...)
}

// Web builds the web interface into web/dist for embedding. It is skipped if
// web/package.json does not exist, or if SKIP_WEB=1 is set, e.g. when dist was
// built in an earlier stage.
func Web() error {
	if os.Getenv("SKIP_WEB") != "" {
		Log("SKIP_WEB set: not building the web interface")
		return nil
	}
	if _, err := os.Stat(path.Join(webDir, "package.json")); errors.Is(err, os.ErrNotExist) {
		Log("No web/package.json: not building the web interface")
		return nil
	}

	lockFile := path.Join(webDir, "package-lock.json")
	modulesStamp := path.Join(webDir, "node_modules", ".package-lock.json")
	if stale, err := target.Path(modulesStamp, lockFile); err != nil || stale {
		if err := npm("--prefix", webDir, "ci"); err != nil {
			return err
		}
	}

	stale, err := target.Dir(path.Join(webDir, "dist", "index.html"),
		path.Join(webDir, "src"), path.Join(curDir, "api"), path.Join(webDir, "index.html"),
		path.Join(webDir, "package.json"), path.Join(webDir, "vite.config.ts"))
	if err != nil || stale {
		return npm("--prefix", webDir, "run", "build")
	}
	return nil
}

func makeBuilder(cmd string, platform Platform) func() error {
	f := func() error {
		cmdSrc := fmt.Sprintf("./%s/%s", must(filepath.Rel(curDir, cmdDir)), cmd)

		Log("Make platform binary directory:", platform.PlatformDir())
		if err := os.MkdirAll(platform.PlatformDir(), os.FileMode(OS_ALL_RWX)); err != nil {
			return errors.Wrapf(err, "error making directory: cmd: %s", cmd)
		}

		Log("Checking for changes:", platform.PlatformBin(cmd))
		if changed, err := target.Path(platform.PlatformBin(cmd), goSrc...); !changed {
			if err != nil {
				if !os.IsNotExist(err) {
					return errors.Wrapf(err, "error while checking for changes: cmd: %s", cmd)
				}
			} else {
				return nil
			}
		}

		fmt.Println("Building", platform.PlatformBin(cmd))
		return sh.RunWith(map[string]string{"CGO_ENABLED": "0", "GOOS": platform.OS, "GOARCH": platform.Arch},
			"go", "build", "-a", "-ldflags", fmt.Sprintf("-buildid='' -extldflags '-static' -X %s=%s", versionSymbol(), version),
			"-trimpath", "-o", platform.PlatformBin(cmd), cmdSrc)
	}
	return f
}

func getCurrentPlatform() *Platform {
	var curPlatform *Platform
	for _, p := range platforms {
		if p.OS == runtime.GOOS && p.Arch == runtime.GOARCH {
			storedP := p
			curPlatform = &storedP
		}
	}
	Log("Determined current platform:", curPlatform)
	return curPlatform
}

// Binary build a binary for the current platform.
func Binary() error {
	curPlatform := getCurrentPlatform()
	if curPlatform == nil {
		return errPlatformNotSupported
	}

	if err := ReleaseBin(curPlatform.String()); err != nil {
		return err
	}

	buildResults := map[string]func() error{}

	for _, cmd := range goCmds {
		buildResults[cmd] = concurrentRun(func() error {
			// Make a root symlink to the build
			cmdPath := path.Join(curDir, cmd)
			os.Remove(cmdPath)
			if err := os.Symlink(curPlatform.PlatformBin(cmd), cmdPath); err != nil {
				return err
			}
			return nil
		})
	}

	return waitResults(buildResults)()
}

// doReleaseBin handles the deferred building of an actual release binary.
//
//nolint:gocritic
func doReleaseBin(OSArch string) func() error {
	mg.Deps(GoGenerate, Web)

	platform, ok := platformsLookup[OSArch]
	if !ok {
		return func() error { return errors.Wrapf(errPlatformNotSupported, "ReleaseBin: %s", OSArch) }
	}

	buildResults := map[string]func() error{}

	for _, cmd := range goCmds {
		buildResults[cmd] = concurrentRun(makeBuilder(cmd, platform))
	}

	return waitResults(buildResults)
}

// ReleaseBin builds cross-platform release binaries under the bin/ directory.
//
//nolint:gocritic
func ReleaseBin(OSArch string) error {
	return doReleaseBin(OSArch)()
}

// ReleaseBinAll builds cross-platform release binaries under the bin/ directory.
func ReleaseBinAll() error {
	buildResults := map[string]func() error{}
	for OSArch := range platformsLookup {
		buildResults[fmt.Sprintf("build-%s", OSArch)] = doReleaseBin(OSArch)
	}

	return waitResults(buildResults)()
}

// Release builds release archives under the release/ directory.
//
//nolint:gocritic
func doRelease(OSArch string) func() error {
	platform, ok := platformsLookup[OSArch]
	if !ok {
		return func() error { return errors.Wrapf(errPlatformNotSupported, "ReleaseBin: %s", OSArch) }
	}

	return func() error {
		if err := ReleaseBin(OSArch); err != nil {
			return err
		}

		archiveCmds := map[string]func() error{}
		if platform.OS == "windows" {
			// build a zip binary as well
			archiveName := fmt.Sprintf("%s.zip", platform.ReleaseBase())
			archiveCmds[archiveName] = concurrentRun(func() error {
				if _, err := os.Stat(archiveName); err == nil {
					_ = os.Remove(archiveName)
				}
				archiveDir := path.Join(binDir, platform.ArchiveDir())
				fmt.Println("Archiving", archiveName)
				return archiver.NewZip().Archive([]string{archiveDir}, archiveName)
			})
		}

		// build tar gz
		archiveName := fmt.Sprintf("%s.tar.gz", platform.ReleaseBase())
		archiveCmds[archiveName] = concurrentRun(func() error {
			if _, err := os.Stat(archiveName); err == nil {
				_ = os.Remove(archiveName)
			}
			archiveDir := path.Join(binDir, platform.ArchiveDir())
			fmt.Println("Archiving", archiveName)
			return archiver.NewTarGz().Archive([]string{archiveDir}, archiveName)
		})

		return waitResults(archiveCmds)()
	}
}

// PlatformTargets prints the list of target platforms
func PlatformTargets() error {
	platforms := make([]string, 0, len(platformsLookup))
	for platform := range platformsLookup {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	for _, platform := range platforms {
		fmt.Println(platform)
	}
	return nil
}

// Release a binary archive for a specific platform
//
//nolint:gocritic
func Release(OSArch string) error {
	return doRelease(OSArch)()
}

// Release builds release archives under the release/ directory.
func ReleaseAll() error {
	buildResults := map[string]func() error{}
	for OSArch := range platformsLookup {
		buildResults[fmt.Sprintf("release-%s", OSArch)] = doRelease(OSArch)
	}

	return waitResults(buildResults)()
}

// Clean deletes build output and cleans up the working directory.
func Clean() error {
	// Remove the root symlinks made by Binary
	for _, name := range goCmds {
		if err := sh.Rm(path.Join(curDir, name)); err != nil {
			return err
		}
	}

	for _, name := range outputDirs {
		if err := sh.Rm(name); err != nil {
			return err
		}
	}
	return nil
}

// Debug prints the value of internal state variables
//
//nolint:unparam
func Debug() error {
	mg.Deps(GoGenerate)

	fmt.Println("Source Files:", goSrc)
	fmt.Println("Packages:", goPkgs())
	fmt.Println("Directories:", goDirs)
	fmt.Println("Command Paths:", goCmds)
	fmt.Println("Output Dirs:", outputDirs)
	fmt.Println("PATH:", os.Getenv("PATH"))

	fmt.Println("Version:", version)
	fmt.Println("Version short:", versionShort)
	fmt.Println("Version symbol:", versionSymbol())
	return nil
}

// Autogen configure local git repository with commit hooks.
func Autogen() error {
	if _, err := os.Stat(gitHookDir); errors.Is(err, os.ErrNotExist) {
		fmt.Println("No", constGitHookDir, "directory: no git hooks to install")
		return nil
	}
	fmt.Println("Installing git hooks in local repository...")

	for _, fname := range must(os.ReadDir(gitHookDir)) {
		hookName := fname.Name()
		if !fname.IsDir() {
			continue
		}

		gitHookPath := fmt.Sprintf(".git/hooks/%s", hookName)
		repoHookPath := path.Join(gitHookDir, fname.Name())

		scripts := []string{}
		for _, scriptName := range must(os.ReadDir(repoHookPath)) {
			if scriptName.IsDir() {
				continue
			}
			fullHookPath := path.Join(gitHookDir, hookName, scriptName.Name())
			relHookPath := must(filepath.Rel(binRootName, fullHookPath))

			scripts = append(scripts, relHookPath)

			data, err := os.ReadFile(gitHookPath)
			if err != nil {
				data = []byte("#!/bin/bash\n")
			}

			splitHook := strings.Split(string(data), "\n")
			if strings.TrimRight(splitHook[0], " \t") != "#!/bin/bash" {
				fmt.Printf("Don't know how to update your %s script.\n", hookName)
				return errAutogenUnknownPreCommitScriptFormat
			}

			headAt := -1
			tailAt := -1
			for idx, line := range splitHook {
				// Search until header.
				if strings.TrimPrefix(line, " ") == constManagedScriptSectionHead {
					if headAt != -1 {
						fmt.Println("Found multiple managed script sections in ", fname.Name(), "first was at line ", headAt, "second was at line ", idx)
						return errAutogenMultipleScriptSections
					}
					headAt = idx
					continue
				} else if strings.TrimPrefix(line, " ") == constManagedScriptSectionFoot {
					if tailAt != -1 {
						fmt.Println("Found multiple managed script sections in ", fname.Name(), "first was at line ", headAt, "second was at line ", idx)
						return errAutogenMultipleScriptSections
					}
					tailAt = idx + 1
					continue
				}
			}

			if headAt == -1 {
				headAt = 1
			}

			if tailAt == -1 {
				tailAt = len(splitHook)
			}

			scriptPackage := []string{constManagedScriptSectionHead}
			scriptPackage = append(scriptPackage, "# These lines were added by go run mage.go autogen.", "")
			for _, scriptPath := range scripts {
				scriptPackage = append(scriptPackage, fmt.Sprintf("\"./%s\" || exit $?", scriptPath))
			}
			scriptPackage = append(scriptPackage, "", constManagedScriptSectionFoot)

			updatedScript := splitHook[:headAt]
			updatedScript = append(updatedScript, scriptPackage...)
			updatedScript = append(updatedScript, splitHook[tailAt:]...)

			err = os.WriteFile(gitHookPath, []byte(strings.Join(updatedScript, "\n")),
				os.FileMode(OS_ALL_RW|OS_USER_X))
			if err != nil {
				return err
			}
		}
	}

	return nil
}
