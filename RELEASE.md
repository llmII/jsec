
# Table of Contents

1.  [Release Checklist](#org9a65954)
    1.  [Pre-Release](#org7dcbc9e)
    2.  [Version Numbering](#org2ed16c8)
    3.  [Release Steps](#orgea2bbb5)
    4.  [Post-Release](#org614cbfb)
    5.  [Development vs Release](#org329a125)
    6.  [Quality Gates](#orga49071c)
    7.  [Emergency Releases](#orgea71163)
2.  [Available Build Targets](#org7a33f7f)
3.  [Distribution](#org7030f46)
    1.  [Janet Package Manager (JPM)](#org6215ac8)
    2.  [Manual Installation (Fossil)](#org306646d)
    3.  [Manual Installation (Git Mirror)](#org877b843)
    4.  [Dependencies](#orgc200d30)
4.  [Testing](#org8bc3dbb)
    1.  [Running Tests](#org90c4930)
    2.  [Performance Testing](#org85249a5)
5.  [Support Policy](#orge3ab555)



<a id="org9a65954"></a>

# Release Checklist


<a id="org7dcbc9e"></a>

## Pre-Release

1.  Ensure all tests pass:
    
        janet test/runner.janet -f '{unit,regression,coverage}'
2.  Run sanitizer tests (ASan/UBSan):
    
        jpm run test-sanitized
3.  Check for memory leaks:
    
        jpm run leak-check
4.  Update version in `project.janet`
5.  Update [NEWS.org](NEWS.md) with changes since last release
6.  Review and update documentation
7.  Format all code:
    
        jpm run format
8.  Build clean and test:
    
        jpm clean && jpm build && jpm install
        janet test/runner.janet -f '{unit,regression,coverage}'


<a id="org2ed16c8"></a>

## Version Numbering

jsec follows semantic versioning (SemVer):

-   **MAJOR**: Incompatible API changes
-   **MINOR**: Backwards-compatible functionality additions
-   **PATCH**: Backwards-compatible bug fixes

Example: `1.2.3`

-   Major: 1
-   Minor: 2
-   Patch: 3


<a id="orgea2bbb5"></a>

## Release Steps

1.  **Update Version**
    
        # In project.janet
        (declare-project
          :name "jsec"
          :version "1.0.0"  # Update this
          ...)

2.  **Update NEWS.org**
    
    Document all changes, fixes, and new features.

3.  **Prepare Release**
    
        jpm run release
    
    This runs `clean` and `format` targets.

4.  **Final Testing**
    
        jpm clean && jpm build && jpm install
        janet test/runner.janet -f '{unit,regression,coverage}'

5.  **Commit Release**
    
        fossil commit -m "Release version X.Y.Z"

6.  **Tag Release**
    
        fossil tag add vX.Y.Z tip

7.  **Push to Repository**
    
        fossil push

8.  **Mirror to GitHub** (for wider distribution)
    
        fossil git export ../jsec-git --force
        cd ../jsec-git && git push origin main --tags


<a id="org614cbfb"></a>

## Post-Release

1.  Verify installation from repository
2.  Update dependent projects if needed
3.  Announce release
4.  Begin next development cycle


<a id="org329a125"></a>

## Development vs Release

-   **Development**: Version ends in `-dev` (e.g., `1.1.0-dev`)
-   **Release**: Clean version number (e.g., `1.1.0`)

After a release, immediately bump to next dev version:

-   `1.0.0` → `1.0.1-dev` (for patch development)
-   `1.0.0` → `1.1.0-dev` (for minor development)
-   `1.0.0` → `2.0.0-dev` (for major development)


<a id="orga49071c"></a>

## Quality Gates

All of these must pass before release:

-   [ ] All tests pass (unit, regression, coverage categories)
-   [ ] No ASan/UBSan errors (when these tools work appropriately)
-   [ ] No memory leaks detected by valgrind (elide for now, valgrind is slow)
-   [ ] Documentation is current
-   [ ] Examples all work
-   [ ] Code is formatted (`jpm run format`)
-   [ ] NEWS.org is updated
-   [ ] Version is bumped appropriately


<a id="orgea71163"></a>

## Emergency Releases

For critical security fixes:

1.  Create hotfix branch from release tag
2.  Apply minimal fix
3.  Test thoroughly
4.  Release as patch version
5.  Backport fix to development branch


<a id="org7a33f7f"></a>

# Available Build Targets

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Target</th>
<th scope="col" class="org-left">Description</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left"><code>format</code></td>
<td class="org-left">Format all code (C and Janet)</td>
</tr>

<tr>
<td class="org-left"><code>format-c</code></td>
<td class="org-left">Format C code with astyle</td>
</tr>

<tr>
<td class="org-left"><code>format-janet</code></td>
<td class="org-left">Format Janet code with janet-format</td>
</tr>

<tr>
<td class="org-left"><code>release</code></td>
<td class="org-left">Clean and format for release</td>
</tr>

<tr>
<td class="org-left"><code>leak-check</code></td>
<td class="org-left">Run valgrind memory leak detection</td>
</tr>

<tr>
<td class="org-left"><code>tidy</code></td>
<td class="org-left">Run clang-tidy static analysis</td>
</tr>

<tr>
<td class="org-left"><code>tidy-fix</code></td>
<td class="org-left">Run clang-tidy with auto-fix</td>
</tr>

<tr>
<td class="org-left"><code>test-sanitized</code></td>
<td class="org-left">Build and test with ASan/UBSan</td>
</tr>

<tr>
<td class="org-left"><code>clean</code></td>
<td class="org-left">Remove build artifacts</td>
</tr>
</tbody>
</table>


<a id="org7030f46"></a>

# Distribution


<a id="org6215ac8"></a>

## Janet Package Manager (JPM)

jsec is installed via `jpm`:

    # From GitHub mirror
    jpm install https://github.com/llmII/jsec
    
    # From Fossil repository (preferred)
    jpm install https://fossil.example.org/jsec


<a id="org306646d"></a>

## Manual Installation (Fossil)

From source using Fossil:

    fossil clone https://code.amlegion.org/jsec jsec.fossil
    mkdir jsec && cd jsec
    fossil open ../jsec.fossil
    jpm build
    jpm install


<a id="org877b843"></a>

## Manual Installation (Git Mirror)

From the GitHub mirror:

    git clone https://github.com/llmII/jsec.git
    cd jsec
    jpm build
    jpm install


<a id="orgc200d30"></a>

## Dependencies

-   Janet 1.30+
-   OpenSSL 1.1.1+ or 3.x
-   spork (Janet package)


<a id="org8bc3dbb"></a>

# Testing

jsec uses the [assay](https://github.com/llmII/janet-assay) testing framework.


<a id="org90c4930"></a>

## Running Tests

    # Run unit, regression, and coverage tests (recommended)
    janet test/runner.janet -f '{unit,regression,coverage}'
    
    # Run all tests including performance (takes hours)
    janet test/runner.janet
    
    # Dry run to see what would execute
    janet test/runner.janet -f '{unit,regression,coverage}' --dry-run
    
    # Verbose output
    janet test/runner.janet -f '{unit,regression,coverage}' --verbosity 2


<a id="org85249a5"></a>

## Performance Testing

Performance tests are separate and run for extended periods:

    # Run performance tests
    janet test/runner.janet -f 'performance'
    
    # Analyze results
    ./bin/perf9-analyze /tmp/perf-results.json

See [docs/TESTING.org](docs/TESTING.md) for comprehensive testing documentation.


<a id="orge3ab555"></a>

# Support Policy

-   **Current Release**: Full support
-   **Previous Minor**: Security fixes only
-   **Older Releases**: Unsupported

Users should upgrade to the latest release. While version is prior to 1.0 the
support policy does not apply.

