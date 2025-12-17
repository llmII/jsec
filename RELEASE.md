
# Table of Contents

1.  [Release Checklist](#org66bd395)
    1.  [Pre-Release](#orga664e3d)
    2.  [Version Numbering](#org3ead5ca)
    3.  [Release Steps](#orgdbb680b)
    4.  [Post-Release](#orgd4f9072)
    5.  [Development vs Release](#orgd1232fe)
    6.  [Quality Gates](#orge8c11f3)
    7.  [Emergency Releases](#orgda6f5eb)
2.  [Available Build Targets](#orgf01ebc0)
3.  [Distribution](#orgbe6cb89)
    1.  [Janet Package Manager (JPM)](#orgc81cca9)
    2.  [Manual Installation (Fossil)](#org9529252)
    3.  [Manual Installation (Git Mirror)](#org16c9d76)
    4.  [Dependencies](#org131cfb9)
4.  [Testing](#org148e045)
    1.  [Running Tests](#org912fee7)
    2.  [Performance Testing](#orgc917d9d)
5.  [Support Policy](#orga081bcd)



<a id="org66bd395"></a>

# Release Checklist


<a id="orga664e3d"></a>

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


<a id="org3ead5ca"></a>

## Version Numbering

jsec follows semantic versioning (SemVer):

-   **MAJOR**: Incompatible API changes
-   **MINOR**: Backwards-compatible functionality additions
-   **PATCH**: Backwards-compatible bug fixes

Example: `1.2.3`

-   Major: 1
-   Minor: 2
-   Patch: 3


<a id="orgdbb680b"></a>

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


<a id="orgd4f9072"></a>

## Post-Release

1.  Verify installation from repository
2.  Update dependent projects if needed
3.  Announce release
4.  Begin next development cycle


<a id="orgd1232fe"></a>

## Development vs Release

-   **Development**: Version ends in `-dev` (e.g., `1.1.0-dev`)
-   **Release**: Clean version number (e.g., `1.1.0`)

After a release, immediately bump to next dev version:

-   `1.0.0` → `1.0.1-dev` (for patch development)
-   `1.0.0` → `1.1.0-dev` (for minor development)
-   `1.0.0` → `2.0.0-dev` (for major development)


<a id="orge8c11f3"></a>

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


<a id="orgda6f5eb"></a>

## Emergency Releases

For critical security fixes:

1.  Create hotfix branch from release tag
2.  Apply minimal fix
3.  Test thoroughly
4.  Release as patch version
5.  Backport fix to development branch


<a id="orgf01ebc0"></a>

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


<a id="orgbe6cb89"></a>

# Distribution


<a id="orgc81cca9"></a>

## Janet Package Manager (JPM)

jsec is installed via `jpm`:

    # From GitHub mirror
    jpm install https://github.com/llmII/jsec
    
    # From Fossil repository (preferred)
    jpm install https://fossil.example.org/jsec


<a id="org9529252"></a>

## Manual Installation (Fossil)

From source using Fossil:

    fossil clone https://code.amlegion.org/jsec jsec.fossil
    mkdir jsec && cd jsec
    fossil open ../jsec.fossil
    jpm build
    jpm install


<a id="org16c9d76"></a>

## Manual Installation (Git Mirror)

From the GitHub mirror:

    git clone https://github.com/llmII/jsec.git
    cd jsec
    jpm build
    jpm install


<a id="org131cfb9"></a>

## Dependencies

-   Janet 1.30+
-   OpenSSL 3.0+
-   spork (Janet package)


<a id="org148e045"></a>

# Testing

jsec uses the [assay](https://github.com/llmII/janet-assay) testing framework.


<a id="org912fee7"></a>

## Running Tests

    # Run unit, regression, and coverage tests (recommended)
    janet test/runner.janet -f '{unit,regression,coverage}'
    
    # Run all tests including performance (takes hours)
    janet test/runner.janet
    
    # Dry run to see what would execute
    janet test/runner.janet -f '{unit,regression,coverage}' --dry-run
    
    # Verbose output
    janet test/runner.janet -f '{unit,regression,coverage}' --verbosity 2


<a id="orgc917d9d"></a>

## Performance Testing

Performance tests are separate and run for extended periods:

    # Run performance tests
    janet test/runner.janet -f 'performance'
    
    # Analyze results
    ./bin/perf9-analyze /tmp/perf-results.json

See [docs/TESTING.org](docs/TESTING.md) for comprehensive testing documentation.


<a id="orga081bcd"></a>

# Support Policy

-   **Current Release**: Full support
-   **Previous Minor**: Security fixes only
-   **Older Releases**: Unsupported

Users should upgrade to the latest release. While version is prior to 1.0 the
support policy does not apply.

