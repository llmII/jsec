

# Overview

jsec supports Linux, FreeBSD, macOS, DragonflyBSD, NetBSD, OpenBSD, and Windows.

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Platform</th>
<th scope="col" class="org-left">SSL Library</th>
<th scope="col" class="org-left">Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left">Linux</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">Primary dev platform</td>
</tr>

<tr>
<td class="org-left">FreeBSD</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">System OpenSSL</td>
</tr>

<tr>
<td class="org-left">macOS</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">Via Homebrew</td>
</tr>

<tr>
<td class="org-left">DragonflyBSD</td>
<td class="org-left">LibreSSL</td>
<td class="org-left">System LibreSSL 3.6+</td>
</tr>

<tr>
<td class="org-left">NetBSD</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">System OpenSSL</td>
</tr>

<tr>
<td class="org-left">OpenBSD</td>
<td class="org-left">LibreSSL</td>
<td class="org-left">System LibreSSL 3.9+</td>
</tr>

<tr>
<td class="org-left">Windows</td>
<td class="org-left">OpenSSL 3.x</td>
<td class="org-left">Via vcpkg</td>
</tr>
</tbody>
</table>


## Janet Version Requirements

jsec currently builds and tests against **Janet git master**. This is because
git master contains a fix for a Unix domain socket bug on BSD platforms that
has not yet been included in a stable release. Once the next Janet release is
available with this fix, jsec will target the latest stable release, only
deviating when blocked by a bug in Janet itself.

For building Janet from source, see the official instructions:
<https://janet-lang.org/docs/index.html>


# Linux


## Prerequisites

    # Debian/Ubuntu
    sudo apt install build-essential libssl-dev git
    
    # Fedora/RHEL
    sudo dnf install gcc openssl-devel git
    
    # Arch
    sudo pacman -S base-devel openssl git

Build Janet from source (see <https://janet-lang.org/docs/index.html>):

    git clone https://github.com/janet-lang/janet.git
    cd janet
    make && sudo make install


## Building jsec

    cd jsec
    jpm clean && jpm build && jpm install


## Running Tests

    janet test/runner.janet --verbosity 2 -j thread:4


# FreeBSD


## Prerequisites

OpenSSL is included in the base system.

Build Janet from source (see <https://janet-lang.org/docs/index.html>):

    pkg install git gmake
    git clone https://github.com/janet-lang/janet.git
    cd janet
    gmake && gmake install


## Building jsec

    cd jsec
    jpm clean && jpm build && jpm install


## Notes

-   FreeBSD uses kqueue for event loop
-   All TLS and DTLS tests pass
-   Unix socket tests work correctly


# macOS


## Prerequisites

macOS system LibreSSL 3.3.6 is too old. Use Homebrew OpenSSL:

    # Install Homebrew if needed
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Install OpenSSL
    brew install openssl@3

Build Janet from source (see <https://janet-lang.org/docs/index.html>):

    git clone https://github.com/janet-lang/janet.git
    cd janet
    make && make install

Or install via Homebrew (may not be latest git):

    brew install janet


## Building jsec

`project.janet` auto-detects Homebrew OpenSSL:

-   ARM Mac (M1/M2/M3): `/opt/homebrew/opt/openssl@3`
-   Intel Mac: `/usr/local/opt/openssl@3`

    cd jsec
    jpm clean && jpm build && jpm install

Override with environment variable if needed:

    OPENSSL_PREFIX=/custom/path jpm build


## Verification

Verify jsec links to Homebrew OpenSSL (not system LibreSSL):

    otool -L build/jsec/tls-stream.so
    # Should show /opt/homebrew/opt/openssl@3/lib/libssl.*.dylib


# DragonflyBSD


## Prerequisites

DragonflyBSD ships with LibreSSL 3.6+ which has all required APIs.

Build Janet from source (see <https://janet-lang.org/docs/index.html>):

    pkg install git gmake
    git clone https://github.com/janet-lang/janet.git
    cd janet
    gmake && gmake install


## Building jsec

    cd jsec
    jpm clean && jpm build && jpm install


## Notes

-   Uses csh shell by default: use `setenv` instead of `export`
-   LibreSSL compatibility layer handles API differences


# NetBSD


## Prerequisites

NetBSD uses OpenSSL 3.x from base.

Build Janet from source (see <https://janet-lang.org/docs/index.html>):

    pkgin install git gmake
    git clone https://github.com/janet-lang/janet.git
    cd janet
    gmake && gmake install


## Building jsec

    cd jsec
    jpm clean && jpm build && jpm install


## Notes

-   Test suite runs ~2.4x slower than Linux (VM/platform overhead)
-   All tests pass


# OpenBSD


## Prerequisites

OpenBSD ships with LibreSSL 3.9+ in base.

Build Janet from source (see <https://janet-lang.org/docs/index.html>):

    pkg_add git gmake
    git clone https://github.com/janet-lang/janet.git
    cd janet
    gmake && doas gmake install


## Building jsec

    cd jsec
    jpm clean && jpm build && jpm install


## Notes

-   LibreSSL 3.9+ has all required APIs
-   All tests pass on OpenBSD 7.6


# Windows


## Prerequisites

1.  **Visual Studio 2022** (Build Tools or Community Edition)
    -   Install "Desktop development with C++" workload

2.  **Janet** - Download the Windows installer from <https://janet-lang.org>
    -   Add to PATH

3.  **vcpkg** (Package Manager)

**Note:** On Windows, use the official Janet installer rather than building
from source. Building Janet on Windows requires additional setup.


## Installing vcpkg and OpenSSL

    cd C:\Users\%USERNAME%\sources
    git clone https://github.com/microsoft/vcpkg.git
    cd vcpkg
    bootstrap-vcpkg.bat
    vcpkg install openssl:x64-windows

Set environment variable (optional):

    setx VCPKG_ROOT "C:\Users\%USERNAME%\sources\vcpkg"


## Building jsec

Use "x64 Native Tools Command Prompt for VS 2022":

    cd path\to\jsec
    jpm build

Or from regular Command Prompt:

    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
    jpm build


## Running Tests

    janet test/runner.janet

Unix socket tests are automatically skipped on Windows.


## Troubleshooting


### LNK1181: cannot open input file 'janet.lib'

The jpm default configuration may have incorrect paths. Edit:

    notepad "%LOCALAPPDATA%\Apps\Janet\Library\jpm\default-config.janet"

Fix the paths:

    ;; Change these to point to actual location of janet.lib:
    :janet-importlib "C:/Users/YourName/AppData/Local/Apps/Janet/C/janet.lib"
    :libpath "C:/Users/YourName/AppData/Local/Apps/Janet/C"


### DLL Not Found

Add vcpkg bin to PATH:

    set PATH=%VCPKG_ROOT%\installed\x64-windows\bin;%PATH%


## Platform Limitations

-   No Unix domain sockets (`AF_UNIX`)
-   IOCP reports connect success immediately; errors visible on first I/O
-   Use backslash paths (handled automatically by build system)


# Common Information


## Testing Commands

All platforms use the same test runner:

    # Full suite with parallel threads
    janet test/runner.janet --verbosity 2 -j thread:4
    
    # Filter specific tests
    janet test/runner.janet --filter "tls"
    janet test/runner.janet --filter "dtls"
    
    # Unit tests only
    janet test/runner.janet --filter "unit/*"


## Environment Variables

<table border="2" cellspacing="0" cellpadding="6" rules="groups" frame="hsides">


<colgroup>
<col  class="org-left" />

<col  class="org-left" />
</colgroup>
<thead>
<tr>
<th scope="col" class="org-left">Variable</th>
<th scope="col" class="org-left">Purpose</th>
</tr>
</thead>
<tbody>
<tr>
<td class="org-left">OPENSSL_PREFIX</td>
<td class="org-left">Override OpenSSL location (macOS/custom)</td>
</tr>

<tr>
<td class="org-left">VCPKG_ROOT</td>
<td class="org-left">vcpkg installation path (Windows)</td>
</tr>

<tr>
<td class="org-left">JANET_PATH</td>
<td class="org-left">Janet module search path</td>
</tr>
</tbody>
</table>


## Known Issues


### BSD Unix Socket Bug

**Status:** Fixed in Janet git master. Awaiting next stable release.

**Workaround:** Build Janet from git master (as documented above).


## LibreSSL Compatibility

DragonflyBSD and OpenBSD use LibreSSL. The compatibility layer in
`src/compat.h` handles API differences:

-   Conditional includes for `core_names.h` (OpenSSL 3.0 only)
-   Fallbacks for `OSSL_PKEY_PARAM` macros
-   Guards for `SSL_OP_NO_RENEGOTIATION`


## Verification

After building, verify jsec loads correctly:

    janet -e '(import jsec) (print "jsec loaded successfully")'

