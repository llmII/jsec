
# Table of Contents

1.  [Overview](#org90909d1)
2.  [C Code](#org9492986)
    1.  [Formatting](#org9106261)
    2.  [Naming](#orgf39957a)
    3.  [comments](#orgeac9b9a)
    4.  [OpenSSL](#org9dcc446)
3.  [Janet Code](#org7829b53)
    1.  [Formatting](#org99ea724)
    2.  [Naming](#org62d6135)
    3.  [Documentation](#org9a866c9)
4.  [Testing](#org28ea8a5)



<a id="org90909d1"></a>

# Overview

This document defines the coding style for the jsec project.


<a id="org9492986"></a>

# C Code


<a id="org9106261"></a>

## Formatting

-   ****Indentation****: 4 spaces. No tabs.
-   ****Braces****: K&R style (opening brace on the same line).
    
        if (condition) {
            statement;
        } else {
            statement;
        }
-   ****Line Length****: Try to keep under 80 characters, but clarity is priority.


<a id="orgf39957a"></a>

## Naming

-   ****Variables/Functions****: \`snake<sub>case</sub>\`.
-   ****Types****: \`PascalCase\` (e.g., \`TLSStream\`).
-   ****Macros****: \`UPPER<sub>CASE</sub>\`.


<a id="orgeac9b9a"></a>

## comments

-   Use \`/\* \*/\` for multi-line comments.
-   Use \`//\` for single-line comments.
-   Comments should explain **why**, not **what**.


<a id="org9dcc446"></a>

## OpenSSL

-   Do not use deprecated functions (e.g., avoid \`RSA<sub>new</sub>\`, use \`EVP<sub>PKEY</sub>\`).
-   Check return values of all OpenSSL functions.
-   Always clear the error queue or handle errors appropriately.


<a id="org7829b53"></a>

# Janet Code


<a id="org99ea724"></a>

## Formatting

-   ****Indentation****: 2 spaces.
-   ****Braces/Parens****: Standard Lisp style (trailing parens on the same line).


<a id="org62d6135"></a>

## Naming

-   ****Functions/Macros****: \`kebab-case\`.
-   ****Globals/Dynamics****: \`\*kebab-case\*\`.


<a id="org9a866c9"></a>

## Documentation

-   Public functions must have docstrings.


<a id="org28ea8a5"></a>

# Testing

-   Write tests for every new feature.
-   Use \`jsec/test/helper.janet\` for common utilities.
-   Ensure tests clean up resources (use \`defer\`).

