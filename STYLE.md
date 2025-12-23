
# Table of Contents

1.  [Overview](#org13aabf8)
2.  [C Code](#org747a5a0)
    1.  [Formatting](#orgeab014a)
    2.  [Naming](#orga01fb5e)
    3.  [comments](#org653cc0c)
    4.  [OpenSSL](#org569bd55)
3.  [Janet Code](#org4e6f369)
    1.  [Formatting](#org5ca0917)
    2.  [Naming](#orgd4b9144)
    3.  [Documentation](#org42dc7b7)
4.  [Testing](#orgda5aef3)



<a id="org13aabf8"></a>

# Overview

This document defines the coding style for the jsec project.


<a id="org747a5a0"></a>

# C Code


<a id="orgeab014a"></a>

## Formatting

-   ****Indentation****: 4 spaces. No tabs.
-   ****Braces****: K&R style (opening brace on the same line).
    
        if (condition) {
            statement;
        } else {
            statement;
        }
-   ****Line Length****: Try to keep under 80 characters, but clarity is priority.


<a id="orga01fb5e"></a>

## Naming

-   ****Variables/Functions****: \`snake<sub>case</sub>\`.
-   ****Types****: \`PascalCase\` (e.g., \`TLSStream\`).
-   ****Macros****: \`UPPER<sub>CASE</sub>\`.


<a id="org653cc0c"></a>

## comments

-   Use \`/\* \*/\` for multi-line comments.
-   Use \`//\` for single-line comments.
-   Comments should explain **why**, not **what**.


<a id="org569bd55"></a>

## OpenSSL

-   Do not use deprecated functions (e.g., avoid \`RSA<sub>new</sub>\`, use \`EVP<sub>PKEY</sub>\`).
-   Check return values of all OpenSSL functions.
-   Always clear the error queue or handle errors appropriately.


<a id="org4e6f369"></a>

# Janet Code


<a id="org5ca0917"></a>

## Formatting

-   ****Indentation****: 2 spaces.
-   ****Braces/Parens****: Standard Lisp style (trailing parens on the same line).


<a id="orgd4b9144"></a>

## Naming

-   ****Functions/Macros****: \`kebab-case\`.
-   ****Globals/Dynamics****: \`\*kebab-case\*\`.


<a id="org42dc7b7"></a>

## Documentation

-   Public functions must have docstrings.


<a id="orgda5aef3"></a>

# Testing

-   Write tests for every new feature.
-   Use \`jsec/test/helper.janet\` for common utilities.
-   Ensure tests clean up resources (use \`defer\`).

