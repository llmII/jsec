
# Table of Contents

1.  [Overview](#orgafac667)
2.  [C Code](#org2642673)
    1.  [Formatting](#org7fbd2a2)
    2.  [Naming](#orgeb3fe4a)
    3.  [comments](#org587aa48)
    4.  [OpenSSL](#org713c659)
3.  [Janet Code](#org9427aec)
    1.  [Formatting](#org4a7878d)
    2.  [Naming](#orgce029d3)
    3.  [Documentation](#org92f94cd)
4.  [Testing](#org8a5e47a)



<a id="orgafac667"></a>

# Overview

This document defines the coding style for the jsec project.


<a id="org2642673"></a>

# C Code


<a id="org7fbd2a2"></a>

## Formatting

-   ****Indentation****: 4 spaces. No tabs.
-   ****Braces****: K&R style (opening brace on the same line).
    
        if (condition) {
            statement;
        } else {
            statement;
        }
-   ****Line Length****: Try to keep under 80 characters, but clarity is priority.


<a id="orgeb3fe4a"></a>

## Naming

-   ****Variables/Functions****: \`snake<sub>case</sub>\`.
-   ****Types****: \`PascalCase\` (e.g., \`TLSStream\`).
-   ****Macros****: \`UPPER<sub>CASE</sub>\`.


<a id="org587aa48"></a>

## comments

-   Use \`/\* \*/\` for multi-line comments.
-   Use \`//\` for single-line comments.
-   Comments should explain **why**, not **what**.


<a id="org713c659"></a>

## OpenSSL

-   Do not use deprecated functions (e.g., avoid \`RSA<sub>new</sub>\`, use \`EVP<sub>PKEY</sub>\`).
-   Check return values of all OpenSSL functions.
-   Always clear the error queue or handle errors appropriately.


<a id="org9427aec"></a>

# Janet Code


<a id="org4a7878d"></a>

## Formatting

-   ****Indentation****: 2 spaces.
-   ****Braces/Parens****: Standard Lisp style (trailing parens on the same line).


<a id="orgce029d3"></a>

## Naming

-   ****Functions/Macros****: \`kebab-case\`.
-   ****Globals/Dynamics****: \`\*kebab-case\*\`.


<a id="org92f94cd"></a>

## Documentation

-   Public functions must have docstrings.


<a id="org8a5e47a"></a>

# Testing

-   Write tests for every new feature.
-   Use \`jsec/test/helper.janet\` for common utilities.
-   Ensure tests clean up resources (use \`defer\`).

