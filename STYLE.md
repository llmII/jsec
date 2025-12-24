
# Table of Contents

1.  [Overview](#orga651421)
2.  [C Code](#org9ebb5f4)
    1.  [Formatting](#orgb08413c)
    2.  [Naming](#org3dd18dd)
    3.  [comments](#org8197b3f)
    4.  [OpenSSL](#org800c184)
3.  [Janet Code](#org4c18684)
    1.  [Formatting](#org4f509b5)
    2.  [Naming](#orgeb6d4bf)
    3.  [Documentation](#org0277d8b)
4.  [Testing](#org61f7788)



<a id="orga651421"></a>

# Overview

This document defines the coding style for the jsec project.


<a id="org9ebb5f4"></a>

# C Code


<a id="orgb08413c"></a>

## Formatting

-   ****Indentation****: 4 spaces. No tabs.
-   ****Braces****: K&R style (opening brace on the same line).
    
        if (condition) {
            statement;
        } else {
            statement;
        }
-   ****Line Length****: Try to keep under 80 characters, but clarity is priority.


<a id="org3dd18dd"></a>

## Naming

-   ****Variables/Functions****: \`snake<sub>case</sub>\`.
-   ****Types****: \`PascalCase\` (e.g., \`TLSStream\`).
-   ****Macros****: \`UPPER<sub>CASE</sub>\`.


<a id="org8197b3f"></a>

## comments

-   Use \`/\* \*/\` for multi-line comments.
-   Use \`//\` for single-line comments.
-   Comments should explain **why**, not **what**.


<a id="org800c184"></a>

## OpenSSL

-   Do not use deprecated functions (e.g., avoid \`RSA<sub>new</sub>\`, use \`EVP<sub>PKEY</sub>\`).
-   Check return values of all OpenSSL functions.
-   Always clear the error queue or handle errors appropriately.


<a id="org4c18684"></a>

# Janet Code


<a id="org4f509b5"></a>

## Formatting

-   ****Indentation****: 2 spaces.
-   ****Braces/Parens****: Standard Lisp style (trailing parens on the same line).


<a id="orgeb6d4bf"></a>

## Naming

-   ****Functions/Macros****: \`kebab-case\`.
-   ****Globals/Dynamics****: \`\*kebab-case\*\`.


<a id="org0277d8b"></a>

## Documentation

-   Public functions must have docstrings.


<a id="org61f7788"></a>

# Testing

-   Write tests for every new feature.
-   Use \`jsec/test/helper.janet\` for common utilities.
-   Ensure tests clean up resources (use \`defer\`).

