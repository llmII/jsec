
# Table of Contents

1.  [Overview](#org959b87b)
2.  [C Code](#orgc01740b)
    1.  [Formatting](#org99a1bf5)
    2.  [Naming](#org0bf9f42)
    3.  [comments](#org1556fc7)
    4.  [OpenSSL](#orgdc53991)
3.  [Janet Code](#orgfd49187)
    1.  [Formatting](#org97e2c5f)
    2.  [Naming](#org8d68921)
    3.  [Documentation](#org51f0b29)
4.  [Testing](#org255e299)



<a id="org959b87b"></a>

# Overview

This document defines the coding style for the jsec project.


<a id="orgc01740b"></a>

# C Code


<a id="org99a1bf5"></a>

## Formatting

-   ****Indentation****: 4 spaces. No tabs.
-   ****Braces****: K&R style (opening brace on the same line).
    
        if (condition) {
            statement;
        } else {
            statement;
        }
-   ****Line Length****: Try to keep under 80 characters, but clarity is priority.


<a id="org0bf9f42"></a>

## Naming

-   ****Variables/Functions****: \`snake<sub>case</sub>\`.
-   ****Types****: \`PascalCase\` (e.g., \`TLSStream\`).
-   ****Macros****: \`UPPER<sub>CASE</sub>\`.


<a id="org1556fc7"></a>

## comments

-   Use \`/\* \*/\` for multi-line comments.
-   Use \`//\` for single-line comments.
-   Comments should explain **why**, not **what**.


<a id="orgdc53991"></a>

## OpenSSL

-   Do not use deprecated functions (e.g., avoid \`RSA<sub>new</sub>\`, use \`EVP<sub>PKEY</sub>\`).
-   Check return values of all OpenSSL functions.
-   Always clear the error queue or handle errors appropriately.


<a id="orgfd49187"></a>

# Janet Code


<a id="org97e2c5f"></a>

## Formatting

-   ****Indentation****: 2 spaces.
-   ****Braces/Parens****: Standard Lisp style (trailing parens on the same line).


<a id="org8d68921"></a>

## Naming

-   ****Functions/Macros****: \`kebab-case\`.
-   ****Globals/Dynamics****: \`\*kebab-case\*\`.


<a id="org51f0b29"></a>

## Documentation

-   Public functions must have docstrings.


<a id="org255e299"></a>

# Testing

-   Write tests for every new feature.
-   Use \`jsec/test/helper.janet\` for common utilities.
-   Ensure tests clean up resources (use \`defer\`).

