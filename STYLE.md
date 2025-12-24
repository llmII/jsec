
# Table of Contents

1.  [Overview](#orga7a6054)
2.  [C Code](#org6282143)
    1.  [Formatting](#org30ee86e)
    2.  [Naming](#org83d4be7)
    3.  [comments](#org73904f8)
    4.  [OpenSSL](#orge6d7693)
3.  [Janet Code](#orga9fee96)
    1.  [Formatting](#org48af9e2)
    2.  [Naming](#org346f503)
    3.  [Documentation](#orgc3935f9)
4.  [Testing](#org82049b0)



<a id="orga7a6054"></a>

# Overview

This document defines the coding style for the jsec project.


<a id="org6282143"></a>

# C Code


<a id="org30ee86e"></a>

## Formatting

-   ****Indentation****: 4 spaces. No tabs.
-   ****Braces****: K&R style (opening brace on the same line).
    
        if (condition) {
            statement;
        } else {
            statement;
        }
-   ****Line Length****: Try to keep under 80 characters, but clarity is priority.


<a id="org83d4be7"></a>

## Naming

-   ****Variables/Functions****: \`snake<sub>case</sub>\`.
-   ****Types****: \`PascalCase\` (e.g., \`TLSStream\`).
-   ****Macros****: \`UPPER<sub>CASE</sub>\`.


<a id="org73904f8"></a>

## comments

-   Use \`/\* \*/\` for multi-line comments.
-   Use \`//\` for single-line comments.
-   Comments should explain **why**, not **what**.


<a id="orge6d7693"></a>

## OpenSSL

-   Do not use deprecated functions (e.g., avoid \`RSA<sub>new</sub>\`, use \`EVP<sub>PKEY</sub>\`).
-   Check return values of all OpenSSL functions.
-   Always clear the error queue or handle errors appropriately.


<a id="orga9fee96"></a>

# Janet Code


<a id="org48af9e2"></a>

## Formatting

-   ****Indentation****: 2 spaces.
-   ****Braces/Parens****: Standard Lisp style (trailing parens on the same line).


<a id="org346f503"></a>

## Naming

-   ****Functions/Macros****: \`kebab-case\`.
-   ****Globals/Dynamics****: \`\*kebab-case\*\`.


<a id="orgc3935f9"></a>

## Documentation

-   Public functions must have docstrings.


<a id="org82049b0"></a>

# Testing

-   Write tests for every new feature.
-   Use \`jsec/test/helper.janet\` for common utilities.
-   Ensure tests clean up resources (use \`defer\`).

