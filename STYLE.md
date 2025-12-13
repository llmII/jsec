
# Table of Contents

1.  [Overview](#orgf57adcd)
2.  [C Code](#org092c1f1)
    1.  [Formatting](#org4858e4d)
    2.  [Naming](#org85c2b1d)
    3.  [comments](#org5302674)
    4.  [OpenSSL](#org5463218)
3.  [Janet Code](#org000b815)
    1.  [Formatting](#orgafe4274)
    2.  [Naming](#org17eb00b)
    3.  [Documentation](#org8de4fac)
4.  [Testing](#org7da9d8f)



<a id="orgf57adcd"></a>

# Overview

This document defines the coding style for the jsec project.


<a id="org092c1f1"></a>

# C Code


<a id="org4858e4d"></a>

## Formatting

-   ****Indentation****: 4 spaces. No tabs.
-   ****Braces****: K&R style (opening brace on the same line).
    
        if (condition) {
            statement;
        } else {
            statement;
        }
-   ****Line Length****: Try to keep under 80 characters, but clarity is priority.


<a id="org85c2b1d"></a>

## Naming

-   ****Variables/Functions****: \`snake<sub>case</sub>\`.
-   ****Types****: \`PascalCase\` (e.g., \`TLSStream\`).
-   ****Macros****: \`UPPER<sub>CASE</sub>\`.


<a id="org5302674"></a>

## comments

-   Use \`/\* \*/\` for multi-line comments.
-   Use \`//\` for single-line comments.
-   Comments should explain **why**, not **what**.


<a id="org5463218"></a>

## OpenSSL

-   Do not use deprecated functions (e.g., avoid \`RSA<sub>new</sub>\`, use \`EVP<sub>PKEY</sub>\`).
-   Check return values of all OpenSSL functions.
-   Always clear the error queue or handle errors appropriately.


<a id="org000b815"></a>

# Janet Code


<a id="orgafe4274"></a>

## Formatting

-   ****Indentation****: 2 spaces.
-   ****Braces/Parens****: Standard Lisp style (trailing parens on the same line).


<a id="org17eb00b"></a>

## Naming

-   ****Functions/Macros****: \`kebab-case\`.
-   ****Globals/Dynamics****: \`\*kebab-case\*\`.


<a id="org8de4fac"></a>

## Documentation

-   Public functions must have docstrings.


<a id="org7da9d8f"></a>

# Testing

-   Write tests for every new feature.
-   Use \`jsec/test/helper.janet\` for common utilities.
-   Ensure tests clean up resources (use \`defer\`).

