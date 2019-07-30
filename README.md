# x509-parser project

## Copyright and license
Copyright (C) 2019

This software is licensed under a dual BSD and GPL v2 license.
See [LICENSE](LICENSE) file at the root folder of the project.

## Authors

  * Arnaud EBALARD (<mailto:arnaud.ebalard@ssi.gouv.fr>)

## Contributors

  * Ryad BENADJILA (<mailto:ryad.benadjila@ssi.gouv.fr>)
  * Patricia MOUY (<mailto:patricia.mouy@ssi.gouv.fr>)

## Description

This software implements a X.509 certificate parser, annotated using
ACSL annotations for verification with Frama-C (version 18/Argon).

## Building

The main [Makefile](Makefile) is in the root directory, and compiling is
as simple as executing:

<pre>
	$ make
</pre>

This will compile different elements in the [build](build/) directory:

  * the x509-parser.o object file
  * the x509-parser binary, which can be used on a DER certificate (or
    a concatenation of such elements)

## Validating

The main [Makefile](Makefile) has a Frama-C target which can be used to
start Frama-C to verify the project.

<pre>
	$ make frama-c
</pre>

Frama-C must have been installed prior to calling that target. Installing
Frama-C can be done using OPAM. More details can be found on
[Frama-C](https://frama-c.com/) project website. Frama-C may also be
available as a common package on your distribution.

