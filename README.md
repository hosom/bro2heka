# bro2heka
Small utility for automatically generating Lua sandbox scripts to parse Bro logs.

This go program will parse a bro log header and generate a Lua script that can be used with Heka to parse your logs. 

Binaries for Windows and Linux are available in the releases.

===============================================
Building from source.
===============================================

Requirements: golang

Once go is installed, simply run the following:

<pre>
go build bro2heka.go
</pre>

Afterwards, it should be ready to go.
