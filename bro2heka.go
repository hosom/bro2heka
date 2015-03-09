package main 

import (
	"fmt"
	"os"
	"bufio"
	"strings"
	"encoding/hex"
	"text/template"
	"flag"
)

const (
	VERSION = "0.2.1"
)

type BroField struct {
	Name string
	Index int
	FieldType string
}

type BroHeader struct {
	Separator string
	EscapedSeparator string
	EmptyField string
	UnsetField string
	Path string
	Fields []BroField
	LastField BroField
	Lines []string
}

func ReadBroHeader(filepath string) []string {
	file, err := os.Open(filepath)
	defer file.Close()
	if err != nil {
		fmt.Println("Error while opening Bro log file.")
		os.Exit(1)
	}
	scanner := bufio.NewScanner(file)

	var lines []string
	linecount := 1
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		linecount += 1
		if linecount > 8 {
			break
		}
	}
	return lines
}

func NewBroHeader(filepath string) BroHeader {
	header := BroHeader{}
	header.Lines = ReadBroHeader(filepath)
	header.Separator = strings.Split(header.Lines[0], " ")[1]
	separator_hex, _ := hex.DecodeString(header.Separator[2:])
	header.Separator = string(separator_hex)
	header.EscapedSeparator = fmt.Sprintf("%q", header.Separator)
	header.EmptyField = strings.Split(header.Lines[2], header.Separator)[1]
	header.UnsetField = strings.Split(header.Lines[3], header.Separator)[1]
	header.Path = strings.Split(header.Lines[4], header.Separator)[1]

	fields := strings.Split(header.Lines[6], header.Separator)[2:]
	types := strings.Split(header.Lines[7], header.Separator)[2:]

	header.LastField = BroField{Name: fields[len(fields)-1], Index: len(fields)+1, FieldType: GetType(types[len(fields)-1])}

	fields = fields[:len(fields)-1]
	types = types[:len(types)-1]
	for idx, field := range fields {
		header.Fields = append(header.Fields, BroField{Name: field, Index: idx+2, FieldType: GetType(types[idx])})
	}

	return header
}

func GetType(field_type string) string {
	FieldMap := make(map[string]string)
	FieldMap["void"] = "String"
	FieldMap["bool"] = "String"
	FieldMap["int"] = "Number"
	FieldMap["count"] = "Number"
	FieldMap["counter"] = "Number"
	FieldMap["double"] = "Number"
	FieldMap["time"] = "String"
	FieldMap["interval"] = "String"
	FieldMap["string"] = "String"
	FieldMap["pattern"] = "String"
	FieldMap["enum"] = "String"
	FieldMap["port"] = "Number"
	FieldMap["addr"] = "String"
	FieldMap["subnet"] = "String"
	FieldMap["any"] = "String"
	FieldMap["table"] = "String"
	FieldMap["set"] = "String"
	FieldMap["vector"] = "String"
	FieldMap["record"] = "String"
	FieldMap["opaque"] = "String"
	FieldMap["file"] = "String"
	if val, ok := FieldMap[field_type]; ok {
		return val
	}
	return "String"
}

func main() {

	FilePath := flag.String("file", "/opt/bro/log/current/conn.log", 
							"The logfile to use to generate the Lua script.")
	version := flag.Bool("version", false, "Output version and exit.")
	flag.Parse()

	if *version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	header := NewBroHeader(*FilePath)
	tmpl, _ := template.New("output").Parse(`
--[[
SOURCE HEADER USED TO GENERATE PARSING LOGIC:
{{ range $line := .Lines }}
{{ $line }}{{ end }}
]]

local l=require "lpeg"
local string=require "string"
l.locale(l)
local space = l.space^0
local sep = l.P{{.EscapedSeparator}}
local elem = l.C((1-sep)^0)
local grammar = l.Ct(elem * (sep * elem)^0)

local function toString(value)
	if ( value == "{{.UnsetField}}" or value == "{{.EmptyField}}" ) then
		return ""
	end
	return value
end

local function toNumber(value)
	if ( value == "{{.UnsetField}}" or value == "{{.EmptyField}}" ) then
		return 0
	end
	return tonumber(value)
end

local function lastField(value)
	-- Remove the last line return if one exists
	if value and string.len(value) > 1 and string.sub(value, -1) == "\n" then
		return string.sub(value, 1, -2) 
	end
	return value
end

function process_message()
	local log = read_message("Payload")
	local matches = grammar:match(log)

	if not matches then
		--Return 0 to avoid sending errors to heka's log.
		--Return a message with IGNORE type to not match heka's message watcher
		inject_message({Type = "IGNORE", Fields = {}})
		return 0
	end
	
	if string.sub(log,1,1)=="#" then
		--Ignore Bro's comment lines used to identify headers in log files.
		inject_message({Type = "IGNORE", Fields = {}})
		return 0
	end

	local msg = {
		Type = "{{.Path}}",
		Timestamp = toNumber(matches[1]),
		Fields = {}
	}

	{{ range $idx, $field := .Fields }}
	msg.Fields["{{ $field.Name }}"] = to{{ $field.FieldType }}(matches[{{$field.Index}}]){{ end }}
	msg.Fields["{{ .LastField.Name }}"] = to{{ .LastField.FieldType }}(lastField(matches[{{ .LastField.Index }}]))
	local ok, err = pcall(inject_message, msg)
	if not ok then return -1, err end
	return 0
end
	`)
	err := tmpl.Execute(os.Stdout, header)
	if err != nil { panic(err) }
}