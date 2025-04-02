---
title: Phishing in Microsoft Office
tags:
  - breach
  - operations
  - phishing
  - microsoft
  - office
  - powershell
  - win32api
  - windows
  - api
  - vba
  - visual
  - basic
---

## Gaining VBA script execution

Visual Basic for Applications (VBA) is a scripting language available for use
in Microsoft Office applications like Microsoft Word and Microsoft Excel. Over
the years, plenty of mitigations have been implemented to prevent client-side
code execution attacks using VBA in these products. Before we talk about that,
let's talk about how scripts can be executed when Office documents are opened.

### Document_Open

The `Document_Open` subroutine is a subroutine that is executed for eligible
VBA scripts stored within an Office document when the `Document.Open` event
occurs. Some examples and detail on this subroutine are provided
[here](https://learn.microsoft.com/en-us/office/vba/api/word.document.open).

### Auto macros

There are various
[auto macros](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
that can be used to gain code execution of eligible VBA scripts during
different events like starting Microsoft Word, opening a document, etc. In
these docs, you'll primarily see the use of `AutoOpen` - an auto macro and
subroutine that is executed for eligible VBA scripts stored within an Office
document.

## Mitigations

### File formats

Presently, only some file formats support the execution of macros defined by
VBA scripts - `.doc` and `.docm`. The latest `.docx` does not support macro
execution - stricter security features. You can find more info on Microsoft
Word supported file formats
[here](https://learn.microsoft.com/en-us/office/compatibility/office-file-format-reference).

### Mark of the Web

Mark of the Web (MoTW) is a metadata, boolean identifier used by Windows to
mark files downloaded from the internet. This mark is used by products like
Microsoft Office and Excel to warn users that a file was downloaded from the
internet, and that caution should be exercised when enabling certain features.

To gain macro code execution on an Office document payload, an attacker would
have to hope that a victim would go out of their way to disable these
mitigations and security features to enable the execution of their macro
payload.

> NOTE: Interestingly enough, I've used `Invoke-WebRequest` to download
> payloads from an attacker host - MoTW was not set on the resulting downloaded
> file.

## Useful functions

### Shell

The `Shell` function does what you probably think it does, executes a shell
command. Provide a `pathname` and a `windowstyle` (usually `0` for hidden) to
execute the program located at `pathname`. More details
[here](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/shell-function).
Here's an example of executing `cmd.exe` in a hidden window:

```vba
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    Shell str, vbHide
End Sub
```

### Windows Scripting Host

A more powerful primitive for code execution is to use the Windows Scripting
Host (WSH). This enables us to define an entire script for execution - rather
than just executing a single program. Details and examples on how to create and
run a WSH object can be found [here](https://ss64.com/vb/createobject.html).
Here's an example of executing `cmd.exe` in a hidden window:

```vba
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    CreateObject("Wscript.Shell").Run str, 0
End Sub
```
