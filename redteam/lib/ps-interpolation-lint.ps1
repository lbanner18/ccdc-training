<#
    Find $_ inside a DOUBLE-quoted PowerShell string.

    "... $_.Resources ..." does not print $_. PowerShell interpolates it, $_ is
    empty outside a pipeline, and what reaches the operator is ".Resources" - a
    syntax error in the command they were told to paste. It is silent: the file
    parses, the script runs, the finding prints.

    Quote parity cannot be judged with a regex - a closing quote looks exactly
    like an opening one, so `"...text..." -f $_.Message` reads as a hit when the
    $_ is outside the string entirely. This asks the real parser instead, and
    looks only at strings that ARE expandable, which is the whole question.

    Prints one "file:line: text" per hit and exits 1 if there were any.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string[]]$Path)

$hits = 0
foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errors)
    if ($null -eq $ast) { continue }

    # ExpandableStringExpressionAst is precisely "a double-quoted string", which
    # is the only kind that interpolates. A single-quoted '$_' is already safe.
    $strings = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)
    foreach ($s in $strings) {
        # The distinction that matters is how the parser read it.
        #
        #   "$($_.Exception.Message)"  ->  a SubExpressionAst. Deliberate, and
        #                                  the normal way to report an error in
        #                                  a catch block. Fine.
        #   "$_.Resources"             ->  a bare VariableExpressionAst, with
        #                                  ".Resources" left as literal text.
        #                                  Almost always someone who meant the
        #                                  characters $_ to reach the screen.
        #
        # So look only at the nested expressions the string interpolates DIRECTLY,
        # not at anything wrapped in $( ).
        foreach ($nested in $s.NestedExpressions) {
            if ($nested -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
            if ($nested.VariablePath.UserPath -ne '_') { continue }
            $hits++
            $line = ($s.Extent.Text -split "`n")[0]
            if ($line.Length -gt 110) { $line = $line.Substring(0, 110) + ' ...' }
            Write-Output ('{0}:{1}: {2}' -f (Split-Path -Leaf $p), $s.Extent.StartLineNumber, $line)
            break
        }
    }
}
if ($hits -gt 0) { exit 1 }
exit 0
