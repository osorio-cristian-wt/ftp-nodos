# Autocompletado (Tab) de ztftp para PowerShell.
# Completa subcomandos, alias de nodos y rutas remotas (nodo:ruta) consultando al nodo.
# Cargalo desde tu $PROFILE:  . "C:\ruta\a\ztftp-completion.ps1"

Register-ArgumentCompleter -Native -CommandName ztftp -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $elements = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })
    # Elementos ya escritos antes de la palabra que se completa (el primero es "ztftp").
    $prior = if ($wordToComplete -ne '') { @($elements | Select-Object -SkipLast 1) } else { $elements }

    function New-Result($text, $tip) {
        if ($text -match "[\s'`"]") { $text = "'" + $text.Replace("'", "''") + "'" }
        [System.Management.Automation.CompletionResult]::new($text, $text, 'ParameterValue', $tip)
    }

    if ($prior.Count -le 1) {
        'init', 'serve', 'cp', 'ls' | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { New-Result $_ $_ }
        return
    }
    if ($prior[1] -notin 'cp', 'ls') { return }   # serve/init: completado de archivos por defecto

    $word = $wordToComplete.Trim("'", '"')
    $remote = & ztftp _complete $word 2>$null
    $remote | Where-Object { $_ } | ForEach-Object { New-Result $_ $_ }

    # Sin "nodo:" (o con unidad C:\...) tambien se completan rutas locales.
    if ($word -notmatch ':' -or $word -match '^[A-Za-z]:[\\/]') {
        [System.Management.Automation.CompletionCompleters]::CompleteFilename($word)
    }
}
