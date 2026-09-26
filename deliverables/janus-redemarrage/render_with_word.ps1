param(
    [Parameter(Mandatory = $true)][string]$InputDocx,
    [Parameter(Mandatory = $true)][string]$OutputPdf
)

$inputPath = (Resolve-Path -LiteralPath $InputDocx).Path
$outputPath = [System.IO.Path]::GetFullPath($OutputPdf)
$word = $null
$document = $null

try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $document = $word.Documents.Open($inputPath, $false, $true)
    $document.Fields.Update() | Out-Null
    $document.ExportAsFixedFormat($outputPath, 17)
}
finally {
    if ($null -ne $document) {
        $document.Close(0)
    }
    if ($null -ne $word) {
        $word.Quit()
    }
}
