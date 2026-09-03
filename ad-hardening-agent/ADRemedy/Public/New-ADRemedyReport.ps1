function New-ADRemedyReport {
    <#
    .SYNOPSIS
        Renders findings as a single self-contained HTML file.

    .DESCRIPTION
        The report is built for reading and learning, not just listing: every finding
        carries the explanation of how it is abused, the remediation commands, a
        verification query, and what might break. No external assets, no network
        calls, so it opens on an isolated network and can be printed to PDF.

    .PARAMETER Finding
        Findings from Invoke-ADRemedyAudit or Import-ADRemedyFindings.

    .PARAMETER Path
        Output file path. Defaults to ADRemedy-Report-<timestamp>.html in the current directory.

    .PARAMETER Title
        Heading for the report.

    .PARAMETER MaxObjectRows
        Maximum affected objects rendered per finding. Default 100.

    .PARAMETER PassThru
        Return the FileInfo object for the report.

    .EXAMPLE
        Invoke-ADRemedyAudit | New-ADRemedyReport -Path .\corp-ad-review.html -PassThru

    .EXAMPLE
        Import-ADRemedyFindings .\Samples | New-ADRemedyReport -Title 'Lab domain review'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$Finding,

        [string]$Path,
        [string]$Title = 'Active Directory remediation report',
        [int]$MaxObjectRows = 100,
        [switch]$PassThru
    )

    begin {
        $all = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($f in $Finding) { if ($f) { $all.Add($f) } }
    }

    end {
        if (-not $all.Count) {
            Write-Warning 'No findings supplied, nothing to render.'
            return
        }

        if (-not $Path) {
            $Path = Join-Path (Get-Location) ("ADRemedy-Report-{0:yyyyMMdd-HHmmss}.html" -f (Get-Date))
        }

        $findings = $all | Sort-Object SeverityRank, Category, Title
        $domains = @($findings.Domain | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique | Sort-Object)
        $sources = @($findings.Source | Where-Object { $_ } | ForEach-Object { $_ -split '\s*\+\s*' } |
            ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique | Sort-Object)

        $counts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
        foreach ($f in $findings) {
            if ($counts.Contains($f.Severity)) { $counts[$f.Severity]++ } else { $counts['Low']++ }
        }
        $total = $findings.Count

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine((Get-ADRemedyReportHead -Title $Title))

        # ---- header -------------------------------------------------------
        $domainLabel = if ($domains) { $domains -join ', ' } else { 'Domain not recorded in source data' }
        [void]$sb.AppendLine('<header class="masthead">')
        [void]$sb.AppendLine('<div class="masthead-text">')
        [void]$sb.AppendLine("<h1>$(ConvertTo-ADRemedyHtmlText $Title)</h1>")
        [void]$sb.AppendLine("<p class=""subject"">$(ConvertTo-ADRemedyHtmlText $domainLabel)</p>")
        [void]$sb.AppendLine("<p class=""meta"">Generated $(Get-Date -Format 'dd MMM yyyy HH:mm') &middot; $total finding$(if($total -ne 1){'s'}) &middot; from $(ConvertTo-ADRemedyHtmlText ($sources -join ', '))</p>")
        [void]$sb.AppendLine('</div>')
        [void]$sb.AppendLine((Get-ADRemedyTallyHtml -Counts $counts -Total $total))
        [void]$sb.AppendLine('</header>')

        # ---- controls -----------------------------------------------------
        $categories = @($findings.Category | Select-Object -Unique | Sort-Object)
        [void]$sb.AppendLine('<div class="controls">')
        [void]$sb.AppendLine('<input type="search" id="filter-text" placeholder="Filter by name, ID, or affected object" aria-label="Filter findings">')
        [void]$sb.AppendLine('<select id="filter-category" aria-label="Filter by category"><option value="">All categories</option>')
        foreach ($cat in $categories) {
            $enc = ConvertTo-ADRemedyHtmlText $cat
            [void]$sb.AppendLine("<option value=""$enc"">$enc</option>")
        }
        [void]$sb.AppendLine('</select>')
        [void]$sb.AppendLine('<select id="filter-severity" aria-label="Filter by severity"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select>')
        [void]$sb.AppendLine('<button type="button" id="expand-all">Open all</button>')
        [void]$sb.AppendLine('<span id="result-count" class="result-count"></span>')
        [void]$sb.AppendLine('</div>')

        # ---- findings -----------------------------------------------------
        [void]$sb.AppendLine('<main id="findings">')
        $index = 0
        foreach ($f in $findings) {
            $index++
            [void]$sb.AppendLine((Get-ADRemedyFindingHtml -Finding $f -Index $index -MaxObjectRows $MaxObjectRows))
        }
        [void]$sb.AppendLine('</main>')

        [void]$sb.AppendLine('<p class="empty" id="empty-state" hidden>No findings match the current filter.</p>')
        [void]$sb.AppendLine('<footer class="colophon">Generated by ADRemedy. Every command in this report changes production behaviour, so read the "What could break" note before running it.</footer>')
        [void]$sb.AppendLine((Get-ADRemedyReportScript))
        [void]$sb.AppendLine('</body></html>')

        $dir = Split-Path -Path $Path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
        Write-Host "Report written to $Path" -ForegroundColor Green

        if ($PassThru) { Get-Item -LiteralPath $Path }
    }
}

function ConvertTo-ADRemedyHtmlText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return '' }
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-ADRemedyTallyHtml {
    param([System.Collections.Specialized.OrderedDictionary]$Counts, [int]$Total)

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<div class="tally" role="img" aria-label="Findings by severity">')
    [void]$sb.AppendLine('<div class="tally-bar">')
    foreach ($key in $Counts.Keys) {
        if ($Counts[$key] -le 0) { continue }
        $pct = [math]::Round(($Counts[$key] / [math]::Max($Total, 1)) * 100, 2)
        $cls = $key.ToLowerInvariant()
        [void]$sb.AppendLine("<span class=""seg seg-$cls"" style=""width:$pct%"" title=""$key : $($Counts[$key])""></span>")
    }
    [void]$sb.AppendLine('</div><dl class="tally-list">')
    foreach ($key in $Counts.Keys) {
        $cls = $key.ToLowerInvariant()
        [void]$sb.AppendLine("<div class=""tally-item""><dt class=""dot-$cls"">$key</dt><dd>$($Counts[$key])</dd></div>")
    }
    [void]$sb.AppendLine('</dl></div>')
    $sb.ToString()
}

function Get-ADRemedyObjectTableHtml {
    param([object[]]$Objects, [int]$MaxRows = 100)

    $objects = @($Objects | Where-Object { $_ })
    if (-not $objects) { return '' }

    $columns = [System.Collections.Generic.List[string]]::new()
    foreach ($o in ($objects | Select-Object -First 25)) {
        if ($o -isnot [psobject]) { continue }
        foreach ($p in $o.PSObject.Properties) {
            if ($columns -notcontains $p.Name -and $columns.Count -lt 8) { $columns.Add($p.Name) }
        }
    }
    if (-not $columns.Count) { $columns.Add('Name') }

    $shown = @($objects | Select-Object -First $MaxRows)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<div class="table-wrap"><table class="objects"><thead><tr>')
    foreach ($c in $columns) { [void]$sb.Append("<th>$(ConvertTo-ADRemedyHtmlText $c)</th>") }
    [void]$sb.AppendLine('</tr></thead><tbody>')

    foreach ($o in $shown) {
        [void]$sb.Append('<tr>')
        foreach ($c in $columns) {
            $value = if ($o -is [psobject] -and $o.PSObject.Properties[$c]) { $o.PSObject.Properties[$c].Value } else { $null }
            $text = if ($value -is [datetime]) { $value.ToString('yyyy-MM-dd') }
                    elseif ($value -is [System.Array]) { ($value -join '; ') }
                    else { [string]$value }
            if ($text.Length -gt 160) { $text = $text.Substring(0, 157) + '...' }
            [void]$sb.Append("<td>$(ConvertTo-ADRemedyHtmlText $text)</td>")
        }
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table></div>')

    if ($objects.Count -gt $shown.Count) {
        [void]$sb.AppendLine("<p class=""truncated"">Showing $($shown.Count) of $($objects.Count). Export the finding objects to CSV for the full list.</p>")
    }
    $sb.ToString()
}

function Get-ADRemedyFindingHtml {
    param([Parameter(Mandatory)]$Finding, [int]$Index, [int]$MaxObjectRows = 100)

    $g = $Finding.Guidance
    $sev = [string]$Finding.Severity
    $sevClass = $sev.ToLowerInvariant()
    $searchBlob = @(
        $Finding.FindingId, $Finding.Title, $Finding.Category, $Finding.Evidence,
        $(if ($g) { @($g.edges) -join ' ' }),
        ($Finding.AffectedObjects | ForEach-Object { if ($_ -is [psobject] -and $_.PSObject.Properties['Edge']) { $_.Edge } }),
        ($Finding.AffectedObjects | ForEach-Object { if ($_ -is [psobject] -and $_.PSObject.Properties['Name']) { $_.Name } })
    ) -join ' '

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("<details class=""finding sev-$sevClass"" data-severity=""$sev"" data-category=""$(ConvertTo-ADRemedyHtmlText $Finding.Category)"" data-search=""$(ConvertTo-ADRemedyHtmlText $searchBlob.ToLowerInvariant())"">")

    # summary row
    [void]$sb.AppendLine('<summary>')
    [void]$sb.AppendLine("<span class=""sev-chip"">$sev</span>")
    [void]$sb.AppendLine('<span class="headline">')
    [void]$sb.AppendLine("<span class=""finding-title"">$(ConvertTo-ADRemedyHtmlText $Finding.Title)</span>")
    [void]$sb.AppendLine("<span class=""finding-id"">$(ConvertTo-ADRemedyHtmlText $Finding.FindingId) &middot; $(ConvertTo-ADRemedyHtmlText $Finding.Category) &middot; $(ConvertTo-ADRemedyHtmlText $Finding.Source)</span>")
    [void]$sb.AppendLine('</span>')
    if ($Finding.AffectedCount -gt 0) {
        [void]$sb.AppendLine("<span class=""count"">$($Finding.AffectedCount)<small>object$(if($Finding.AffectedCount -ne 1){'s'})</small></span>")
    }
    [void]$sb.AppendLine('</summary>')

    [void]$sb.AppendLine('<div class="body">')
    [void]$sb.AppendLine('<div class="main-col">')

    if ($Finding.Evidence) {
        [void]$sb.AppendLine("<p class=""evidence"">$(ConvertTo-ADRemedyHtmlText $Finding.Evidence)</p>")
    }

    if (-not $g) {
        [void]$sb.AppendLine('<p class="no-guidance">This finding came from an external tool and has no catalog entry yet. The source description is above. Add an entry to Data/RemediationCatalog.json to give it a full writeup.</p>')
        [void]$sb.AppendLine((Get-ADRemedyObjectTableHtml -Objects $Finding.AffectedObjects -MaxRows $MaxObjectRows))
        [void]$sb.AppendLine('</div></div></details>')
        return $sb.ToString()
    }

    [void]$sb.AppendLine('<section class="block"><h3>What it is</h3>')
    [void]$sb.AppendLine("<p>$(ConvertTo-ADRemedyHtmlText $g.summary)</p></section>")

    [void]$sb.AppendLine('<section class="block"><h3>How it is abused</h3>')
    [void]$sb.AppendLine("<p>$(ConvertTo-ADRemedyHtmlText $g.howItWorks)</p>")
    if ($g.attackChain) {
        [void]$sb.AppendLine('<ol class="chain">')
        foreach ($step in $g.attackChain) { [void]$sb.AppendLine("<li>$(ConvertTo-ADRemedyHtmlText $step)</li>") }
        [void]$sb.AppendLine('</ol>')
    }
    [void]$sb.AppendLine('</section>')

    [void]$sb.AppendLine('<section class="block fix"><h3>Remediation</h3><ol class="steps">')
    foreach ($step in $g.remediation) {
        [void]$sb.AppendLine('<li>')
        [void]$sb.AppendLine("<p>$(ConvertTo-ADRemedyHtmlText $step.step)</p>")
        if ($step.command) {
            [void]$sb.AppendLine('<div class="cmd"><pre><code>' + (ConvertTo-ADRemedyHtmlText $step.command) + '</code></pre><button type="button" class="copy" aria-label="Copy command">Copy</button></div>')
        }
        [void]$sb.AppendLine('</li>')
    }
    [void]$sb.AppendLine('</ol>')

    if ($g.validation) {
        [void]$sb.AppendLine('<h4>Verify the fix</h4>')
        [void]$sb.AppendLine('<div class="cmd"><pre><code>' + (ConvertTo-ADRemedyHtmlText $g.validation) + '</code></pre><button type="button" class="copy" aria-label="Copy command">Copy</button></div>')
    }
    [void]$sb.AppendLine('</section>')

    if ($Finding.AffectedObjects.Count) {
        [void]$sb.AppendLine("<section class=""block""><h3>Affected objects</h3>")
        [void]$sb.AppendLine((Get-ADRemedyObjectTableHtml -Objects $Finding.AffectedObjects -MaxRows $MaxObjectRows))
        [void]$sb.AppendLine('</section>')
    }

    [void]$sb.AppendLine('</div>')   # end main-col
    [void]$sb.AppendLine('<aside class="side-col">')

    if ($g.breakRisk) {
        [void]$sb.AppendLine('<section class="block caution"><h3>What could break</h3>')
        [void]$sb.AppendLine("<p>$(ConvertTo-ADRemedyHtmlText $g.breakRisk)</p></section>")
    }

    if ($g.lab) {
        [void]$sb.AppendLine('<section class="block lab"><h3>See it yourself</h3>')
        [void]$sb.AppendLine("<p>$(ConvertTo-ADRemedyHtmlText $g.lab)</p></section>")
    }

    if ($g.edges) {
        [void]$sb.AppendLine('<section class="block edges"><h3>BloodHound edges</h3><ul class="edge-list">')
        foreach ($edge in $g.edges) {
            [void]$sb.AppendLine("<li>$(ConvertTo-ADRemedyHtmlText $edge)</li>")
        }
        [void]$sb.AppendLine('</ul></section>')
    }

    $refBits = @()
    if ($g.mitre) { $refBits += "MITRE ATT&amp;CK $(ConvertTo-ADRemedyHtmlText ($g.mitre -join ', '))" }
    if ($g.effort) { $refBits += "Effort to fix: $(ConvertTo-ADRemedyHtmlText $g.effort)" }
    if ($refBits -or $g.references) {
        [void]$sb.AppendLine('<section class="block refs">')
        if ($refBits) { [void]$sb.AppendLine("<p class=""tags"">$($refBits -join ' &middot; ')</p>") }
        if ($g.references) {
            [void]$sb.AppendLine('<ul>')
            foreach ($ref in $g.references) {
                $t = ConvertTo-ADRemedyHtmlText $ref.title
                if ($ref.url) {
                    $u = ConvertTo-ADRemedyHtmlText $ref.url
                    [void]$sb.AppendLine("<li><a href=""$u"" rel=""noreferrer noopener"" target=""_blank"">$t</a></li>")
                } else {
                    [void]$sb.AppendLine("<li>$t</li>")
                }
            }
            [void]$sb.AppendLine('</ul>')
        }
        [void]$sb.AppendLine('</section>')
    }

    [void]$sb.AppendLine('</aside>')
    [void]$sb.AppendLine('</div></details>')
    $sb.ToString()
}

function Get-ADRemedyReportHead {
    param([string]$Title)

    $encoded = ConvertTo-ADRemedyHtmlText $Title
    $css = @'
:root{
  --paper:#e9edf1; --panel:#ffffff; --ink:#16232e; --ink-soft:#4a5c6b; --rule:#c9d3db;
  --steel:#2c4c6b; --critical:#8b1e2d; --high:#b4531b; --medium:#8a6d1f; --low:#40606b;
  --code-bg:#f2f5f7;
}
*{box-sizing:border-box}
body{
  margin:0; padding:2.5rem 1.5rem 4rem; background:var(--paper); color:var(--ink);
  font-family:"Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
  font-size:15px; line-height:1.55;
}
.masthead,.controls,#findings,.colophon,.empty{max-width:64rem;margin-left:auto;margin-right:auto}
.masthead{display:flex;flex-wrap:wrap;gap:2rem;justify-content:space-between;align-items:flex-end;
  border-bottom:2px solid var(--ink);padding-bottom:1.25rem;margin-bottom:1.5rem}
h1{font-size:1.75rem;font-weight:650;letter-spacing:-.015em;margin:0 0 .25rem}
.subject{margin:0;font-size:1.05rem;color:var(--steel);font-weight:600}
.meta{margin:.35rem 0 0;color:var(--ink-soft);font-size:.85rem}
.tally{min-width:16rem}
.tally-bar{display:flex;height:.55rem;border-radius:2px;overflow:hidden;background:var(--rule);margin-bottom:.6rem}
.seg-critical{background:var(--critical)} .seg-high{background:var(--high)}
.seg-medium{background:var(--medium)} .seg-low{background:var(--low)}
.tally-list{display:flex;gap:1.1rem;margin:0;flex-wrap:wrap}
.tally-item{display:flex;align-items:baseline;gap:.4rem}
.tally-list dt{font-size:.8rem;color:var(--ink-soft);position:relative;padding-left:.75rem}
.tally-list dt::before{content:"";position:absolute;left:0;top:.35em;width:.5rem;height:.5rem;border-radius:50%}
.dot-critical::before{background:var(--critical)} .dot-high::before{background:var(--high)}
.dot-medium::before{background:var(--medium)} .dot-low::before{background:var(--low)}
.tally-list dd{margin:0;font-weight:650;font-variant-numeric:tabular-nums}
.controls{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center;margin-bottom:1.25rem}
.controls input,.controls select,.controls button{
  font:inherit;font-size:.9rem;padding:.45rem .7rem;border:1px solid var(--rule);
  border-radius:3px;background:var(--panel);color:var(--ink)}
.controls input{flex:1 1 14rem;min-width:10rem}
.result-count{margin-left:auto}
.controls button{cursor:pointer}
.controls button:hover{border-color:var(--steel);color:var(--steel)}
.controls :focus-visible{outline:2px solid var(--steel);outline-offset:1px}
.result-count{font-size:.8rem;color:var(--ink-soft)}
.finding{background:var(--panel);border:1px solid var(--rule);border-left:5px solid var(--low);
  margin-bottom:.6rem;border-radius:2px}
.finding.sev-critical{border-left-color:var(--critical)}
.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--medium)}
summary{display:flex;align-items:center;gap:1rem;padding:.85rem 1.1rem;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}
summary:hover .finding-title{color:var(--steel)}
summary:focus-visible{outline:2px solid var(--steel);outline-offset:-2px}
.sev-chip{font-size:.7rem;font-weight:650;letter-spacing:.02em;padding:.2rem .5rem;border-radius:2px;
  color:#fff;white-space:nowrap;min-width:5rem;text-align:center}
.sev-critical .sev-chip{background:var(--critical)} .sev-high .sev-chip{background:var(--high)}
.sev-medium .sev-chip{background:var(--medium)} .sev-low .sev-chip{background:var(--low)}
.headline{flex:1;display:flex;flex-direction:column;gap:.15rem}
.finding-title{font-weight:600}
.finding-id{font-family:"Cascadia Mono",Consolas,"Courier New",monospace;font-size:.75rem;color:var(--ink-soft)}
.count{text-align:right;font-weight:650;font-variant-numeric:tabular-nums;line-height:1.1}
.count small{display:block;font-weight:400;font-size:.7rem;color:var(--ink-soft)}
.body{padding:.25rem 1.1rem 1.4rem 1.1rem;border-top:1px solid var(--rule);
  display:grid;grid-template-columns:minmax(0,1fr) 17rem;gap:0 2rem;align-items:start}
.main-col{min-width:0}
.side-col{position:sticky;top:1rem;padding-top:1.4rem;font-size:.88rem}
.side-col .block{margin:0 0 1.2rem}
.side-col p{max-width:none}
@media (max-width:60rem){
  .body{display:block}
  .side-col{position:static;padding-top:0;border-top:1px solid var(--rule);margin-top:1rem}
}
@media (max-width:34rem){
  body{padding:1.5rem .9rem 3rem}
  summary{flex-wrap:wrap;gap:.5rem}
  .sev-chip{order:1} .count{order:2;margin-left:auto} .headline{order:3;flex-basis:100%}
}
.evidence{background:var(--code-bg);border-left:3px solid var(--steel);padding:.6rem .8rem;margin:1rem 0;font-size:.92rem}
.block{margin:1.4rem 0}
.block h3{font-size:.95rem;font-weight:650;margin:0 0 .5rem;color:var(--steel)}
.block h4{font-size:.85rem;font-weight:650;margin:1.2rem 0 .4rem;color:var(--steel)}
.block p{margin:0 0 .6rem;max-width:68ch}
.chain{margin:.8rem 0 0;padding-left:1.2rem;color:var(--ink-soft);font-size:.92rem;max-width:70ch}
.chain li{margin-bottom:.25rem}
.steps{margin:0;padding-left:1.2rem;max-width:74ch}
.steps>li{margin-bottom:1rem}
.steps p{margin:0 0 .4rem}
.cmd{position:relative;margin:.4rem 0 0}
.cmd pre{margin:0;background:var(--code-bg);border:1px solid var(--rule);border-radius:2px;
  padding:1.7rem .7rem .6rem .7rem;white-space:pre-wrap;overflow-wrap:anywhere}
.cmd code{font-family:"Cascadia Mono",Consolas,"Courier New",monospace;font-size:.8rem;color:#123}
.copy{position:absolute;top:.3rem;right:.3rem;font:inherit;font-size:.68rem;padding:.15rem .45rem;
  border:1px solid var(--rule);background:var(--panel);border-radius:2px;cursor:pointer;color:var(--ink-soft)}
.copy:hover{border-color:var(--steel);color:var(--steel)}
.caution p{border-left:3px solid var(--high);padding-left:.8rem}
.lab p{border-left:3px solid var(--low);padding-left:.8rem}
.edge-list{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:.3rem}
.edge-list li{font-family:"Cascadia Mono",Consolas,monospace;font-size:.72rem;
  padding:.15rem .45rem;border:1px solid var(--rule);border-radius:2px;
  background:var(--code-bg);color:var(--steel)}
.no-guidance{color:var(--ink-soft);font-size:.9rem}
.table-wrap{overflow-x:auto;border:1px solid var(--rule);border-radius:2px}
table.objects{border-collapse:collapse;width:100%;font-size:.82rem}
table.objects th{text-align:left;background:var(--code-bg);padding:.45rem .6rem;
  border-bottom:1px solid var(--rule);font-weight:650;white-space:nowrap}
table.objects td{padding:.4rem .6rem;border-bottom:1px solid #eef2f5;
  font-family:"Cascadia Mono",Consolas,monospace;font-size:.78rem;vertical-align:top}
table.objects tr:last-child td{border-bottom:none}
.truncated{font-size:.78rem;color:var(--ink-soft);margin:.5rem 0 0}
.refs{border-top:1px solid var(--rule);padding-top:.8rem}
.tags{font-size:.78rem;color:var(--ink-soft);margin-bottom:.4rem}
.refs ul{margin:0;padding-left:1.1rem;font-size:.82rem}
.refs a{color:var(--steel)}
.empty{color:var(--ink-soft);text-align:center;padding:2rem 0}
.colophon{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--rule);
  font-size:.78rem;color:var(--ink-soft)}
@media print{
  body{background:#fff;padding:0;font-size:11px}
  .controls,.copy{display:none}
  .finding{break-inside:avoid;border:1px solid #999;margin-bottom:.4rem}
  .body{display:block !important}
  details{page-break-inside:avoid}
}
@media (prefers-reduced-motion:no-preference){
  .finding[open] .body{animation:reveal .18s ease-out}
  @keyframes reveal{from{opacity:0}to{opacity:1}}
}
'@

    @"
<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="ADRemedy">
<title>$encoded</title>
<style>
$css
</style>
</head><body>
"@
}

function Get-ADRemedyReportScript {
    @'
<script>
(function () {
  var text = document.getElementById('filter-text');
  var cat = document.getElementById('filter-category');
  var sev = document.getElementById('filter-severity');
  var expand = document.getElementById('expand-all');
  var counter = document.getElementById('result-count');
  var empty = document.getElementById('empty-state');
  var findings = Array.prototype.slice.call(document.querySelectorAll('.finding'));

  function apply() {
    var q = (text.value || '').toLowerCase().trim();
    var c = cat.value;
    var s = sev.value;
    var shown = 0;
    findings.forEach(function (el) {
      var ok = (!q || el.dataset.search.indexOf(q) !== -1) &&
               (!c || el.dataset.category === c) &&
               (!s || el.dataset.severity === s);
      el.hidden = !ok;
      if (ok) { shown++; }
    });
    counter.textContent = shown + ' of ' + findings.length + ' shown';
    empty.hidden = shown !== 0;
  }

  [text, cat, sev].forEach(function (el) {
    el.addEventListener('input', apply);
    el.addEventListener('change', apply);
  });

  expand.addEventListener('click', function () {
    var open = findings.some(function (el) { return !el.open && !el.hidden; });
    findings.forEach(function (el) { if (!el.hidden) { el.open = open; } });
    expand.textContent = open ? 'Close all' : 'Open all';
  });

  document.addEventListener('click', function (e) {
    if (!e.target.classList.contains('copy')) { return; }
    var code = e.target.previousElementSibling.textContent;
    var done = function () {
      var original = e.target.textContent;
      e.target.textContent = 'Copied';
      setTimeout(function () { e.target.textContent = original; }, 1200);
    };
    if (navigator.clipboard) {
      navigator.clipboard.writeText(code).then(done, function () {});
    } else {
      var ta = document.createElement('textarea');
      ta.value = code;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); done(); } catch (err) {}
      document.body.removeChild(ta);
    }
  });

  apply();
})();
</script>
'@
}
