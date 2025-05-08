# sonar-summary.ps1
$projectKey = "mcarthey_MemoryScanner"
$org = "mcarthey"
$token = $env:SONAR_TOKEN

$headers = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${token}:")) }

$url = "https://sonarcloud.io/api/issues/search?componentKeys=$projectKey&resolved=false"

$response = Invoke-RestMethod -Uri $url -Headers $headers

$topIssues = $response.issues | Select-Object -First 5

Write-Host "::notice::Top SonarCloud Issues:"
foreach ($issue in $topIssues) {
    $msg = "$($issue.severity): $($issue.message) (Line $($issue.line) in $($issue.component.Split(':')[-1]))"
    Write-Host "::notice::$msg"
}
