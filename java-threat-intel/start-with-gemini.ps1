# start-with-gemini.ps1
# Starts the Java backend with the GEMINI_API_KEY environment variable set.
# Usage: .\start-with-gemini.ps1 -ApiKey "your_key_here"
# Or:    Set $env:GEMINI_API_KEY = "your_key" in the terminal, then run: mvn exec:java

param (
    [string]$ApiKey = $env:GEMINI_API_KEY,
    [string]$Model  = ($env:GEMINI_MODEL ?? "gemini-2.0-flash")
)

if (-not $ApiKey -or $ApiKey -eq "") {
    Write-Error "ERROR: GEMINI_API_KEY is not set."
    Write-Host "Usage: .\start-with-gemini.ps1 -ApiKey 'your_gemini_api_key'"
    Write-Host "Or: Set the GEMINI_API_KEY environment variable and run: mvn exec:java"
    Write-Host "Get a free API key at: https://aistudio.google.com/apikey"
    exit 1
}

$env:GEMINI_API_KEY = $ApiKey
$env:GEMINI_MODEL   = $Model

Write-Host "✅ GEMINI_API_KEY is set (${$ApiKey.Length} chars)"
Write-Host "✅ GEMINI_MODEL = $Model"
Write-Host "🚀 Starting Java backend on port 8081..."
Write-Host ""

Set-Location -Path $PSScriptRoot
mvn exec:java
