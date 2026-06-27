$jars = @(
    "https://repo1.maven.org/maven2/com/mysql/mysql-connector-j/8.0.33/mysql-connector-j-8.0.33.jar",
    "https://repo1.maven.org/maven2/com/zaxxer/HikariCP/5.1.0/HikariCP-5.1.0.jar",
    "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar",
    "https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/2.0.9/slf4j-simple-2.0.9.jar",
    "https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/gson-2.10.1.jar"
)

mkdir lib -ErrorAction SilentlyContinue | Out-Null
mkdir bin -ErrorAction SilentlyContinue | Out-Null

Write-Host "Downloading dependencies..."
foreach ($url in $jars) {
    $filename = Split-Path $url -Leaf
    if (-not (Test-Path "lib\$filename")) {
        Write-Host "Downloading $filename..."
        Invoke-WebRequest -Uri $url -OutFile "lib\$filename"
    } else {
        Write-Host "$filename already present, skipping."
    }
}

Write-Host "Collecting Java sources..."
# Collect all .java files recursively from all sub-packages
$sources = Get-ChildItem -Path "src\main\java" -Filter "*.java" -Recurse | ForEach-Object { $_.FullName }
$sourceList = $sources -join " "

Write-Host "Compiling $($sources.Count) Java source files..."
$compileCmd = "javac -cp `"lib\*`" -d bin $sourceList"
Invoke-Expression $compileCmd

if ($LASTEXITCODE -eq 0) {
    Write-Host "Compilation successful!"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  Start server:        java -cp `"bin;lib\*`" com.threatintel.Main"
    Write-Host "  Init DB schema:      java -cp `"bin;lib\*`" com.threatintel.Main --init-db"
    Write-Host "  Generate test data:  java -cp `"bin;lib\*`" com.threatintel.Main --generate-data"
    Write-Host ""
    Write-Host "Starting server..."
    java -cp "bin;lib\*" com.threatintel.Main
} else {
    Write-Host "Compilation failed. Please check the errors above."
    exit 1
}
