$gitCmd = "C:\Users\Mitun S\AppData\Local\Programs\Git\cmd"
$gitBin = "C:\Users\Mitun S\AppData\Local\Programs\Git\mingw64\bin"
$env:Path = "$gitCmd;$gitBin;$env:Path"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  SecureCloud 2.0 - GitHub Push Utility" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Using Git: $(git --version)" -ForegroundColor Green
Write-Host "Pushing to https://github.com/S-Mitun/SECURECLOUD ..." -ForegroundColor Yellow

git push -u origin main
