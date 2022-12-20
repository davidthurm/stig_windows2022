$fancyDate = (Get-Date -f 'yyyy-MM-dd_HH-mm-ss')
Start-Transcript -Path "$($env:USERPROFILE)\Documents\MyScriptLog_$($fancyDate).txt" -NoClobber -Force

Stop-Transcript
