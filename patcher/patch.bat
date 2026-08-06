@echo off
setlocal
cd /d "%~dp0"

rem === Pick Python: prefer venv, else system python ===
set "PY=venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

rem === SSL-inspection method ===
rem   NSC patch works on ALL apps incl. hardened SoLoader apps (Instagram,
rem   Facebook, ...). It makes the app trust user-installed CAs so you can
rem   intercept HTTPS with a proxy + your proxy CA. Bundles are merged to one
rem   installable .apk. (Frida-gadget injection is NOT used here because it
rem   crashes SoLoader apps; run patch.py directly if you want that instead.)
set "ARGS=--patch-nsc --no-gadget"

if not "%~1"=="" goto haveargs
echo.
echo Usage: drag ^& drop APK / XAPK / APKS / APKM file(s) onto this .bat
echo        You can drop multiple files at once.
echo.
pause
exit /b 1

:haveargs
echo Method: NSC patch (trust user CAs) -^> single installable .apk
set "FAIL=0"
set "COUNT=0"

rem === Process every dropped file in order (spaces in path are OK) ===
for %%F in (%*) do call :process "%%~F"

echo.
echo ------------------------------------------------------------
if "%FAIL%"=="0" goto allok
echo Some file(s) FAILED. Check the ERROR messages above.
goto summary_end
:allok
echo All %COUNT% file(s) processed successfully.
:summary_end
echo Output is next to each input as "<name>_patched.apk".
echo To intercept traffic: install your proxy CA as a USER cert on the
echo device, set the device proxy to your host, then launch the app.
echo ------------------------------------------------------------
echo.
pause
exit /b %FAIL%

rem ============================================================
rem  Process a single file (arg1 = file path)
rem ============================================================
:process
set /a COUNT+=1
echo.
echo ============================================================
echo  Processing: %~nx1
echo ============================================================
"%PY%" patch.py -i "%~1" %ARGS%
set "RC=%errorlevel%"
if "%RC%"=="0" echo [OK]   %~nx1
if not "%RC%"=="0" echo [FAIL] %~nx1
if not "%RC%"=="0" set "FAIL=1"
goto :eof
