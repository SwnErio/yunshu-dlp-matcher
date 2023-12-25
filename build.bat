@echo off

PUSHD "%~dp0%

set OldPath = "%Path%"

echo [%date% %time%] Start building

del ".\ReleaseFiles\*" /F /Q /S

cargo build -p matcher-ffi --release --target=i686-pc-windows-msvc
IF ERRORLEVEL 1 goto Error

md ".\ReleaseFiles\"
md ".\ReleaseFiles\pdb\"
copy ".\target\i686-pc-windows-msvc\release\matcher.dll" ".\ReleaseFiles\matcher.dll"
copy ".\target\i686-pc-windows-msvc\release\matcher.pdb" ".\ReleaseFiles\pdb\matcher.pdb"

echo [%date% %time%] Building Complete!

set Path = "%OldPath%"
POPD
goto :EOF

:Error
set Path = "%OldPath%"
POPD
pause