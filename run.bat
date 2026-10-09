@echo off
rem Windows launcher (needs Python 3.9+; no other packages). Opens the UI in your browser.
cd /d "%~dp0"
python -m lvx serve --open %*
