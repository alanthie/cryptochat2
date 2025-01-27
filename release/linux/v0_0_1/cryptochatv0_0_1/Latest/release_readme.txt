CryptoChat version 0.0.1
Copyright © 2024–2025 Alain Lanhier
This program comes with absolutely no warranty

RELEASE LINUX:
lnx_chatcli
lnx_chatsrv
mediaviewer
res (ressource folder for the mediaviewer)

DEPENDENCIES (you may install the none dev version instead, which are smaller):
sudo apt-get update
sudo apt-get install build-essential
sudo apt-get install libunistring-dev
sudo apt-get install libcurl4-gnutls-dev
sudo apt-get install libsfml-dev
sudo apt-get install libopencv-dev
sudo apt install ffmpeg

Start a server [then follow the setup instructions]:
./lnx_chatsrv -cfg cfgsrv.txt

Start a client [then follow the setup instructions]:
./lnx_chatscli -cfg cfgcli1.txt

To have a public server on the internet, you have to do port forwarding on your router


