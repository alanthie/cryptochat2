if [ -d /home/allaptop/dev/cryptochatal/release/linux/Latest/ ]; then
	rm -r /home/allaptop/dev/cryptochatal/release/linux/Latest/*
	
	cp /home/allaptop/dev/cryptochatal/build/lnx_chatcli/lnx_chatcli /home/allaptop/dev/cryptochatal/release/linux/Latest/
	cp /home/allaptop/dev/cryptochatal/build/lnx_chatsrv/lnx_chatsrv /home/allaptop/dev/cryptochatal/release/linux/Latest/
	cp /home/allaptop/dev/cryptochatal/build/mediaviewer/mediaviewer /home/allaptop/dev/cryptochatal/release/linux/Latest/
	cp -r /home/allaptop/dev/cryptochatal/mediaviewer/prj/res /home/allaptop/dev/cryptochatal/release/linux/Latest/
	
	cp /home/allaptop/dev/cryptochatal/release_readme.txt /home/allaptop/dev/cryptochatal/release/linux/Latest/
fi

