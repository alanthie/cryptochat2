#  ------------------------------------------------------
#  SET THE FOLDER where repositories are
#	 if your downloaded in /home/allaptop/dev/cryptochat2
#	 then FOLDER="/home/allaptop/dev"
#	
#	 Using sudo apt - You may need to change it for your distro
#  ------------------------------------------------------
FOLDER="/home/allaptop/dev"

if [ -d "${FOLDER}" ]; then
	echo "Using directory ${FOLDER}"
else
	echo "Directory not set"
	exit
fi
	
function install_pkg()
{
	status="$(dpkg-query -W --showformat='${db:Status-Status}' "$1" 2>&1)"
	if [ ! $? = 0 ] || [ ! "$status" = installed ] 
	then
		sudo apt -y install $1
	else
		echo "$1 is already installed"
	fi
}

function remove_pkg()
{
	status="$(dpkg-query -W --showformat='${db:Status-Status}' "$1" 2>&1)"
	if [ ! $? = 0 ] || [ ! "$status" = installed ] 
	then
		echo "$1 is not installed"
	else
		sudo apt -y remove --auto-remove $1
		sudo apt -y purge --auto-remove $1
	fi
}

function git_clone()
{
	if [ -d "$2" ]; then
		echo "Directory already exist $2 ..."
	else
		mkdir $2
		git clone $1 $2
	fi
}

# MANUAL 
#sudo apt update
#sudo apt upgrade

install_pkg g++
install_pkg build-essential
install_pkg aptitude
install_pkg ccache
install_pkg libgmp-dev
install_pkg libcurl4-gnutls-dev
install_pkg cmake
install_pkg git
install_pkg libsfml-dev
install_pkg libopencv-dev
install_pkg ffmpeg

# notcurses
install_pkg doctest-dev 
install_pkg libavdevice-dev 
install_pkg libdeflate-dev 
install_pkg libgpm-dev 
install_pkg libncurses-dev 
install_pkg libqrcodegen-dev 
install_pkg libswscale-dev 
install_pkg libunistring-dev 
install_pkg pandoc 
install_pkg pkg-config

git_clone https://github.com/alanthie/notcurses.git "${FOLDER}/notcurses"
cd "${FOLDER}/notcurses"
if [ -d "${FOLDER}/notcurses/build" ]; then
	echo "Directory already exist ${FOLDER}/notcurses/build ..."
	cd "${FOLDER}/notcurses/build"
	make
	# TODO - detect change in lib...
	# sudo make install
else
	mkdir build
	cd build
	cmake ..
	make
  sudo make install
fi
	
git_clone  https://github.com/ckormanyos/wide-integer.git "${FOLDER}/wide-integer"
git_clone  https://github.com/ckormanyos/wide-decimal.git "${FOLDER}/wide-decimal"
 
git_clone https://github.com/libevent/libevent.git  "${FOLDER}/libevent"
cd "${FOLDER}/libevent"
if [ -d "${FOLDER}/libevent/build" ]; then
	echo "Directory already exist ${FOLDER}/libevent/build ..."
	cd "${FOLDER}/libevent/build"
	make
else
	mkdir build
	cd build
	cmake ..
	make
fi

#copy event-config.h from build to event2 folder if missing
#From /home/alain/dev/libevent/build/include/event2/event-config.h
# /home/alain/dev/libevent/include/event2/
if [ -f "${FOLDER}/libevent/include/event2/event-config.h" ]; then
	echo "File already exist ${FOLDER}/libevent/include/event2/event-config.h..."
	# TODO - detect change in file...
	# cp "${FOLDER}/libevent/build/include/event2/event-config.h" "${FOLDER}/libevent/include/event2/"
else
	cp "${FOLDER}/libevent/build/include/event2/event-config.h" "${FOLDER}/libevent/include/event2/"
fi


#  ------------------------------------------------------
#  cryptochat2
#  ------------------------------------------------------
# git_clone   https://github.com/alanthie/cryptochat2.git "${FOLDER}/cryptochat2"
cd "${FOLDER}/cryptochat2"
if [ -d "${FOLDER}/cryptochat2/build" ]; then
	echo "Directory already exist ${FOLDER}/cryptochat2/build ..."
	cd "${FOLDER}/cryptochat2/build"
	cmake ..
	make
else
	mkdir build
	cd build
	cmake ..
	make
fi

#exit

#  ------------------------------------------------------
#  EXTRA - remove previous exit if want this tool
#  Encryptions
#  ------------------------------------------------------
git_clone   https://github.com/libntl/ntl.git  "${FOLDER}/ntl"
cd "${FOLDER}/ntl/src"
if [ -f "${FOLDER}/ntl/src/ntl.a" ]; then
	echo "Lib already exist ${FOLDER}/ntl/src/ntl.a ..."
	cd "${FOLDER}/ntl/src"
	make
	# TODO - detect change in lib...
	# sudo make install
else
	./configure 
	make
	sudo make install
fi

git_clone   https://github.com/alanthie/Encryptions.git "${FOLDER}/Encryptions"
cd "${FOLDER}/Encryptions"
if [ -d "${FOLDER}/Encryptions/build" ]; then
	echo "Directory already exist ${FOLDER}/Encryptions/build ..."
	cd "${FOLDER}/Encryptions/build"
	make
else
	mkdir build
	cd build
	cmake ..
	make
fi




