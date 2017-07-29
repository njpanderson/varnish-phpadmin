#!/bin/sh
# This shell script is intended to be run as a user which can access the varnish
# command line tools (usually root). It will place files in the directory path
# as defined by the first argument to the script.
# To run: ./varnishstat-json.sh /path/to/stats
if [ -z "$1" ]; then
	echo "No path supplied. Please supply a path to store stat data.";
	exit 1;
fi

rootpath=$1;
minutes="$(date +%M)";
statsfilename="${rootpath}/stat/${minutes}.json";
topfilename="${rootpath}/top.json";
missesfilename="${rootpath}/top-misses.json";
uafilename="${rootpath}/top-ua.json";

if [ ! -d ${rootpath} ]; then
	echo "Root path not found.";
	exit 1;
fi

if [ ! -d "${rootpath}/stat" ]; then
	mkdir "${rootpath}/stat";
fi

chmod 755 ${rootpath};
chmod 755 "${rootpath}/stat";

# Get stats snapshot for this minute
varnishstat -j > "${statsfilename}";

# Get top requests snapshot
varnishtop -1 -g request -i ReqURL > "${topfilename}";

# Get top MISSes snapshot
varnishtop -1 -g request -i BereqURL > "${missesfilename}";

# Get top UA snapshot
varnishtop -1 -C -I "ReqHeader:User-Agent" > "${uafilename}";

files=$(find ${rootpath} -type f);
chmod 666 $files