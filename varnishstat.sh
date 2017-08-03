#!/bin/sh
# This shell script is intended to be run as a user which can access the varnish
# command line tools (usually root). It will place files in the directory path
# as defined by the first argument to the script.
# To run: ./varnishstat-json.sh /path/to/data
if [ -z "$1" ]; then
	echo "No path supplied. Please supply a path to store stat data.";
	exit 1;
fi

rootpath=$1;
statspath="${rootpath}/stats";
hostspath="${rootpath}/hosts";
minutes="$(date +%M)";
statsfilename="${statspath}/${minutes}.json";

# Error out if the root path doesn't exist
if [ ! -d ${rootpath} ]; then
	echo "Root path not found.";
	exit 1;
fi

# Create stats path if it doesn't exist
if [ ! -d ${statspath} ]; then
	mkdir ${statspath};
fi

# Enforce mode on stats path
chmod 755 ${statspath};

# Produce stats snapshot based on current minute of the hour
varnishstat -j > "${statsfilename}";

# Loop through hostname paths to generate host specific data
if [ -d ${hostspath} ]; then
	# Enforce mode on hosts path
	chmod 755 ${hostspath};

	# Loop and produce host specific stats
	for foldername in ${hostspath}/*; do
		if [ -d ${foldername} ]; then
			hostroot=${foldername#${hostspath}/};

			topfilename="${foldername}/top.txt";
			missesfilename="${foldername}/top-misses.txt";
			uafilename="${foldername}/top-ua.txt";

			# Get top requests snapshot
			varnishtop -1 -g request -i ReqURL -q 'ReqHeader ~ "Host: '$hostroot'"' > ${topfilename};

			# Get top MISSes snapshot
			varnishtop -1 -g request -i BereqURL -q 'ReqHeader ~ "Host: '${hostroot}'"' > ${missesfilename};

			# Get top UA snapshot
			varnishtop -1 -C -I "ReqHeader:User-Agent" -q 'ReqHeader ~ "Host: '${hostroot}'"' > ${uafilename};
		fi
	done
else
	topfilename="${rootpath}/top.txt";
	missesfilename="${rootpath}/top-misses.txt";
	uafilename="${rootpath}/top-ua.txt";

	# Get top requests snapshot
	varnishtop -1 -g request -i ReqURL > ${topfilename};

	# Get top MISSes snapshot
	varnishtop -1 -g request -i BereqURL > ${missesfilename};

	# Get top UA snapshot
	varnishtop -1 -C -I "ReqHeader:User-Agent" > ${uafilename};
fi

# Enforce modes on all the sub files
files=$(find ${rootpath} -type f);
chmod 666 $files