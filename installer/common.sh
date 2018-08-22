function fail() {
    echo "installation failed: $1"
    exit 1
}

function create_ace_dirs() {
	# creates any required ACE directories we need
	# this function assumes you are already in SAQ_HOME
    for d in \
        archive/email \
        archive/smtp_stream \
        archive/office \
        archive/ole \
        data \
        error_reports \
        etc/snort \
        logs \
        malicious \
        scan_failures \
		ssl/web \
        stats \
        storage \
        var \
        vt_cache \
        work 
	do
		if [ ! -d "$d" ]
		then
			echo "creating directory $d"
			mkdir -p "$d"
		fi
	done

	return 0
}
