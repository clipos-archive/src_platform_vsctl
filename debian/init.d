#!/bin/sh
### BEGIN INIT INFO
# Provides:          vsctl
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: <Enter a short description of the sortware>
# Description:       <Enter a long description of the software>
#                    <...>
#                    <...>
### END INIT INFO

# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2007-2018 ANSSI. All Rights Reserved.
# Author: Olivier Levillain <clipos@ssi.gouv.fr>

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
NAME=vsctl             # Introduce a short description here
SCRIPTNAME=/etc/init.d/$NAME

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions


do_vsattr() {
	local list="$1"
	local attr="--$2"

	local reallist=""
	for _f in ${list}; do 
		[ -e "${_f}" ] && reallist="${reallist} ${_f}"
	done
	[ -z "${reallist}" ] && return 0
	/bin/echo "${reallist}" | xargs vsattr ${attr}
}

do_start()
{
	local ret=0
	do_vsattr "$VPROCUNHIDE_NONE" '~admin' || ret=1
	do_vsattr "$VPROCUNHIDE_ALL" '~hide' || ret=1
	return $ret
}


case "$1" in
	start)
		[ "$VERBOSE" != no ] && log_daemon_msg "Fixing /proc files visibility" "$NAME"
		do_start
		case "$?" in
			0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
			2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
		esac
		;;
	stop)
		;;
	force-reload)
		do_start
		;;
	restart)
		do_start
		;;
	*)
		echo "Usage: $SCRIPTNAME {start|stop}" >&2
		exit 3
		;;
esac

:
