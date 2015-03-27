#!/bin/bash

requirements=(
	"expect"
	"sed"
	"dd"
	"base64"
)

VERBOSE=false

if [[ $1 == "-h" || $1 == "--help" ]]; then 
	echo "Usage: $0 [-v]"
	echo -e "\t-v: verbose mode"
	exit 0
fi

if [[ $1 == "-v" ]]; then
	VERBOSE=true
fi

for req in "${requirements[@]}"; do
	which $req >/dev/null 2>&1 || { echo "$req not found, aborting"; exit 1; }
done

TESTDIR=$GOPATH/src/github.com/jfindley/skds/_testsuite
TMPDIR=$TESTDIR/_tmp
SOURCE=$TESTDIR/_source
PATH=$TESTDIR/bin:$PATH

cleanup() {
	kill $(<$TMPDIR/server.pid) 2>/dev/null
	rm -rf $TMPDIR/*
	rm -f $TESTDIR/server/*
	rm -f $TESTDIR/admin*/*
	rm -f $TESTDIR/client*/*
}

run_server() {
	skds-server -f server/server.conf &
	echo $! > $TMPDIR/server.pid
	sleep 10
}

run_client1() {
	skds-client -f client1/client.conf
}

run_client2() {
	skds-client -f client2/client.conf
}

# admin_firstrun username password installdir
admin_firstrun() {
	tmpfile=$TMPDIR/admin.$RANDOM.expect
	# newpass=$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | base64)
	newpass="randompass$RANDOM"
	cat <<-EOF > $tmpfile
		set timeout 60
		cd $TESTDIR
		spawn ./bin/skds-admin -d $3
		expect "Performing first-run install"
		expect "Enter your username:" {send -- "$1\r"}
		expect "Please enter your password:" {send -- "$2\r"}
		expect "Enter the server hostname:" {send -- "localhost\r"}
		expect "Enter the server port (default 8443):" {send "8443\r"}
		expect "Logged in"
		expect "Please enter a new password:" {send "$newpass\r"}
		expect "Please enter the password again:" {send "$newpass\r"}
		expect "First-run setup complete"
	EOF
	expect -f $tmpfile > /dev/null 2>&1
	echo "$newpass"
}

# admin_dir password
register-clients() {
	run_client1
	run_client2

	clientlist="$(echo admin user list | skds-admin -d $1 -p $2 )"

	if [[ $clientlist =~ "client1" && $clientlist =~ "client2" ]]; then
		echo OK
		return
	else
		echo FAIL
		if $VERBOSE; then echo "$clientlist"; fi
		return
	fi
}

tests=(
	"register-clients"
)

# admin_dir password
run_tests() {
	for t in "${tests[@]}"; do
		echo "Running test $t"
		$t $1 $2
	done
}


cd $TESTDIR

cleanup

sed "s|__DIR__|$TESTDIR/server|g" $SOURCE/server.conf > server/server.conf
sed -e "s|__DIR__|$TESTDIR/client1|g" -e "s|__NAME__|client1|g" $SOURCE/client.conf > client1/client.conf
sed -e "s|__DIR__|$TESTDIR/client2|g" -e "s|__NAME__|client2|g" $SOURCE/client.conf > client2/client.conf

# go build -o bin/skds-server github.com/jfindley/skds/server
# go build -o bin/skds-admin github.com/jfindley/skds/admin
# go build -o bin/skds-client github.com/jfindley/skds/client

run_server

PASS="$(admin_firstrun admin password $TESTDIR/admin1)"

run_tests $TESTDIR/admin1 "$PASS"

cleanup



