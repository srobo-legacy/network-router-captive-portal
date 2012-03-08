<?php

function IPtoMAC($ip){
	//Do an ARP request for it
	$MAC = trim(shell_exec("/usr/sbin/arp -n | grep -E '^$ip' | awk '{print $3;}'"));
	if(!$MAC) $MAC = trim(shell_exec("ping -c 1 $ip 2>&1 >/dev/null && ( /usr/sbin/arp -n | grep -E '^$ip' | awk '{print $3;}' )"));
	if(!$MAC) return false;
	return $MAC;
}

function ClearMACUser($mac){
	$lockHandle = fopen("/usr/share/sr-captive-portal/data/portal-macs.lock", "a"); //Open a lock file.
	flock($lockHandle, LOCK_EX);	//Lock the file
	ftruncate($lockHandle, 0);	//Empty the file
	fwrite($lockHandle, $_SERVER["REMOTE_ADDR"] . " locked portal-macs"); //Store a useful message about who locked it.

	//Now do stuff with portal-macs
	$macUsers = unserialize(file_get_contents("/usr/share/sr-captive-portal/data/portal-macs"));
	chmod("/usr/share/sr-captive-portal/data/portal-macs", 0600);
	unset($macUsers[$mac]);

	file_put_contents("/usr/share/sr-captive-portal/data/portal-macs", serialize($macUsers));
	//Close the lock file off
	fclose($lockHandle);
	//Delete the lock
	unlink("/usr/share/sr-captive-portal/data/portal-macs.lock");
}

$ip = $_SERVER["REMOTE_ADDR"];
$mac = strtolower(IPtoMAC($ip));

if(!$mac){
	header("Location: no_mac.php");
	exit();
}

// Revoke ALL access
shell_exec("sudo /usr/bin/sr-portal-revoke $mac staff");
shell_exec("sudo /usr/bin/sr-portal-revoke $mac management");
shell_exec("sudo /usr/bin/sr-portal-revoke $mac video");
shell_exec("sudo /usr/bin/sr-portal-revoke $mac compnet");
shell_exec("sudo /usr/bin/sr-portal-revoke $mac internet");

ClearMACUser($mac);

echo "OK";

?>
