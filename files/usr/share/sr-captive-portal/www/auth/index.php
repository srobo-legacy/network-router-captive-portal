<?php

define("TEAM_PREFIX", "team-");

require_once("SSOClient.php");

function IPtoMAC($ip){
	//Do an ARP request for it
	$MAC = trim(shell_exec("/usr/sbin/arp -n | grep -E '^$ip' | awk '{print $3;}'"));
	if(!$MAC) $MAC = trim(shell_exec("ping -c 1 $ip 2>&1 >/dev/null && ( /usr/sbin/arp -n | grep -E '^$ip' | awk '{print $3;}' )"));
	if(!$MAC) return false;
	return $MAC;
}

function GetLocalGroups($username){
	$groups = explode("\n", shell_exec("id " . $username . " 2>/dev/null | awk '{print $3;}' | awk -F= '{print $2;}' | awk -F, '{out=\"\"; for(i=1; i<=NF; i++){print \$i;}}'"));
	$groupNames = array();
	foreach($groups as $group){
		$groupName = substr($group, strpos($group, "(") + 1);
		$groupName = substr($groupName, 0, strpos($group, ")") - strpos($group, "(") - 1);
		$groupNames[] = $groupName;
	}
	return $groupNames;
}

function UpdateMACList($mac, $user){
	$lockHandle = fopen("/usr/share/sr-captive-portal/data/portal-macs.lock", "a"); //Open a lock file.
	flock($lockHandle, LOCK_EX);	//Lock the file
	ftruncate($lockHandle, 0);	//Empty the file
	fwrite($lockHandle, $_SERVER["REMOTE_ADDR"] . " locked portal-macs"); //Store a useful message about who locked it.

	//Now do stuff with portal-macs
	$macUsers = unserialize(file_get_contents("/usr/share/sr-captive-portal/data/portal-macs"));
	chmod("/usr/share/sr-captive-portal/data/portal-macs", 0600);
	$macUsers[$mac] = $user;

	file_put_contents("/usr/share/sr-captive-portal/data/portal-macs", serialize($macUsers));
	//Close the lock file off
	fclose($lockHandle);
	//Delete the lock
	unlink("/usr/share/sr-captive-portal/data/portal-macs.lock");
}

$sso_url = "https://www.studentrobotics.org/external-auth/";
$sso_pub_key = file_get_contents("/etc/sr-captive-portal/key.pub");

$ip = $_SERVER["REMOTE_ADDR"];
$mac = strtolower(IPtoMAC($ip));

if(!$mac){
	header("Location: no_mac.php");
	exit();
}

$isAlreadyAuthed = trim(shell_exec("sudo /usr/bin/sr-portal-status $mac | grep -E '^Username:' | awk '{print $2;}'"));
if($isAlreadyAuthed != "Guest"){
	// Make sure they actually do at least have internet access
	shell_exec("sudo /usr/bin/sr-portal-grant $mac internet");

	// Take them back where they came from
	header("Location: " . $_GET["from"]);
	exit();
}

#### IF WE GET TO THIS POINT THE CLIENT IS NOT AUTHENTICATED AT ALL ####

$sso = new SSOClient($sso_url, $sso_pub_key);

//Force a login
$UserInfo = $sso->DoSSO();

if(in_array("mentors", $UserInfo->groups)){
	// User is a blueshirt, permit access to staff and competitor
	shell_exec("sudo /usr/bin/sr-portal-grant $mac staff");
}

//Look up the local groups
$LocalGroups = GetLocalGroups("sys-" . $UserInfo->username);

// Are they a sysadmin
if(in_array("sr-sysadmins", $LocalGroups)){
	// User is a sysadmin, permit access to management
	shell_exec("sudo /usr/bin/sr-portal-grant $mac management");
}
// Are they a video admin
if(in_array("sr-videoadmins", $LocalGroups)){
	// User is a video admin, permit access to video
	shell_exec("sudo /usr/bin/sr-portal-grant $mac video");
}
// Are they a competition network admin
if(in_array("sr-compnetadmins", $LocalGroups)){
	// User is a comp net admin, permit access to competition services.
	shell_exec("sudo /usr/bin/sr-portal-grant $mac compnet");
}

// Allow everyone to access the internet
shell_exec("sudo /usr/bin/sr-portal-grant $mac internet");

UpdateMACList($mac, $UserInfo->username);

header("Location: " . $_GET["from"]);

?>
