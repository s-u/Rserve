<?php ob_start(); // just to make sure we can send headers
//
// Simple Rserve client for PHP.
// Supports Rserve protocol 0103 only (used by Rserve 0.5 and higher)
//
// NOTE: for a more complete PHP client see http://code.google.com/p/rserve-php
//
// (C)Copyright 2009 Simon Urbanek
// Licensed under GPL v2 or at your option v3
// 
// API functions:
// 
// * function Rserve_connect($host="127.0.0.1", $port=6311)
//   connects to Rserve. if port is 0 then host is interpreted as unix
//   socket, otherwise host is the host to connect to (default is
//   local) and port is the TCP port number (6311 is the default).
//   returns a socket used to communicate with Rserve
//
// * function Rserve_eval($socket, $command[, $attr])
//   evaluates the given command and returns the result
//   $attr is optional and is expected to be a reference to the
//   variable you want the R object attributes to be stored in.
//
// * function Rserve_close($socket)
//   closes the connection
//
// NOTE: The current client is very primitive and only supports
//       connect/eval/close. In addition, some return types of
//       eval are not implemented (e.g. complex). Also note that
//       arrays behave strangely in PHP (e.g. string indices get
//       converted to integers and behave differently than they
//       should) so beware that those quirks in PHP can cause
//       trouble for some named lists in R where the conventions
//       are not as erratic as in PHP.

//======= helper functions
$machine_is_bigendian = pack("s", 1); $machine_is_bigendian = ($machine_is_bigendian[0] == 0);
function int8($buf, $o=0) { return ord($buf[$o]); }
function int24($buf, $o=0) { return (ord($buf[$o]) | (ord($buf[$o + 1]) << 8) | (ord($buf[$o + 2]) << 16)); }
function int32($buf, $o=0) { return (ord($buf[$o]) | (ord($buf[$o + 1]) << 8) | (ord($buf[$o + 2]) << 16) | (ord($buf[$o + 3]) << 24)); }
function mkint32($i) { $r = chr($i & 255); $i >>= 8; $r .= chr($i & 255); $i >>=8; $r .= chr($i & 255); $i >>=8; $r .= chr($i & 255); return $r; }
function mkint24($i) { $r = chr($i & 255); $i >>= 8; $r .= chr($i & 255); $i >>=8; $r .= chr($i & 255); return $r; }
function flt64($buf, $o=0) { $ss = substr($buf, $o, 8); if ($machine_is_bigendian) for ($k = 0; $k < 7; $k++) $ss[7 - $k] = $buf[$o + $k]; $r = unpack("d", substr($buf, $o, 8)); return $r[1]; }

function mkp_str($cmd, $string) {
    $n = strlen($string) + 1; $string .= chr(0);
    while (($n & 3) != 0) { $string .= chr(1); $n++; }
    return mkint32($cmd) . mkint32($n + 4) . mkint32(0) . mkint32(0) . chr(4) . mkint24($n) . $string;
}

function get_rsp($socket) {
    $n = socket_recv($socket, $buf, 16, 0);
    if ($n != 16) return FALSE;
    $len = int32($buf, 4);
    $ltg = $len;
    while ($ltg > 0) {
       $n = socket_recv($socket, $b2, $ltg, 0);
       if ($n > 0) { $buf .= $b2; unset($b2); $ltg -= $n; } else break;
    }
    return $buf;
}

// parse SEXP results -- limited implementation for now (large packets and some data types are not supported)
function parse_SEXP($buf, $offset, $attr = NULL) {
    $r = $buf;
    $i = $offset;
    // some simple parsing - just skip attributes and assume short responses
    $ra = int8($r, $i);
    $rl = int24($r, $i + 1);
    $i += 4;
    $offset = $eoa = $i + $rl;
    // echo "[data type ".($ra & 63).", length ".$rl." with payload from ".$i." to ".$eoa."]<br/>\n";
    if (($ra & 64) == 64) {
	echo "sorry, long packets are not supported (yet)."; return FALSE;
    }
    if ($ra > 127) {
        $ra &= 127;
        $al = int24($r, $i + 1);
	$attr = parse_SEXP($buf, $i);
   	$i += $al + 4;
    } 
    if ($ra == 0) return NULL;
    if ($ra == 16) { // generic vector
	$a = array();
	while ($i < $eoa)
	    $a[] = parse_SEXP($buf, &$i);
	// if the 'names' attribute is set, convert the plain array into a map
	if (isset($attr['names'])) {
	    $names = $attr['names']; $na = array(); $n = count($a);
	    for ($k = 0; $k < $n; $k++) $na[$names[$k]] = $a[$k];
	    return $na;
	}
	return $a;
    }
    if ($ra == 19) { // symbol
	$oi = $i; while ($i < $eoa && ord($r[$i]) != 0) $i++;
	return substr($buf, $oi, $i - $oi);
    }
    if ($ra == 20 || $ra == 22) { // pairlist w/o tags
	$a = array();
	while ($i < $eoa) $a[] = parse_SEXP($buf, &$i);
	return $a;
    }
    if ($ra == 21 || $ra == 23) { // pairlist with tags
	$a = array();
	while ($i < $eoa) { $val = parse_SEXP($buf, &$i); $tag = parse_SEXP($buf, &$i); $a[$tag] = $val; }
	return $a;
    }
    if ($ra == 32) { // integer array
	$a = array();
	while ($i < $eoa) { $a[] = int32($r, $i); $i += 4; }
	if (count($a) == 1) return $a[0];
	return $a;
    }
    if ($ra == 33) { // double array
	$a = array();
	while ($i < $eoa) { $a[] = flt64($r, $i); $i += 8; }
	if (count($a) == 1) return $a[0];
	return $a;
    }
    if ($ra == 34) { // string array
        $a = array();
	$oi = $i;
	while ($i < $eoa) {
	    if (ord($r[$i]) == 0) {
		$a[] = substr($r, $oi, $i - $oi);
		$oi = $i + 1;
	    }
	    $i++;
	}
	if (count($a) == 1) return $a[0];
	return $a;
    }
    if ($ra == 36) { // boolean vector
	$n = int32($r, $i); $i += 4; $k = 0;
	$a = array();
	while ($k < $n) { $v = int8($r, $i++); $a[$k++] = ($v == 1) ? TRUE : (($v == 0) ? FALSE : NULL); }
	if ($n == 1) return $a[0];
	return $a;
    }
    if ($ra == 37) { // raw vector
	$len = int32($r, $i); $i += 4;
	return substr($r, $i, $len);
    }
    if ($ra == 48) { // unimplemented type in Rserve
	$uit = int32($r, $i);
	// echo "Note: result contains type #$uit unsupported by Rserve.<br/>";
	return NULL;
    }
    echo "Warning: type ".$ra." is currently not implemented in the PHP client.";
    return FALSE;
}

//------------ Rserve API functions

// if port is 0 then host is interpreted as unix socket, otherwise host is the host to connect to (default is local) and port is the TCP port number (6311 is the default)
function Rserve_connect($host="127.0.0.1", $port=6311) {
    if ($port == 0)
      $ok = (($socket = socket_create(AF_UNIX, SOCK_STREAM, 0)) and (socket_connect($socket, $host)));
    else
      $ok = (($socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) and (socket_connect($socket, $host, $port)));
    if ($ok) {
	$n = socket_recv($socket, $buf, 32, 0);
	if ($n < 32 || strncmp($buf, "Rsrv", 4) != 0) {
	     echo "Invalid response from server.";
	     return FALSE;
	}
	$rv = substr($buf, 4, 4);
	if (strcmp($rv, "0103") != 0) {
	     echo "Unsupported protocol version.";
	     return FALSE;
	}
    } else {
    	echo "Unable to connect<pre>".socket_strerror(socket_last_error())."</pre>";
	return FALSE;
    }
    return $socket;
}

function Rserve_eval($socket, $command, $attr = NULL) {
    $pkt = mkp_str(3, $command);
    socket_send($socket, $pkt, strlen($pkt), 0);
    $r = get_rsp($socket);
    $res = int32($r);
    $sc = ($res >> 24) & 127;
    $rr = $res & 255;
    if ($rr != 1) { echo "eval failed with error code " . $sc; return FALSE; }
    if (int8($r, 16) != 10) { echo "invalid response (expecting SEXP)"; return FALSE; }
    $i = 20;
    return parse_SEXP($r, $i, &$attr);
}

function Rserve_close($socket) {
    return socket_close($socket);
}

//========== FastRWeb - compatible requests - sample use of the client to behave like Rcgi in FastRWeb

$root = "/var/FastRWeb"; // set to the root of your FastRWeb installation - must be absolute

function process_FastRWeb() {
    global $root;
    // $req = array_merge($_GET, $_POST);
    $path = $_SERVER['PATH_INFO'];
    if (!isset($path)) { echo "No path specified."; return FALSE; }
    $sp = str_replace("..", "_", $path); // sanitize paths
    $script = "$root/web.R$sp.R";
    if (!file_exists($script)) { echo "Script [$script] $sp.R does not exist."; return FALSE; }
    // escape dangerous characters
    $script = str_replace("\\", "\\\\", $script);
    $script = str_replace("\"", "\\\"", $script);
    $qs = str_replace("\\", "\\\\", $_SERVER['QUERY_STRING']);
    $qs = str_replace("\"", "\\\"", $qs);
    $s = Rserve_connect();
    $r =  Rserve_eval($s, "{ qs<-\"$qs\"; setwd('$root/tmp'); library(FastRWeb); .out<-''; cmd<-'html'; ct<-'text/html'; hdr<-''; pars<-list(); lapply(strsplit(strsplit(qs,\"&\")[[1]],\"=\"),function(x) pars[[x[1]]]<<-x[2]); if(exists('init') && is.function(init)) init(); as.character(try({source(\"$script\"); as.WebResult(do.call(run, pars)) },silent=TRUE))}");
    Rserve_close($s);

    if (!is_array($r)) { // this ususally means that an erro rocurred since the returned value is jsut a string
	ob_end_flush();
	echo $r;
	exit(0);
    }

    if (isset($r[2])) header("Content-type: $r[2]");

    if (($r[0] == "file") or ($r[0] == "tmpfile")) {
	$f = fopen($r[1], "rb");
        $contents = '';
        while (!feof($f)) $contents .= fread($f, 8192);
	fclose($f);
	ob_end_clean();
	echo $contents;
	if ($r[0] == "tmpfile") unlink($r[0]);
	exit(0);
    }

    if ($r[0] == "html") {
	ob_end_clean();
	echo (is_array($r[1]) ? implode("\n", $r[1]) : $r[1]);
	exit(0);
    }

    print_r($r);

    ob_end_flush();

    exit(0);
}

//--- uncomment the following line if you want this script to serve as FastRWeb handler (see FastRWeb package and IASC paper)
// process_FastRWeb();

//========== user code -- example and test --

$s = Rserve_connect();
if ($s == FALSE) {
    echo "Connect FAILED";
} else {
    print_r (Rserve_eval($s, "list(str=R.version.string,foo=1:10,bar=1:5/2,logic=c(TRUE,FALSE,NA))"));
    echo "<p/>";
    print_r (Rserve_eval($s, "{x=rnorm(10); y=x+rnorm(10)/2; lm(y~x)}"));

    Rserve_close($s);
}

ob_end_flush();

?>
