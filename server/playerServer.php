<?php

function proper_parse_str($str)
{
	$arr = array();			# result array
	$pairs = explode('&', $str);	# split on outer delimiter
	foreach ($pairs as $i) {		# loop through each pair
		if (strpos($i, "=") !== false) {
			list($name,$value) = explode('=', $i, 2);	# split into name and value

			if( isset($arr[$name]) ) {		# if name already exists
				if( is_array($arr[$name]) ) {
					$arr[$name][] = $value;		# stick multiple values into an array
				}
				else {
					$arr[$name] = array($arr[$name], $value);
				}
			}
			else {
				$arr[$name] = $value;		# otherwise, simply stick it in a scalar
			}
		}
	}
	return $arr;
}
function memshare($mode,$data){
	$id =  msg_get_queue ( 1 );
    if (!msg_send ($id, $mode, $data, false, true, $msg_err)) {
  		echo "faile!";
		echo "Msg not sent because $msg_err\n";
  	}else{
 		//echo "success!";
 	}
}

function downloadFile($filename)
{
	$dir="2nd/";

	if (file_exists($dir.$filename)) {
		$file = @fopen($dir.$filename, "rb");
		if ($file) {
			
			Header ( "Content-type: application/octet-stream" );
		
			Header ( "Accept-Ranges: bytes" );
			Header ( "Accept-Length: " . filesize ($dir.$filename ) );
			Header ( "Content-Disposition: attachment; filename=" . $filename );

			fseek($file, 0);

    		//ob_start();
    		while (!feof($file)) {
        		$chunk_size = 1024 * 1024 * 2; // 2MB
        		echo fread($file, $chunk_size);
        		ob_flush(); 
        		flush(); 
       		// sleep(1); 
    		}
    		//ob_end_clean();
			fclose($file);
		}
		else {
            $http_code = 503;
		    header( "HTTP/2 ". $http_code . " Internal Server Error", true, $http_code);
		    header( "X-Error-Description: Index file for rendition report cannot be opened ". $filename . " ;");
        }
	}
	else {
        $http_code = 503;
		header( "HTTP/2 ". $http_code . " Internal Server Error", true, $http_code);
        header( "X-Error-Description: Index file for requested rendition report does not exist ".$filename . " ;");
	}
}
function getFileContent($filename)
{
	$content="";

	if (file_exists($filename)) {
		$handle = @fopen($filename, "r");
		if ($handle) {
			$emit_next = false;
			while (($buffer = fgets($handle, 4096)) !== false) {
				$content = $content . $buffer;
            }
				fclose($handle);
		}
		else {
            $http_code = 503;
		    header( "HTTP/2 ". $http_code . " Internal Server Error", true, $http_code);
		    header( "X-Error-Description: Index file for rendition report cannot be opened ". $filename . " ;");
        }
	}
	else {
        $http_code = 503;
		header( "HTTP/2 ". $http_code . " Internal Server Error", true, $http_code);
        header( "X-Error-Description: Index file for requested rendition report does not exist ". $filename . " ;");
	}
	return $content;
}

// print_r($_SERVER);	
// print_r($_GET);
// print_r($_ENV);
// echo $_SERVER['REMOTE_PORT']."\n";	
$url =  $_SERVER['REQUEST_URI'];
$fileName = parse_url($url, PHP_URL_PATH);
$fileName = substr($fileName, 1);
$query_string = parse_url($url, PHP_URL_QUERY);
$query_params = proper_parse_str($query_string);
$flow_key = array_key_exists('flowid', $query_params) ? $query_params['flowid'] : "1";
$mode = array_key_exists('mode', $query_params) ? $query_params['mode'] : "1";
$player_type = array_key_exists('player_type', $query_params) ? $query_params['player_type'] : "1";
$target_rate = array_key_exists('target_rate', $query_params) ? $query_params['target_rate'] : "1";
$value = $target_rate."#".$mode."#".$player_type."#";
memshare($flow_key,$value);
downloadFile($fileName);

#$content = getFileContent($fileName);
#echo $content;
#$curl = "http://10.10.194.143:8080/".$fileName;
#header('location:'.$curl);

?>
