<?php
namespace Kawana;

class Client {
    const DEFAULT_PORT = 9291;

    const PASS = 0;
    const CAPTCHA = 1;
    const BLOCK = 2;
  
    public function __construct($hostname, $port = null) {
        $this->_address = gethostbyname($hostname);
        $this->_port = $port || DEFAULT_PORT;
    }

    public function setCaptchaThresholds($fiveMin, $hour, $day) {
        $this->_setThresholds($this->_captchaThresholds, $fiveMin, $hour, $day);
    }

    public function setBlockThreshold($fiveMin, $hour, $day) {
        $this->_setThresholds($this->_blockThresholds, $fiveMin, $hour, $day);
    }

    /*
    * Add the $impactAmount to the fiveMin, hour, and day windows for $ip
    * @param $ip long or string
    * @param $impactAmount int
    * @return one of PASS, CAPTCHA, or BLOCK based on the updated data.
    *         always returns PASS if the $ip is whitelisted, else
    *         returns BLOCK if the $ip is blacklisted.
    */
    public function logIP($ip, $impactAmount);

    /*
    * Subtract a percentage of the captcha threshold from the $ip's 
    * fiveMin, hour, and day windows.
    * @param $percent optional between 0.0 and 1.0, defaults to 0.5
    * @return one of PASS, CAPTCHA, or BLOCK based on the updated data.
    *         always returns PASS if the $ip is whitelisted, else
    *         returns BLOCK if the $ip is blacklisted.
    */
    public function forgiveIP($percent = null);

    public function whitelistIP($ip);
    public function blacklistIP($ip);
    public function unWhitelistIP($ip);
    public function unBlacklistIP($ip);


    /*
     * @return string response bytes
     */
    protected function _sendAndRecv($bytes, $responseLength) {
        // create socket
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($socket === false) {
            throw new Exception("socket_create() failed: reason: " . socket_strerror(socket_last_error($socket)));
        }

        // connect to kawana server
        $connected = socket_connect($socket, $address, $service_port);
        if ($connected === false) {
            throw new Exception("socket_connect() failed.\nReason: ($connected) " . socket_strerror(socket_last_error($socket)));
        } 

        // write bytes to server
        $numBytes = strlen($bytes);
        for($sent = 0; $sent < $numBytes;) {
            $n = socket_write($socket, $bytes);
            if($n === false) {
                throw new Exception("socket_write() failed: reason: " . socket_strerror(socket_last_error($socket)));
            }
            $sent += $n;
        }

        // read response from server
        $resp = "";
        for($recvd = 0; $recvd < $responseLength;) {
            $r = socket_read($socket, $responseLength);
            if($r === false) {
                throw new Exception("socket_read() failed: reason: " . socket_strerror(socket_last_error($socket)));
            }
            $recvd += strlen($r);
            $resp .= $r;
        }

        return $resp;
    }

    protected function _setThresholds($arr, $fiveMin, $hour, $day) {
        foreach([$fiveMin, $hour, $day] as $threshold) {
            if($threshold < 0) {
                throw new Exception("Threshold cannot be less than 0");
            }
        }

        $arr['fiveMin'] = $fiveMin;
        $arr['hour'] = $hour;
        $arr['day'] = $day;
    }
}
