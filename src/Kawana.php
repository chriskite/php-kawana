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

    public function setForgivenThreshold($numForgiven) {
        if($numForgiven <= 0) {
            throw new Exception("numForgiven cannot be negative or 0");
        }
        $this->_forgivenThreshold = $numForgiven;
    }

    /*
    * Add the $impactAmount to the fiveMin, hour, and day windows for $ip
    * @param $ip long|string
    * @param $impactAmount int
    * @return one of PASS, CAPTCHA, or BLOCK based on the updated data.
    *         always returns PASS if the $ip is whitelisted, else
    *         returns BLOCK if the $ip is blacklisted.
    */
    public function logIP($ip, int $impactAmount) {
        // convert string like '127.0.0.1' to long
        if(is_string($ip)) { $ip = ip2long($ip); }

        if($impactAmount <= 0) {
            throw new Exception("logIP impactAmount cannot be <= 0");
        }

        $cmd = 0x01; // kawana command byte for LogIP
        $bytes = pack("CVV", $cmd, $ip, $impactAmount);
        $resp = $this->_sendAndRecv($bytes);
        return $this->_checkIPData($resp);
    }

    /*
    * Subtract a percentage of the captcha threshold from the $ip's 
    * fiveMin, hour, and day windows.
    * @param $percent optional between 0.0 and 1.0, defaults to 0.5
    * @return one of PASS, CAPTCHA, or BLOCK based on the updated data.
    *         always returns PASS if the $ip is whitelisted, else
    *         returns BLOCK if the $ip is blacklisted.
    */
    public function forgiveIP($percent = 0.5) {
        // convert string like '127.0.0.1' to long
        if(is_string($ip)) { $ip = ip2long($ip); }

        if($percent <= 0.0 || $percent > 1.0) {
            throw new Exception("forgiveIP percent cannot be <= 0.0 or > 1.0");
        }

        $fiveMin = $this->_captchaThresholds['fiveMin'];
        $hour = $this->_captchaThresholds['hour'];
        $day = $this->_captchaThresholds['day'];

        $cmd = 0x02; // kawana command byte for ForgiveIP
        $bytes = pack("CVVVV", $cmd, $ip, $fiveMin, $hour, $day);
        $resp = $this->_sendAndRecv($bytes);
        return $this->_checkIPData($resp);
    }

    public function whitelistIP($ip) {
        $this->_setBlackWhite($ip, 1);
    }

    public function blacklistIP($ip) {
        $this->_setBlackWhite($ip, 2);
    }

    public function unWhitelistIP($ip) {
        $this->_setBlackWhite($ip, 3);
    }

    public function unBlacklistIP($ip) {
        $this->_setBlackWhite($ip, 4);
    }

    protected function _setBlackWhite($ip, $modifier) {
        $validMods = [1, 2, 3, 4];
        if(!in_array($modifier, $validMods)) {
            throw new Exception("Invalid BlackWhite modifier: $modifier");
        }

        $cmd = 0x03; // kawana command byte for BlackWhite
        $bytes = pack("CVC", $cmd, $ip, $modifier);
        $this->_sendAndRecv($bytes);
    }

    protected function _checkIPData($resp) {
        $result = unpack("V3impacts/Sforgiven/Cbw", $resp);

        foreach(['impacts', 'forgiven', 'bw'] as $field) {
            if(!isset($result[$field])) {
                throw new Exception("Invalid response from server");
            }
        }

        $maxImpacts = [
            'fiveMin' => $result['impacts'][0],
            'hour'    => $result['impacts'][1],
            'day'     => $result['impacts'][2]
        ]

        // check blacklist and whitelist
        if($result['bw'] & 0x01) {
            return PASS;
        }
        if($result['bw'] & 0x02) {
            return BLOCK;
        }

        // check block
        foreach($maxImpacts as $time => $impact) {
            if($impact >= $this->_blockThresholds[$time]) {
                return BLOCK;
            }
        }

        // check captcha
        foreach($maxImpacts as $time => $impact) {
            if($impact >= $this->_captchaThresholds[$time]) {
                return CAPTCHA;
            }
        }

        // check forgiven
        if($result['forgiven'] >= $this->_forgivenThreshold) {
            return BLOCK;
        }

        return PASS;
    }

    /*
     * @return string response bytes
     */
    protected function _sendAndRecv($bytes) {
        $responseLength = 15; // kawana response is 15 bytes

        // create socket
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($socket === false) {
            throwSocketException('socket_create', $socket);
        }

        // connect to kawana server
        $connected = socket_connect($socket, $this->_address, $this->_port);
        if ($connected === false) {
            throwSocketException('socket_connect', $socket);
        } 

        // write bytes to server
        $numBytes = strlen($bytes);
        for($sent = 0; $sent < $numBytes;) {
            $n = socket_write($socket, $bytes);
            if($n === false) {
                throwSocketException('socket_write', $socket);
            }
            $sent += $n;
        }

        // read response from server
        $resp = "";
        for($recvd = 0; $recvd < $responseLength;) {
            $r = socket_read($socket, $responseLength);
            if($r === false) {
                throwSocketException('socket_read', $socket);
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

function throwSocketException($fnName, $socket) {
    throw new Exception("$fnName() failed: " . socket_strerror(socket_last_error($socket)));

}
