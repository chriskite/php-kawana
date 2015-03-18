<?php
namespace Kawana;

class Client {
    const DEFAULT_PORT = 9291;

    const PASS = 0;
    const CAPTCHA = 1;
    const BLOCK = 2;

    protected $captchaThresholds;
    protected $blockThresholds;
    protected $forgivenThreshold;
    protected $readTimeout;
  
    public function __construct($hostname, $port = self::DEFAULT_PORT) {
        $this->address = $hostname;
        $this->port = $port;
        $this->readTimeout = null;
    }

    public function setCaptchaThresholds($fiveMin, $hour, $day) {
        $this->captchaThresholds = [];
        $this->setThresholds($this->captchaThresholds, $fiveMin, $hour, $day);
    }

    public function setBlockThresholds($fiveMin, $hour, $day) {
        $this->blockThresholds = [];
        $this->setThresholds($this->blockThresholds, $fiveMin, $hour, $day);
    }

    public function setForgivenThreshold($numForgiven) {
        if($numForgiven <= 0) {
            throw new \InvalidArgumentException("numForgiven cannot be <= 0");
        }
        $this->forgivenThreshold = $numForgiven;
    }

    /*
    *  Set the socket read timeout in milliseconds.
    *  @param $milliseconds must be < 1000 and > 0
    */
    public function setReadTimeout($milliseconds) {
        if($milliseconds >= 1000 || $milliseconds <= 0) {
            throw new \InvalidArgumentException("milliseconds must be < 1000 and > 0");
        }

        $this->readTimeout = array("sec" => 0, "usec" => $milliseconds * 1000);
    }

    /*
    * Add the $impactAmount to the fiveMin, hour, and day windows for $ip
    * @param $ip long|string
    * @param $impactAmount int
    * @return one of PASS, CAPTCHA, or BLOCK based on the updated data.
    *         always returns PASS if the $ip is whitelisted, else
    *         returns BLOCK if the $ip is blacklisted.
    */
    public function logIP($ip, $impactAmount) {
        $this->ensureThresholdsSet();

        // convert string like '127.0.0.1' to long
        if(is_string($ip)) { $ip = ip2long($ip); }

        if($impactAmount <= 0) {
            throw new \InvalidArgumentException("logIP impactAmount cannot be <= 0");
        }

        $cmd = 0x01; // kawana command byte for LogIP
        $bytes = pack("CVV", $cmd, $ip, $impactAmount);
        $resp = $this->sendAndRecv($bytes);
        return $this->checkIPData($resp);
    }

    /*
    * Subtract a percentage of the captcha threshold from the $ip's 
    * fiveMin, hour, and day windows.
    * @param $percent optional between 0.0 and 1.0, defaults to 0.5
    * @return one of PASS, CAPTCHA, or BLOCK based on the updated data.
    *         always returns PASS if the $ip is whitelisted, else
    *         returns BLOCK if the $ip is blacklisted.
    */
    public function forgiveIP($ip, $percent = 0.5) {
        $this->ensureThresholdsSet();

        // convert string like '127.0.0.1' to long
        if(is_string($ip)) { $ip = ip2long($ip); }

        if($percent <= 0.0 || $percent > 1.0) {
            throw new \InvalidArgumentException("forgiveIP percent cannot be <= 0.0 or > 1.0");
        }

        $fiveMin = $this->captchaThresholds['fiveMin'];
        $hour = $this->captchaThresholds['hour'];
        $day = $this->captchaThresholds['day'];

        $cmd = 0x02; // kawana command byte for ForgiveIP
        $bytes = pack("CVVVV", $cmd, $ip, $fiveMin, $hour, $day);
        $resp = $this->sendAndRecv($bytes);
        return $this->checkIPData($resp);
    }

    public function whitelistIP($ip) {
        $this->setBlackWhite($ip, 1);
    }

    public function unWhitelistIP($ip) {
        $this->setBlackWhite($ip, 2);
    }

    public function blacklistIP($ip) {
        $this->setBlackWhite($ip, 3);
    }

    public function unBlacklistIP($ip) {
        $this->setBlackWhite($ip, 4);
    }

    protected function setBlackWhite($ip, $modifier) {
        $validMods = [1, 2, 3, 4];
        if(!in_array($modifier, $validMods)) {
            throw new \InvalidArgumentException("Invalid BlackWhite modifier: $modifier");
        }

        // convert string like '127.0.0.1' to long
        if(is_string($ip)) { $ip = ip2long($ip); }

        $cmd = 0x03; // kawana command byte for BlackWhite
        $bytes = pack("CVC", $cmd, $ip, $modifier);
        $this->sendAndRecv($bytes);
    }

    protected function checkIPData($resp) {
        $result = unpack("V3impacts/Sforgiven/Cbw", $resp);

        foreach(['impacts1', 'impacts2', 'impacts3', 'forgiven', 'bw'] as $field) {
            if(!isset($result[$field])) {
                throw new \Exception("Invalid response from server");
            }
        }

        $maxImpacts = [
            'fiveMin' => $result['impacts1'],
            'hour'    => $result['impacts2'],
            'day'     => $result['impacts3']
        ];

        print_r($result);
        // check blacklist and whitelist
        if($result['bw'] & 0x01) {
            return self::PASS;
        }
        if($result['bw'] & 0x02) {
            return self::BLOCK;
        }

        // check block
        foreach($maxImpacts as $time => $impact) {
            if($impact >= $this->blockThresholds[$time]) {
                return self::BLOCK;
            }
        }

        // check captcha
        foreach($maxImpacts as $time => $impact) {
            if($impact >= $this->captchaThresholds[$time]) {
                return self::CAPTCHA;
            }
        }

        // check forgiven
        if($result['forgiven'] >= $this->forgivenThreshold) {
            return self::BLOCK;
        }

        return self::PASS;
    }

    /*
     * @return string response bytes
     */
    protected function sendAndRecv($bytes) {
        $responseLength = 15; // kawana response is 15 bytes

        // create socket
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if($socket === false) {
            throwSocketException('socket_create', $socket);
        }

        if(null !== $this->readTimeout && !socket_set_option($socket,SOL_SOCKET, SO_RCVTIMEO, $this->readTimeout)) {
            throwSocketException('socket_set_options', $socket);
        }

        // connect to kawana server
        $connected = socket_connect($socket, $this->address, $this->port);
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

        socket_close($socket);

        return $resp;
    }

    protected function setThresholds(&$arr, $fiveMin, $hour, $day) {
        foreach([$fiveMin, $hour, $day] as $threshold) {
            if($threshold < 0) {
                throw new \InvalidArgumentException("Threshold cannot be less than 0");
            }
        }

        $arr['fiveMin'] = $fiveMin;
        $arr['hour'] = $hour;
        $arr['day'] = $day;
    }

    protected function ensureThresholdsSet() {
        if(empty($this->blockThresholds)) {
            throw new \Exception("Must call setBlockThresholds() before using client");
        }
        if(empty($this->captchaThresholds)) {
            throw new \Exception("Must call setCaptchaThresholds() before using client");
        }
        if(empty($this->forgivenThreshold)) {
            throw new \Exception("Must call setForgivenThreshold() before using client");
        }
    }
}

function throwSocketException($fnName, $socket) {
    throw new \Exception("$fnName() failed: " . socket_strerror(socket_last_error($socket)));

}
