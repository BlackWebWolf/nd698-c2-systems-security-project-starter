rule unknown_threat_detector {
        meta:
                Author = "@blackwebwolf"
                Description = "This rule detects C&C server for mining"
        strings:
                $domain = "darkl0rd.com" nocase
                $port = "7758"
        condition:
                $domain and $port

}
