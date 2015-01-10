<?php

class database
{
    private $host;
    private $database;
    private $user;
    private $password;
    private $error_is_fatal;
    private $report_errors;
    private $error_path;
        
    private function settings()
    {
        // Default Credentials
        $this->host = "192.168.2.17"; 
        $this->database = "SQLMAP";
        $this->user = "root";
        $this->password  = "a59d6b8ffa4519019833533686";
        
        // Extra settings
        $this->error_is_fatal = false;
        $this->report_errors = false;
        $this->error_path = '/logs/errors/errors_database.txt';
    }
    
    /**
     * Description: Checks if the query is ready to fire.
     * 
     * @param type $mysqli
     * @param type $query
     * @return type
     */
    private function prepare_mysql($mysqli, $query)
    {
        $result = $mysqli->prepare($query);
        return $result;
    }
    
    
    /**
     * Description: Overrides the default settings to create a connection later.
     * 
     * @param type $host
     * @param type $user
     * @param type $password
     * @param type $database
     */
    public function customSettings($host, $user, $password, $database)
    {
        $this->database = $database;
        $this->password = $password;
        $this->user = $user;
        $this->host = $host;
    }

    
    /**
     * Description: Launch the query with an optional returned result.
     * 
     * @param type $query
     * @param type $return_result
     * @param type $return
     * @return boolean|null
     */
    public function query($query, $return=false, $return_result=false, $return_link = false)
    {
        $this->settings();
        $con = mysqli_connect($this->host,$this->user, $this->password, $this->database) or die('');
        
        // Checking if the mysqli query is clear to fire
        if (!$this->prepare_mysql($con, $query))
        {            
            return NULL; // Returns a null value when the preperation is failed so the requestor can handle the rest,
        }
        
        $result_array = mysqli_query($con, $query);
        
        if($return_link)
            return $con;
       
        
        if ($return_result)
        {
            if (mysqli_error($con))
            {
                // Return false when there is an error
                return false;
            }
            else
            {
                return true;
            }
        }
        
        if (mysqli_error($con))
        {
            if ($this->error_is_fatal)
            {
                // When there is an error
                die('An error has occurred, please notify the webmaster');
            }
            if ($this->report_errors)
            {
                $this->report_error();
            }
        }
        
        if($return)
        {
            return $result_array;
        }
     }
     
     
     /**
      * Description: Creates and write to that file when the report_error method failes to write to that file for whatever reason.
      * 
      * @param type $error
      */
     private function backup_writer($error)
     {
         if (is_dir($_SERVER['DOCUMENT_ROOT'].'/error_report_'.time().'txt')) // Check if path exists
         {
             $handle = fopen($_SERVER['DOCUMENT_ROOT'].'/error_report_'.time().'txt', 'a');
             fwrite($handle, "\n".$error);
             fclose($handle);
         }
         else
         {              
            $fp = fopen($_SERVER['DOCUMENT_ROOT'] . "/error_report_".time().'txt',"wb");
            fwrite($fp,$error);
            fclose($fp);   
         }
     }
     
     /**
      * Description: Writes every error to a file for moderating purposes.
      * 
      * @param type $error
      */
     private function report_error($error)
     {
         $handle = fopen(__DIR__."$this->error_path", 'a');
         fwrite($handle, "\n".$error) or die($this->backup_writer($error)); // Launch backup handler on fail
         fclose($handle);
     }
}

