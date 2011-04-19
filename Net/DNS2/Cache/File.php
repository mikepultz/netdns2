<?php

class Net_DNS2_Cache_File extends Net_DNS2_Cache
{
    public function __construct($cache_file)
    {
        $this->_cache_file = $cache_file;
        if (file_exists($this->_cache_file) == true) {

            //
            // open the file for reading
            //
            $fp = fopen($this->_cache_file, "r");
            if ($fp !== false) {
                
                //
                // lock the file just in case
                //
                flock($fp, LOCK_EX);

                //
                // read the file contents
                //
                $this->_cache_data = unserialize(fread($fp, filesize($this->_cache_file)));

                //
                // unlock
                //
                flock($fp, LOCK_UN);

                //
                // close the file
                //
                fclose($fp);

            } else {
                // throw an exception
            }

            $this->clean();
        }
    }
    public function __destruct()
    {
        if (count($this->_cache_data) > 0) {

            //
            // open the file for writing
            //
            $fp = fopen($this->_cache_file, "w");
            if ($fp !== false) {
                
                //
                // lock the file just in case
                //
                flock($fp, LOCK_EX);

                //
                // write the file contents
                //
                fwrite($fp, serialize($this->_cache_data));

                //
                // unlock
                //
                flock($fp, LOCK_UN);

                //
                // close the file
                //
                fclose($fp);

            } else {
                // throw an exception
            }
        }
    }
};

?>
