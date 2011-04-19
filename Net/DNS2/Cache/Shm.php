<?php

class Net_DNS2_Cache_Shm extends Net_DNS2_Cache
{
    public function __construct($cache_file, $size)
    {
        //
        // make sure the file exists first
        //
        if (!file_exists($cache_file)) {
            touch($cache_file);
        }

        //
        // convert the filename to a IPC key
        //
        $this->_cache_file = ftok($cache_file, 't');
echo "using: " . $this->_cache_file . "\n";
        //
        // open the shared memory segment
        //
        $this->_cache_id = shmop_open($this->_cache_file, 'c', 0644, $size);
        if ($this->_cache_id !== false) {

            //
            // this returns the size allocated, and not the size used, but it's
            // still a good check to make sure there's space allocated.
            //
            $size = shmop_size($this->_cache_id);
            if ($size > 0) {
            
                //
                // read the data from teh shared memory segment
                //
                $data = @shmop_read($this->_cache_id, 0, $size);
                if ( ($data !== false) && (strlen($data) > 0) ) {

                    //
                    // unserialize and store the data
                    //
                    $this->_cache_data = unserialize($data);

                    //
                    // call clean to clean up old entries
                    //
                    $this->clean();
                }
            }
        } else {

            // throw an exception
        }
    }
    public function __destruct()
    {
        if (count($this->_cache_data) > 0) {
            
            shmop_write($this->_cache_id, serialize($this->_cache_data), 0);
        }

        shmop_close($this->_cache_id);
    }
};

?>
