<?php

class Net_DNS2_Cache
{
    protected $_cache_id      = false;
    protected $_cache_file    = "";
    protected $_cache_data    = array();
    protected $_cache_size    = 10000;

    public function has($key)
    {
        return isset($this->_cache_data[$key]);
    }
    public function get($key)
    {
        if (isset($this->_cache_data[$key])) {
echo "CACHE HIT!\n";
            return $this->_cache_data[$key]['object'];
        } else {

            return false;
        }
    }
    public function put($key, $data)
    {
        $this->_cache_data[$key] = array('cache_date' => time(), 'object' => $data);
    }
    protected function clean()
    {
        if (count($this->_cache_data) > 0) {

            //
            // go through each entry and adjust their TTL, and remove entries that 
            // have expired
            //
            $now = time();
                
            foreach($this->_cache_data as $key => $data) {

                $diff = $now - $data['cache_date'];
            
                $this->_cache_data[$key]['cache_date'] = $now;

                foreach($data['object']->answer as $index => $rr) {
                    
                    if ($rr->ttl <= $diff) {

                        unset($this->_cache_data[$key]);
                        break 2;
                    } else {

                        $this->_cache_data[$key]['object']->answer[$index]->ttl -= $diff;
                    }
                }
                foreach($data['object']->authority as $index => $rr) {
                    
                    if ($rr->ttl <= $diff) {

                        unset($this->_cache_data[$key]);
                        break 2;
                    } else {

                        $this->_cache_data[$key]['object']->authority[$index]->ttl -= $diff;
                    }
                }
                foreach($data['object']->additional as $index => $rr) {
                    
                    if ($rr->ttl <= $diff) {

                        unset($this->_cache_data[$key]);
                        break 2;
                    } else {

                        $this->_cache_data[$key]['object']->additional[$index]->ttl -= $diff;
                    }
                }
            }

            //
            // how also check to see if we have too many entries, and remove the
            // oldest entries first
            //
        }
    }
};

?>
