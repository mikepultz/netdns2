<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

class Net_DNS2_Cache_Shm extends Net_DNS2_Cache
{
    private \Shmop|false $cache_id = false;
    private int $cache_file_tok = -1;

    /**
     * @throws Net_DNS2_Exception
     */
    public function open(string $cache_file, int $size, string $serializer): void
    {
        $this->cache_size       = $size;
        $this->cache_file       = $cache_file;
        $this->cache_serializer = $serializer;

        if ($this->cache_opened) {
            return;
        }

        if (!file_exists($cache_file)) {
            if (file_put_contents($cache_file, '') === false) {
                throw new Net_DNS2_Exception(
                    "failed to create empty SHM file: {$cache_file}",
                    Net_DNS2_Lookups::E_CACHE_SHM_FILE
                );
            }
        }

        $this->cache_file_tok = ftok($cache_file, 't');
        if ($this->cache_file_tok === -1) {
            throw new Net_DNS2_Exception(
                "failed on ftok() file: {$this->cache_file_tok}",
                Net_DNS2_Lookups::E_CACHE_SHM_FILE
            );
        }

        $this->cache_id = @shmop_open($this->cache_file_tok, 'w', 0, 0);
        if ($this->cache_id !== false) {
            $allocated = shmop_size($this->cache_id);
            if ($allocated > 0) {
                $data = trim(shmop_read($this->cache_id, 0, $allocated));
                if ($data !== '' && strlen($data) > 0) {
                    $decoded = match ($this->cache_serializer) {
                        'json'  => json_decode($data, true),
                        default => unserialize($data),
                    };

                    $this->cache_data = is_array($decoded) ? $decoded : [];
                    $this->clean();
                    $this->cache_opened = true;
                }
            }
        }
    }

    public function __destruct()
    {
        if ($this->cache_file === '') {
            return;
        }

        $fp = fopen($this->cache_file, 'r');
        if ($fp === false) {
            return;
        }

        flock($fp, LOCK_EX);

        if ($this->cache_id === false) {
            $this->cache_id = @shmop_open($this->cache_file_tok, 'w', 0, 0);
            if ($this->cache_id === false) {
                $this->cache_id = @shmop_open($this->cache_file_tok, 'c', 0, $this->cache_size);
            }
        }

        $allocated = shmop_size($this->cache_id);
        $data = trim(shmop_read($this->cache_id, 0, $allocated));

        if ($data !== '' && strlen($data) > 0) {
            $c = $this->cache_data;

            $decoded = match ($this->cache_serializer) {
                'json'  => json_decode($data, true),
                default => unserialize($data),
            };

            if (is_array($decoded)) {
                $this->cache_data = array_merge($c, $decoded);
            }
        }

        shmop_delete($this->cache_id);
        $this->clean();

        $data = $this->resize();
        if ($data !== null) {
            $this->cache_id = @shmop_open($this->cache_file_tok, 'c', 0644, $this->cache_size);
            if ($this->cache_id !== false) {
                shmop_write($this->cache_id, $data, 0);
            }
        }

        flock($fp, LOCK_UN);
        fclose($fp);
    }
}
