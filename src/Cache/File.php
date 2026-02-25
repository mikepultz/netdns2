<?php declare(strict_types=1);

namespace Net\DNS2\Cache;

use Net\DNS2\DNS2;
use Net\DNS2\Exception;

class File extends Cache
{
    /**
     * @throws Exception
     */
    public function open(string $cache_file, int $size, string $serializer): void
    {
        $this->cache_size       = $size;
        $this->cache_file       = $cache_file;
        $this->cache_serializer = $serializer;

        if ($this->cache_opened || !file_exists($this->cache_file)) {
            return;
        }

        $file_size = filesize($this->cache_file);
        if ($file_size === false || $file_size <= 0) {
            return;
        }

        $fp = @fopen($this->cache_file, 'r');
        if ($fp === false) {
            return;
        }

        flock($fp, LOCK_EX);

        $data    = fread($fp, $file_size);
        $decoded = match ($this->cache_serializer) {
            'json'  => json_decode($data, true),
            default => unserialize($data),
        };

        $this->cache_data = is_array($decoded) ? $decoded : [];

        flock($fp, LOCK_UN);
        fclose($fp);

        $this->clean();
        $this->cache_opened = true;
    }

    public function __destruct()
    {
        if ($this->cache_file === '') {
            return;
        }

        $fp = fopen($this->cache_file, 'a+');
        if ($fp === false) {
            return;
        }

        flock($fp, LOCK_EX);
        fseek($fp, 0, SEEK_SET);

        $file_size = @filesize($this->cache_file);

        if ($file_size !== false && $file_size > 0) {
            $data = @fread($fp, $file_size);

            if ($data !== false && strlen($data) > 0) {
                $c = $this->cache_data;

                $decoded = match ($this->cache_serializer) {
                    'json'  => json_decode($data, true),
                    default => unserialize($data),
                };

                if (is_array($decoded)) {
                    $this->cache_data = array_merge($c, $decoded);
                }
            }
        }

        ftruncate($fp, 0);
        $this->clean();

        $data = $this->resize();
        if ($data !== null) {
            fwrite($fp, $data);
        }

        flock($fp, LOCK_UN);
        fclose($fp);
    }
}
