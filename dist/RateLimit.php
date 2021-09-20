<?php
namespace Coercive\Security\Authentication;

use Exception;

/**
 * Class RateLimit
 *
 * @package 	Coercive\Security\Authentication
 * @link		https://github.com/Coercive/Authentication
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2021 Anthony Moral
 * @license 	MIT
 *
 * For the full copyright and license information,
 * please view the LICENSE file that was distributed
 * with this source code.
 */
class RateLimit
{
	const MICRO2SECONDS = 1000000;

	/**
	 * System activation
	 * @var bool $state
	 */
	private bool $state = true;

	/**
	 * System directory
	 * @var string $path
	 */
	private string $path;

	/**
	 * Allowed max requests
	 * @var int $requests
	 */
	private int $requests;

	/**
	 * Allowed requests period (in seconds)
	 * @var int $period
	 */
	private int $period;

	/**
	 * Debounce delay for not allowed (in microseconds)
	 * @var int $debounce
	 */
	private ? int $debounce = null;

	/**
	 * Global IP
	 * @var string|null
	 */
	private ? string $ip = null;

	/**
	 * @param int $delay
	 * @return void
	 */
	static public function sleep(int $delay)
	{
		if($delay > static::MICRO2SECONDS) {
			$seconds = (int) floor($delay / static::MICRO2SECONDS);
			$microseconds = $delay - static::MICRO2SECONDS * $seconds;
		}
		else {
			$seconds = 0;
			$microseconds = $delay;
		}
		if($seconds) {
			sleep($seconds);
		}
		if($microseconds) {
			usleep($microseconds);
		}
	}

	/**
	 * @param string $path
	 * @return RateLimit
	 * @throws Exception
	 */
	private function setPath(string $path): RateLimit
	{
		$this->path = realpath($path);
		if (!$this->path || !is_dir($this->path)) {
			if (!@mkdir($path, 0777, true)) {
				throw new Exception("Can't create directory : $path");
			}
			$this->path = realpath($path);
		}
		return $this;
	}

	/**
	 * RateLimit constructor.
	 *
	 * @param string $path
	 * @param int $requests [optional] quantity
	 * @param int $period [optional] seconds
	 * @return void
	 * @throws Exception
	 */
	public function __construct(string $path, int $requests = 60, int $period = 60)
	{
		$this->setPath($path);
		$this->requests = $requests;
		$this->period = $period;
	}

	/**
	 * Verify if system is active
	 *
	 * @return bool
	 */
	public function isEnabled(): bool
	{
		return $this->state;
	}

	/**
	 * Enable system
	 *
	 * @return $this
	 */
	public function enable(): RateLimit
	{
		$this->state = true;
		return $this;
	}

	/**
	 * Disable system
	 *
	 * @return $this
	 */
	public function disable(): RateLimit
	{
		$this->state = false;
		return $this;
	}

	/**
	 * Enable/Disable system
	 *
	 * @param bool $state
	 * @return $this
	 */
	public function setState(bool $state): RateLimit
	{
		$this->state = $state;
		return $this;
	}

	/**
	 * Set global IPP
	 *
	 * @param string $ip
	 * @return $this
	 */
	public function setIp(string $ip): RateLimit
	{
		$this->ip = $ip;
		return $this;
	}

	/**
	 * Sleep delay for not allowed
	 *
	 * @param int $delay [optional] In microseconds
	 * @return $this
	 */
	public function debounce(? int $delay = null): RateLimit
	{
		$this->debounce = $delay;
		return $this;
	}

	/**
	 * @param string $ip [optional]
	 * @return $this
	 */
	public function set(string $ip = null): RateLimit
	{
		if(!$ip) {
			$ip = $this->ip;
		}
		if(!$ip) {
			throw new Exception('Empty given IP and empty global IP.');
		}
		if($this->isEnabled()) {
			$path = $this->path . DIRECTORY_SEPARATOR . sha1($ip);
			file_put_contents($path, time().PHP_EOL , FILE_APPEND | LOCK_EX);
		}
		return $this;
	}

	/**
	 * @param string $ip [optional]
	 * @return int|null
	 * @throws Exception
	 */
	public function get(string $ip = null): ?int
	{
		if(!$ip) {
			$ip = $this->ip;
		}
		if(!$ip) {
			throw new Exception('Empty given IP and empty global IP.');
		}
		if(!$this->isEnabled()) {
			return 0;
		}

		$path = $this->path . DIRECTORY_SEPARATOR . sha1($ip);
		$tmp = $this->path . DIRECTORY_SEPARATOR . sha1($ip) . '.tmp';
		if(!is_file($path)) {
			return 0;
		}
		$now = time();
		$filemtime = filemtime($path);
		if(false === $filemtime) {
			return null;
		}
		elseif($now - $filemtime > $this->period) {
			unlink($path);
			return 0;
		}

		$nb = 0; $fail = false;
		$file = fopen($path, 'r');
		$new = fopen($tmp, 'w');
		if ($file && $new) {
			do {
				$locked = flock($file, LOCK_EX);
				if(!$locked) {
					usleep(10);
				}
			}
			while(!$locked);
			do {
				$locked = flock($new, LOCK_EX);
				if(!$locked) {
					usleep(10);
				}
			}
			while(!$locked);
			while (false !== ($buffer = fgets($file))) {
				$time = intval($buffer);
				if ($now - $time < $this->period) {
					fwrite($new, $time . PHP_EOL);
					$nb++;
				}
			}
			if (!feof($file)) {
				$fail = true;
			}
			fflush($new);
			flock($new, LOCK_UN);
			flock($file, LOCK_UN);
		}
		else {
			$fail = true;
		}
		fclose($file);
		fclose($new);
		if($fail) {
			return null;
		}
		return $nb;
	}

	/**
	 * @param string $ip [optional]
	 * @param bool $strict [optional]
	 * @return bool
	 */
	public function isAllowed(string $ip = null, bool $strict = false): bool
	{
		$result = $this->get($ip);
		$allowed = ($strict ? null !== $result : true) && $this->requests >= $result;
		if(!$allowed && $this->debounce) {
			$this->sleep();
		}
		return $allowed;
	}

	/**
	 * Clear all files
	 *
	 * @return $this
	 */
	public function clear(): RateLimit
	{
		if($this->isEnabled()) {
			$files = glob($this->path . '/{,.}*', GLOB_BRACE);
			foreach($files as $file) {
				if(is_file($file)) {
					unlink($file);
				}
			}
		}
		return $this;
	}

	/**
	 * Drop all expired files
	 *
	 * @return $this
	 */
	public function expire(): RateLimit
	{
		if($this->isEnabled()) {
			$now = time();
			$files = glob($this->path . DIRECTORY_SEPARATOR . '{,.}*', GLOB_BRACE);
			foreach($files as $file) {
				$filemtime = filemtime($file);
				if(is_file($file) && (false === $filemtime || $now - $filemtime > $this->period)) {
					unlink($file);
				}
			}
		}
		return $this;
	}
}