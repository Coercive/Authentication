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
	 * Last allowed entries quantity
	 * @var int
	 */
	private int $lastNb = 0;

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
	 * Set global IP
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
	 * Get global IP
	 *
	 * @return $this
	 */
	public function getIp(): string
	{
		return (string) $this->ip;
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
	 * Add IP entry with timestamp
	 *
	 * @param string $ip [optional]
	 * @return $this
	 * @throws Exception
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
	 * Count IP entries in period
	 *
	 * @param string $ip [optional]
	 * @return int|null
	 * @throws Exception
	 */
	public function get(string $ip = null): ?int
	{
		$this->lastNb = 0;

		if(!$ip) {
			$ip = $this->ip;
		}
		if(!$ip) {
			throw new Exception('Empty given IP and empty global IP.');
		}
		if(!$this->isEnabled()) {
			return 0;
		}

		$filename = sha1($ip);
		$path = $this->path . DIRECTORY_SEPARATOR . $filename;
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

		$datas = '';
		$entries = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		foreach($entries as $entry) {
			$time = intval($entry);
			if ($now - $time < $this->period) {
				$datas .= $time . PHP_EOL;
				$this->lastNb++;
			}
		}
		if($datas) {
			$tmp = tempnam(sys_get_temp_dir(), 'ratelimit_' . $filename);
			file_put_contents($tmp, $datas, LOCK_EX);
			rename($tmp, $path);
		}
		return $this->lastNb;
	}

	/**
	 * @param string $ip [optional]
	 * @param bool $strict [optional]
	 * @return bool
	 * @throws Exception
	 */
	public function isAllowed(string $ip = null, bool $strict = false): bool
	{
		$result = $this->get($ip);
		$allowed = ($strict ? null !== $result : true) && $this->requests >= $result;
		if(!$allowed && $this->debounce) {
			self::sleep($this->debounce);
		}
		return $allowed;
	}

	/**
	 * @return int
	 */
	public function lastNb(): int
	{
		return $this->lastNb;
	}

	/**
	 * Clear all files or expired files
	 *
	 * @param bool $expire [optional]
	 * @return $this
	 */
	public function clear(bool $expire = true): RateLimit
	{
		if(!$this->isEnabled()) {
			return $this;
		}
		$now = time();
		$files = glob($this->path . DIRECTORY_SEPARATOR . '{,.}*', GLOB_BRACE);
		foreach($files as $file) {
			if(is_file($file)) {
				if(!$expire) {
					unlink($file);
				}
				else {
					$filemtime = filemtime($file);
					if(false === $filemtime || $now - $filemtime > $this->period) {
						unlink($file);
					}
				}
			}
		}
		return $this;
	}
}