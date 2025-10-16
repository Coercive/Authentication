<?php
namespace Coercive\Security\Authentication;

use Exception;

/**
 * Class StopForumSpam
 *
 * From API Stop Forum Spam
 * https://www.stopforumspam.com
 *
 * @package Coercive\Security\Authentication
 * @link https://github.com/Coercive/Authentication
 *
 * @author Anthony Moral <contact@coercive.fr>
 * @copyright 2025 Anthony Moral
 * @license MIT
 *
 * For the full copyright and license information,
 * please view the LICENSE file that was distributed
 * with this source code.
 */
class StopForumSpam
{
	const ENDPOINT = 'http://api.stopforumspam.com/api?json&';

	const TYPE_USERNAME = 'username';
	const TYPE_EMAIL = 'email';
	const TYPE_IP = 'ip';

	/** @var callable */
	private $callbackBefore;

	/** @var callable */
	private $callbackAfter;

	/** @var callable */
	private $callbackBeforeEmail;

	/** @var callable */
	private $callbackAfterEmail;

	/** @var callable */
	private $callbackBeforeIp;

	/** @var callable */
	private $callbackAfterIp;

	/** @var callable */
	private $callbackBeforeUserName;

	/** @var callable */
	private $callbackAfterUserName;

	/**
	 * @param array $query
	 * @return array
	 * @throws Exception
	 */
	private function get(array $query): array
	{
		$json = file_get_contents(self::ENDPOINT . http_build_query($query));
		$arr = json_decode($json, true) ?: [];
		if(!boolval($arr['success'] ?? 0)) {
			throw new Exception('StopForumSpam API call failled.');
		}
		return $arr;
	}

	/**
	 * Verify if email appears in spamlist
	 *
	 * @param string $email
	 * @param bool $hash [optional]
	 * @return bool
	 * @throws Exception
	 */
	public function checkEmail(string $email, bool $hash = false): bool
	{
		if($this->callbackBefore) {
			$rcs = ($this->callbackBefore)(self::TYPE_EMAIL, $email);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		if($this->callbackBeforeEmail) {
			$rcs = ($this->callbackBeforeEmail)($email);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		if($hash) {
			$query = [
				'emailhash' => md5($email)
			];
		}
		else {
			$query = [
				'email' => $email
			];
		}
		$arr = $this->get($query);
		$status = boolval($arr[$hash ? 'emailhash' : 'email']['appears'] ?? 0);
		if($this->callbackAfterEmail) {
			$rcs = ($this->callbackAfterEmail)($status, $email);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		if($this->callbackAfter) {
			$rcs = ($this->callbackAfter)(self::TYPE_EMAIL, $status, $email);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		return $status;
	}

	/**
	 * Verify if ip appears in spamlist
	 *
	 * @param string $ip
	 * @return bool
	 * @throws Exception
	 */
	public function checkIp(string $ip): bool
	{
		if($this->callbackBefore) {
			$rcs = ($this->callbackBefore)(self::TYPE_IP, $ip);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		if($this->callbackBeforeIp) {
			$rcs = ($this->callbackBeforeIp)($ip);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		$arr = $this->get([
			'ip' => $ip
		]);
		$status = boolval($arr['ip']['appears'] ?? 0);
		if($this->callbackAfterIp) {
			$rcs = ($this->callbackAfterIp)($status, $ip);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		if($this->callbackAfter) {
			$rcs = ($this->callbackAfter)(self::TYPE_IP, $status, $ip);
			if(null !== $rcs) {
				return (bool) $rcs;
			}

		}
		return $status;
	}

	/**
	 * Verify if user name appears in spamlist
	 *
	 * @param string $name
	 * @return bool
	 * @throws Exception
	 */
	public function checkUserName(string $name): bool
	{
		if($this->callbackBefore) {
			$rcs = ($this->callbackBefore)(self::TYPE_USERNAME, $name);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		if($this->callbackBeforeUserName) {
			$rcs = ($this->callbackBeforeUserName)($name);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		$arr = $this->get([
			'username' => $name
		]);
		$status = boolval($arr['username']['appears'] ?? 0);
		if($this->callbackAfterUserName) {
			$rcs = ($this->callbackAfterUserName)($status, $name);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		if($this->callbackAfter) {
			$rcs = ($this->callbackAfter)(self::TYPE_USERNAME, $status, $name);
			if(null !== $rcs) {
				return (bool) $rcs;
			}
		}
		return $status;
	}

	/**
	 * Add general callback before all checks
	 *
	 * Receive only the status in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallbackBefore(callable $function): StopForumSpam
	{
		$this->callbackBefore = $function;
		return $this;
	}

	/**
	 * Add general callback after all checks
	 *
	 * Receive only the status in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallbackAfter(callable $function): StopForumSpam
	{
		$this->callbackAfter = $function;
		return $this;
	}

	/**
	 * Add callback before email checks
	 *
	 * Receive status and email in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallbackBeforeEmail(callable $function): StopForumSpam
	{
		$this->callbackBeforeEmail = $function;
		return $this;
	}

	/**
	 * Add callback after email checks
	 *
	 * Receive status and email in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallbackAfterEmail(callable $function): StopForumSpam
	{
		$this->callbackAfterEmail = $function;
		return $this;
	}

	/**
	 * Add callback before ip checks
	 *
	 * Receive status and ip in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallbackBeforeIp(callable $function): StopForumSpam
	{
		$this->callbackBeforeIp = $function;
		return $this;
	}

	/**
	 * Add callback after ip checks
	 *
	 * Receive status and ip in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallbackAfterIp(callable $function): StopForumSpam
	{
		$this->callbackAfterIp = $function;
		return $this;
	}

	/**
	 * Add callback before user name checks
	 *
	 * Receive status and name in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallbackBeforeUserName(callable $function): StopForumSpam
	{
		$this->callbackBeforeUserName = $function;
		return $this;
	}

	/**
	 * Add callback after user name checks
	 *
	 * Receive status and name in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallbackAfterUserName(callable $function): StopForumSpam
	{
		$this->callbackAfterUserName = $function;
		return $this;
	}
}