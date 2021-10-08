<?php
namespace Coercive\Security\Authentication;

use Exception;

/**
 * Class StopForumSpam
 *
 * From API Stop Forum Spam
 * https://www.stopforumspam.com
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
class StopForumSpam
{
	const ENDPOINT = 'http://api.stopforumspam.com/api?json&';

	/** @var callable */
	private $callback;

	/** @var callable */
	private $callbackEmail;

	/** @var callable */
	private $callbackIp;

	/** @var callable */
	private $callbackUserName;

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
		if($this->callbackEmail) {
			($this->callbackEmail)($status, $email);
		}
		if($this->callback) {
			($this->callback)($status);
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
		$arr = $this->get([
			'ip' => $ip
		]);
		$status = boolval($arr['ip']['appears'] ?? 0);
		if($this->callbackIp) {
			($this->callbackIp)($status, $ip);
		}
		if($this->callback) {
			($this->callback)($status);
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
		$arr = $this->get([
			'username' => $name
		]);
		$status = boolval($arr['username']['appears'] ?? 0);
		if($this->callbackUserName) {
			($this->callbackUserName)($status, $name);
		}
		if($this->callback) {
			($this->callback)($status);
		}
		return $status;
	}

	/**
	 * Add general callback after all checks
	 *
	 * Receive only the status in parameter
	 *
	 * @param callable $function
	 * @return $this
	 */
	public function setCallback(callable $function): StopForumSpam
	{
		$this->callback = $function;
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
	public function setCallbackEmail(callable $function): StopForumSpam
	{
		$this->callbackEmail = $function;
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
	public function setCallbackIp(callable $function): StopForumSpam
	{
		$this->callbackIp = $function;
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
	public function setCallbackUserName(callable $function): StopForumSpam
	{
		$this->callbackUserName = $function;
		return $this;
	}
}