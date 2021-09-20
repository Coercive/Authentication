<?php
namespace Coercive\Security\Authentication;

/**
 * Authentication
 *
 * @package 	Coercive\Security\Authentication
 * @link		https://github.com/Coercive/Authentication
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2020 Anthony Moral
 * @license 	MIT
 */
class Authentication
{
	/** @var int : Default cost of hash method */
	const DEFAULT_COST = 15;

	/** @var int : Default hash algo method */
	const DEFAULT_ALGO = PASSWORD_BCRYPT;

	/** @var int : Cost of hash method */
	private int $cost = self::DEFAULT_COST;

	/** @var mixed : Algo of hash method */
	private $algo = self::DEFAULT_ALGO;

	/** @var int : Debounce delay for miswriting password */
	private int $debounce = 0;

	/**
	 * Authentication constructor.
	 *
	 * @param int $cost [optional]
	 * @param mixed $algo [optional]
	 */
	public function __construct(? int $cost = null, $algo = null)
	{
		if(null !== $cost) {
			$this->cost = $cost;
		}
		if(null !== $algo) {
			$this->algo = $algo;
		}
	}

	/**
	 * DEBOUNCE
	 *
	 * Random sleep delay for miswriting password
	 *
	 * @param int $min [optional] In milliseconds
	 * @param int $max [optional] In milliseconds
	 * @return Authentication
	 */
	public function debounce(int $min = 1000, int $max = 2000): Authentication
	{
		$this->debounce = rand($min, $max) * 1000;
		return $this;
	}

	/**
	 * HASH
	 *
	 * @param string $password
	 * @return string
	 */
	public function hash(string $password): string
	{
		return (string) password_hash($password, $this->algo, ['cost' => $this->cost]);
	}

	/**
	 * VERIFY
	 *
	 * @param string $password
	 * @param string $hash
	 * @return bool
	 */
	public function verify(string $password, string $hash): bool
	{
		$state = password_verify($password, $hash);
		if(!$state && $this->debounce) {
			RateLimit::sleep($this->debounce);
		}
		return $state;
	}

	/**
	 * NEEDS REHASH
	 *
	 * @param string $hash
	 * @return bool
	 */
	public function needsRehash(string $hash): bool
	{
		return password_needs_rehash($hash, $this->algo, ['cost' => $this->cost]);
	}
}
