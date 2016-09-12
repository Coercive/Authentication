<?php
namespace Coercive\Security\Authentification;

/**
 * Authentification
 * PHP Version 	7
 *
 * @version		1
 * @package 	Coercive\Security\Authentification
 * @link		https://github.com/Coercive/Authentification
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2016 - 2017 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class Authentification {

	# OPTIONS NANE
	const OPTION_COST = 'cost';

	/** @var int : Default cost of hash method*/
	const DEFAULT_COST = 15;

	/** @var int : Cost of hash method*/
	private $_iCost;

	/** @var array : Options */
	private $_aOptions;

	/**
	 * Authentification constructor.
	 *
	 * @param array $aOptions [optional]
	 */
	public function __construct($aOptions = []) {

		# SET OPTIONS
		$this->_aOptions = array_replace_recursive([
			self::OPTION_COST  =>  self::DEFAULT_COST
		], $aOptions);

		# USE OPTIONS
		$this->_iCost = $this->_aOptions[self::OPTION_COST];
	}

	/**
	 * HASH
	 *
	 * @param string $sPassword
	 * @return string
	 */
	public function hash($sPassword) {
		return (string) password_hash($sPassword, PASSWORD_BCRYPT, ['cost' => $this->_iCost]);
	}

	/**
	 * VERIFY
	 *
	 * @param string $sPassword
	 * @param string $sHash
	 * @return bool
	 */
	public function verify($sPassword, $sHash) {
		return password_verify($sPassword, $sHash);
	}

	/**
	 * NEEDS REHASH
	 *
	 * @param string $sHash
	 * @return bool
	 */
	public function needsRehash($sHash) {
		return password_needs_rehash($sHash, PASSWORD_BCRYPT, ['cost' => $this->_iCost]);
	}

}