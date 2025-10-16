<?php declare(strict_types=1);

use Coercive\Security\Authentication\Authentication;
use PHPUnit\Framework\TestCase;

final class AuthenticationTest extends TestCase
{
	/** @var Authentication */
	private Authentication $auth;

	protected function setUp(): void
	{
		// default constructor: cost 15, BCRYPT (as you specified)
		$this->auth = new Authentication;
	}

	public function testHashVerifyNeedsRehashAndDebounce(): void
	{
		$password = 'S3cureP@ssw0rd!';

		// hash returns a non-empty string and not equal to the plain password
		$hash = $this->auth->hash($password);
		$this->assertIsString($hash);
		$this->assertNotSame($password, $hash);

		// verify succeeds with correct password
		$this->assertTrue($this->auth->verify($password, $hash));

		// verify fails with wrong password
		$this->assertFalse($this->auth->verify('wrong-password', $hash));

		// corrupt/malformed hash should not verify
		$this->assertFalse($this->auth->verify($password, substr($hash, 0, 10)));

		// needsRehash: with same cost (default) should be false
		$this->assertFalse($this->auth->needsRehash($hash));

		// needsRehash: create a new Authentication with a different cost -> should return true
		$authHigherCost = new Authentication(16, null); // cost increased from default 15 -> 16
		$this->assertTrue($authHigherCost->needsRehash($hash));

		// needsRehash: if we re-hash with the new instance, new hash should not need rehash by that instance
		$newHash = $authHigherCost->hash($password);
		$this->assertFalse($authHigherCost->needsRehash($newHash));

		// debounce returns the same Authentication instance (fluid API)
		$returned = $this->auth->debounce(100, 200);
		$this->assertInstanceOf(Authentication::class, $returned);
		$this->assertSame($this->auth, $returned);

		// debounce should not change the correctness of verify (correct still true)
		$this->assertTrue($this->auth->verify($password, $hash));

		// and incorrect password still false after debounce call
		$this->assertFalse($this->auth->verify('still-wrong', $hash));
	}
}