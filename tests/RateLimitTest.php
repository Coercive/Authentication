<?php declare(strict_types=1);

use Coercive\Security\Authentication\RateLimit;
use PHPUnit\Framework\TestCase;

final class RateLimitTest extends TestCase
{
	private string $tmpDir;
	private RateLimit $rateLimit;

	protected function setUp(): void
	{
		// Répertoire temporaire unique pour ces tests
		$this->tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . bin2hex(uniqid('ratelimit_test_'));
		if (!mkdir($this->tmpDir, 0777, true) && !is_dir($this->tmpDir)) {
			throw new RuntimeException('Cannot create tmp dir ' . $this->tmpDir);
		}

		// Petite limite pour tests rapides : 3 requêtes par période
		$this->rateLimit = new RateLimit($this->tmpDir, 3, 60);
	}

	protected function tearDown(): void
	{
		if (!is_dir($this->tmpDir)) {
			return;
		}
		$items = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->tmpDir, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($items as $item) {
			if ($item->isDir()) {
				@rmdir($item->getPathname());
			}
			else {
				@unlink($item->getPathname());
			}
		}
		@rmdir($this->tmpDir);
	}

	public function testRateLimitBasicFlow(): void
	{
		$ip = '127.0.0.1';

		// setIp fluide
		$this->assertInstanceOf(RateLimit::class, $this->rateLimit->setIp($ip));

		// Aucun enregistrement au départ -> get retourne 0 ou null (selon implémentation)
		// On accepte soit 0 soit null, on convertit en int pour l'assertion : ici on autorise 0
		$count = $this->rateLimit->get();
		$this->assertTrue($count === null || $count === 0);

		// Appel set() plusieurs fois -> incrémente le compteur
		$this->rateLimit->set(); // 1
		$this->assertSame(1, $this->rateLimit->get());

		$this->rateLimit->set(); // 2
		$this->assertSame(2, $this->rateLimit->get());

		$this->rateLimit->set(); // 3 (égale à la limite)
		$this->assertSame(3, $this->rateLimit->get());

		// isAllowed sans dépasser -> true (limite 3)
		$this->assertTrue($this->rateLimit->isAllowed());

		// Une insertion supplémentaire -> dépasse la limite
		$this->rateLimit->set(); // 4
		$this->assertSame(4, $this->rateLimit->get());

		// isAllowed doit maintenant renvoyer false
		$this->assertFalse($this->rateLimit->isAllowed());

		// isAllowed en passant explicitement l'IP (API alternative)
		$this->assertFalse($this->rateLimit->isAllowed($ip));

		// Tester set/get en passant l'IP directement (sans setIp)
		$otherIp = '10.0.0.1';
		$this->rateLimit->set($otherIp);
		$this->assertSame(1, $this->rateLimit->get($otherIp));
		$this->assertTrue($this->rateLimit->isAllowed($otherIp));

		// Flood
		$ip = '1.2.3.4';
		$this->rateLimit->setIp($ip);
		foreach (range(1, 100) as $i) {
			$this->rateLimit->set();
		}
		$this->assertFalse($this->rateLimit->isAllowed());
	}
}