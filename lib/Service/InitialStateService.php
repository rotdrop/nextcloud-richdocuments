<?php
/*
 * @copyright Copyright (c) 2021 Julius Härtl <jus@bitgrid.net>
 *
 * @author Julius Härtl <jus@bitgrid.net>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

declare(strict_types=1);

namespace OCA\Richdocuments\Service;

use OCA\Richdocuments\AppInfo\Application;
use OCA\Richdocuments\Db\Wopi;
use OCP\AppFramework\Services\IInitialState;
use OCP\Security\ICrypto;
use OCP\Security\ISecureRandom;
use OCP\Authentication\LoginCredentials\IStore as CredentialsStore;
use OC\Authentication\Token\IProvider as TokenProvider;
use OCP\ILogger;
use OCP\IConfig;
use OCP\IRequest;

class InitialStateService {

	public const COOKIE_NAME = 'nc_wopiPassphrase';
	public const WOPI_DATA_TOKEN_KEY = 'tokenPassphrase';

	/** @var IInitialState */
	private $initialState;

	/** @var CapabilitiesService */
	private $capabilitiesService;

	/** @var IConfig */
	private $config;

	/** @var ILogger */
	private $logger;

	/** @var CredentialsStore */
	private $credentialsStore;

	/** @var ICrypto */
	private $crypto;

	/** @var ISecureRandom */
	protected $random;

	/** @var TokenProvider */
	private $tokenProvider;

	/** @var IRequest */
	private $request;

	/** @var bool */
	private $hasProvidedCapabilities = false;

	public function __construct(
		IInitialState $initialState,
		CapabilitiesService $capabilitiesService,
		IConfig $config,
		ILogger $logger,
		CredentialsStore $credentialsStore,
		ICrypto $crypto,
		ISecureRandom $random,
		TokenProvider $tokenProvider,
		IRequest $request
	) {
		$this->initialState = $initialState;
		$this->capabilitiesService = $capabilitiesService;
		$this->config = $config;
		$this->logger = $logger;
		$this->credentialsStore = $credentialsStore;
		$this->crypto = $crypto;
		$this->tokenProvider = $tokenProvider;
		$this->request = $request;
		$this->random = $random;
	}

	public function provideCapabilities(): void {
		if ($this->hasProvidedCapabilities) {
			return;
		}

		$this->initialState->provideInitialState('productName', $this->capabilitiesService->getProductName());
		$this->initialState->provideInitialState('hasDrawSupport', $this->capabilitiesService->hasDrawSupport());
		$this->initialState->provideInitialState('hasNextcloudBranding', $this->capabilitiesService->hasNextcloudBranding());

		$this->hasProvidedCapabilities = true;
	}

	public function provideDocument(Wopi $wopi): void {
		$this->provideCapabilities();

		$this->initialState->provideInitialState('wopi', $wopi);
		$this->initialState->provideInitialState('theme', $this->config->getAppValue(Application::APPNAME, 'theme', 'nextcloud'));
		$this->initialState->provideInitialState('uiDefaults', [
			'UIMode' => $this->config->getAppValue(Application::APPNAME, 'uiDefaults-UIMode', 'classic')
		]);
		$logoSet = $this->config->getAppValue('theming', 'logoheaderMime', '') !== '';
		if (!$logoSet) {
			$logoSet = $this->config->getAppValue('theming', 'logoMime', '') !== '';
		}
		$this->initialState->provideInitialState('theming-customLogo', ($logoSet ?
			\OC::$server->getURLGenerator()->getAbsoluteURL(\OC::$server->getThemingDefaults()->getLogo())
			: false));

		$wopiData = $this->getWopiData($wopi);

		// the "extra state" will be passed to the WopiController as URL
		// parameter. It is encrypted with the Nextcloud server secret which
		// means that even an external Collabora server will not see the
		// cookie in clear-text and thus should not make things worse as they
		// are.
		$wopiData = self::encryptWopiData($this->crypto, $wopiData);

		// $this->logger->info('INITIAL STATE WOPI DATA ' . $wopiData);
		$this->initialState->provideInitialState('wopiData', $wopiData);
	}

	private static function encryptWopiData(ICrypto $crypto, array $wopiData) {
		$wopiData = $crypto->encrypt(json_encode($wopiData));
		$parts = explode('|', $wopiData);
		$version = array_pop($parts);
		$parts =  array_map(fn(string $part) => strtr(base64_encode(hex2bin($part)), '+/=', '-_.'), $parts);
		$parts[] = $version;
		return implode('|', $parts);
	}

	public static function decryptWopiData(ICrypto $crypto, string $encryptedData) {
		try {
			$parts = $parts = explode('|', $encryptedData);
			$version = array_pop($parts);
			$parts =  array_map(fn(string $part) => bin2hex(base64_decode(strtr($part, '-_.', '+/='))), $parts);
			$parts[] = $version;
			$wopiData = implode('|', $parts);
			$decrypted = json_decode($crypto->decrypt($wopiData), true);
			return $decrypted;
		} catch (\Throwable $t) {
			// ignore
			throw $t;
			return null;
		}
	}

	private function getWopiData(Wopi $wopi) {
		$wopiData = [];
		try {
			$credentials = $this->credentialsStore->getLoginCredentials();
			$passphrase = $this->getWopiCookie($wopi);
			try {
				$token = $this->tokenProvider->getToken($passphrase);
			} catch (\OC\Authentication\Exceptions\InvalidTokenException $e) {
				$token = $this->tokenProvider->generateToken(
					$passphrase,
					$credentials->getUID(),
					$credentials->getLoginName(),
					$credentials->getPassword(),
					'wopi_token_' . $wopi->getToken(),
				);
			}
			$token->setLastActivity($wopi->getExpiry()); // this is in the future, but for the moment prevents the cleanup
			$this->tokenProvider->updateToken($token);

			// $this->logger->info('GET TOKEN EXPIRY ' . $token->getLastActivity());

			// works
			// $this->logger->info('TOKEN ' . $token->getToken());

			$wopiData = [
				self::WOPI_DATA_TOKEN_KEY => $passphrase, // this is just the cookie
			];

			// $this->logger->info('GOT TOKEN FOR WOPI ' . $wopi->getToken());
		} catch (\Throwable $t) {
			$this->logger->logException($t, [ 'message' => 'NO CREDENTIALS' ]);
			$wopiData = [];
		}
		return  $wopiData;
	}

	private function getWopiCookie(Wopi $wopi) {
		$passphrase = $this->request->getCookie(self::COOKIE_NAME);
		if ($passphrase === null) {
			$passphrase = $this->random->generate(128);
			$secureCookie = $this->request->getServerProtocol() === 'https';
			$webRoot = \OC::$WEBROOT;
			if ($webRoot === '') {
				$webRoot = '/';
			}
			setcookie(
				self::COOKIE_NAME,
				$passphrase,
				[
					'expires' => $wopi->getExpiry(),
					'path' => $webRoot,
					'domain' => '',
					'secure' => $secureCookie,
					'httponly' => true,
					'samesite' => 'Lax',
				]
			);
		}
		return $passphrase;
	}
}
