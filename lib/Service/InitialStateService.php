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
use OCP\Authentication\LoginCredentials\IStore as CredentialsStore;
use OC\Authentication\Token\IProvider as TokenProvider;
use OCP\ILogger;
use OCP\IConfig;
use OCP\IRequest;

class InitialStateService {

	public const COOKIE_NAME = 'nc_wopiPassphrase';

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
		TokenProvider $tokenProvider,
		IRequest $request
	) {
		$this->initialState = $initialState;
		$this->capabilitiesService = $capabilitiesService;
		$this->config = $config;
		$this->logger = $logger;
		$this->credentialsStore = $credentialsStore;
		$this->tokenProvider = $tokenProvider;
		$this->request = $request;
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

	public function provideDocument(Wopi $wopi, bool $authenticated = false): void {
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

		if ($authenticated) {
			$this->provideWopiCredentials($wopi);
		}
	}

	private function provideWopiCredentials(Wopi $wopi) {
		try {
			$credentials = $this->credentialsStore->getLoginCredentials();
			$passphrase = $credentials->getUID() . '@' . $wopi->getToken();
			try {
				$token = $this->tokenProvider->getToken($passphrase);
			} catch (\OC\Authentication\Exceptions\InvalidTokenException $e) {
				$token = $this->tokenProvider->generateToken(
					$passphrase,
					$wopi->getToken(), // $credentials->getUID(),
					$credentials->getUID(), // $credentials->getLoginName(),
					$credentials->getPassword(),
					'wopi_token_' . $wopi->getToken(),
				);
			}
			$token->setLastActivity($wopi->getExpiry()); // this is in the future, but for the moment prevents the cleanup
			$token->setExpiry($wopi->getExpiry()); // the WOPI expiry is static and never updated
			$this->tokenProvider->updateToken($token);
		} catch (\Throwable $t) {
			$this->logger->logException($t, [ 'message' => 'NO CREDENTIALS' ]);
		}
	}
}
