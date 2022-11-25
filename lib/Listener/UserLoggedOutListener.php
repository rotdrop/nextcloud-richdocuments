<?php

declare(strict_types=1);

/**
 * @copyright Copyright (c) 2022 Julius Härtl <jus@bitgrid.net>
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



namespace OCA\Richdocuments\Listener;

use OCP\AppFramework\IAppContainer;
use OCP\User\Events\BeforeUserLoggedOutEvent;
use OCP\AppFramework\Utility\ITimeFactory;
use OC\Authentication\Token\IProvider as TokenProvider;
use OCP\IRequest;

use OCA\Richdocuments\Service\InitialStateService;
use OCP\EventDispatcher\Event;
use OCP\Util;

class UserLoggedOutListener implements \OCP\EventDispatcher\IEventListener {

	/** @var IAppContainer */
	private $appContainer;

	public function __construct(IAppContainer $appContainer) {
		$this->appContainer = $appContainer;
	}

	public function handle(Event $event): void {
		if (!$event instanceof BeforeUserLoggedOutEvent) {
			return;
		}

		/** @var IRequest $request */
		$request = $this->appContainer->get(IRequest::class);
		$passphrase = $request->getCookie(InitialStateService::COOKIE_NAME);
		if ($passphrase === null) {
			return;
		}

		/** @var ITimeFactory $timeFactory */
		$timeFactory = $this->appContainer->get(ITimeFactory::class);

		$secureCookie = $request->getServerProtocol() === 'https';
		$webRoot = \OC::$WEBROOT;
		if ($webRoot === '') {
			$webRoot = '/';
		}
		setcookie(InitialStateService::COOKIE_NAME, '', $timeFactory->getTime() - 3600, $webRoot, '', $secureCookie, true);

		/** @var TokenProvider $tokenProvider */
		$tokenProvider = $this->appContainer->get(TokenProvider::class);
		try {
			$token = $tokenProvider->getToken($passphrase);
			$tokenProvider->invalidateToken($token);
		} catch (\Throwable $t) {
			\OCP\Util::writeLog('richdocuments', 'NO TOKEN FOR COOKIE ' . $passphrase, \OCP\Util::INFO);
			// ignore
		}
	}
}
