<?php
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\Richdocuments\Backgroundjobs;

use OCA\Richdocuments\Db\WopiMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OC\Authentication\Token\IProvider as TokenProvider;

class Cleanup extends TimedJob {
	/** @var IDBConnection */
	private $db;
	/** @var WopiMapper $wopiMapper */
	private $wopiMapper;
	/** @var TokenProvider */
	private $tokenProvider;

	public function __construct(ITimeFactory $time, IDBConnection $db, WopiMapper $wopiMapper, TokenProvider $tokenProvider) {
		parent::__construct($time);
		$this->db = $db;
		$this->wopiMapper = $wopiMapper;
		$this->tokenProvider = $tokenProvider;

		$this->setInterval(60 * 10);
	}

	protected function run($argument) {
		\OC::$server->get(\OCP\ILogger::class)->info(__METHOD__);
		// Expire template mappings for file creation
		$query = $this->db->getQueryBuilder();
		$query->delete('richdocuments_template')
			->where($query->expr()->lte('timestamp', $query->createNamedParameter(time() - 60, IQueryBuilder::PARAM_INT)));
		$query->executeStatement();

		// Expired WOPI access tokens
		$this->cleanUpWopiTokens();
	}

	private function cleanUpWopiTokens() {
		$tokens = $this->wopiMapper->getExpiredTokens(1000);
		$query = $this->db->getQueryBuilder();
		$query->delete('richdocuments_wopi')
			->where($query->expr()->in('token', $query->createNamedParameter($tokens, IQueryBuilder::PARAM_INT_ARRAY)));
		$query->executeStatement();
		\OC::$server->get(\OCP\ILogger::class)->info(__METHOD__ . ': #EXPIRED: ' . count($tokens));
		foreach ($tokens as $wopiToken) {
			$authTokens = $this->tokenProvider->getTokenByUser($wopiToken);
			foreach ($authTokens as $authToken) {
				\OC::$server->get(\OCP\ILogger::class)->info('DELETING AUTH TOKEN FOR ' . $wopiToken . ' ' . $authToken->getId());
				$this->tokenProvider->invalidateTokenById($wopiToken, $authToken->getId());
			}
		}
	}
}
