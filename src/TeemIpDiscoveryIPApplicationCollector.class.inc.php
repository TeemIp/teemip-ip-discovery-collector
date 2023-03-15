<?php
/*
 * @copyright   Copyright (C) 2023 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TeemIpDiscoveryIPApplicationCollector extends Collector
{
	const MAX_IP_APPS = 1;

	protected $iIndex;
	protected $oCollectionPlan;

	/**
	 * @inheritdoc
	 */
	public function Init(): void
	{
		parent::Init();

		$this->iIndex = 0;

		// Get a copy of the collection plan
		$this->oCollectionPlan = TeemIpDiscoveryCollectionPlan::GetPlan();
	}

	/**
	 * @inheritdoc
	 */
	public function CheckToLaunch($aOrchestratedCollectors): bool
	{
		if (parent::CheckToLaunch($aOrchestratedCollectors)) {
			if ($this->oCollectionPlan->IsTeemIpInstalled() && ($this->oCollectionPlan->GetApplicationParam('uuid') != '')) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @inheritdoc
	 */
	public function Collect($iMaxChunkSize = 0): bool
	{
		Utils::Log(LOG_INFO, '----------------');

		return parent::Collect($iMaxChunkSize);
	}

	/**
	 * @inheritdoc
	 */
	public function Synchronize($iMaxChunkSize = 0): bool
	{
		Utils::Log(LOG_INFO, '----------------');

		return parent::Synchronize($iMaxChunkSize);
	}

	/**
	 * @inheritdoc
	 */
	public function fetch()
	{
		if ($this->iIndex < static::MAX_IP_APPS) {
			$aDatas = array();
			$aDatas['primary_key'] = $this->oCollectionPlan->GetApplicationParam('uuid');
			$aDatas['uuid'] = $this->oCollectionPlan->GetApplicationParam('uuid');
			$aDatas['last_discovery_date'] = $this->oCollectionPlan->GetApplicationParam('last_discovery_date');
			$aDatas['duration'] = $this->oCollectionPlan->GetApplicationParam('duration');
			$this->iIndex++;

			return $aDatas;
		}

		return false;
	}

}
