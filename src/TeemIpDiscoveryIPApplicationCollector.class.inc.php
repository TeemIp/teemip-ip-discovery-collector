<?php
/*
 * @copyright   Copyright (C) 2010-2024 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

class TeemIpDiscoveryIPApplicationCollector extends Collector
{
	const MAX_IP_APPS = 1;
	protected int $iIndex;
	protected TeemIpDiscoveryCollectionPlan $oCollectionPlan;

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
		if (!parent::CheckToLaunch($aOrchestratedCollectors)) {
			return false;
		}

		// Make sure that TeemIp is installed
		if (!$this->oCollectionPlan->IsTeemIpInstalled()) {
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPApplicationCollector will not be launched as TeemIp is not installed');
			return false;
		}
		// Make sure that a Discovery Application has been identified
		if ($this->oCollectionPlan->GetApplicationParam('uuid') == '') {
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPApplicationCollector will not be launched as no IP Discovery Application has been found');
			return false;
		}
		// Make sure subnets are collected first (i.e. already orchestrated)
		if (!array_key_exists('TeemIpDiscoveryIPv4SubnetCollector', $aOrchestratedCollectors)) {
			Utils::Log(LOG_INFO, '> TeemIpDiscoveryIPApplicationCollector will not be launched as no TeemIpDiscoveryIPv4SubnetCollector has been orchestrated yet. Please check launch sequence!');
			return false;
		}

		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function AttributeIsOptional($sAttCode)
	{
		if ($sAttCode == 'dhcp_range_discovery_enabled') return true;
		if ($sAttCode == 'providercontracts_list') return true;
		if ($sAttCode == 'services_list') return true;
		if ($sAttCode == 'tickets_list') return true;

		return parent::AttributeIsOptional($sAttCode);
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
	 * @return array{ primary_key: int, last_discovery_date: string, duration:int }|false
	 */
	public function Fetch()
	{
		if ($this->iIndex < static::MAX_IP_APPS) {
			$this->iIndex++;
			return [
				'primary_key' => $this->oCollectionPlan->GetApplicationParam('id'),
				'last_discovery_date' => $this->oCollectionPlan->GetApplicationParam('last_discovery_date'),
				'duration' => $this->oCollectionPlan->GetApplicationParam('duration')
			];
		}

		return false;
	}

}
