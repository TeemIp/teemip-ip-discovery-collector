<?php
/*
 * @copyright   Copyright (C) 2022 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

require_once(APPROOT.'collectors/TeemIpDiscoveryIPv4Collector.class.inc.php');
require_once(APPROOT.'collectors/TeemIpDiscoveryIPv4SubnetCollector.class.inc.php');
require_once(APPROOT.'collectors/TeemIpDiscoveryIPApplicationCollector.class.inc.php');

$index = 1;
Orchestrator::AddCollector($index++, 'TeemIpDiscoveryIPv4Collector');
Orchestrator::AddCollector($index++, 'TeemIpDiscoveryIPv4SubnetCollector');
Orchestrator::AddCollector($index++, 'TeemIpDiscoveryIPApplicationCollector');

