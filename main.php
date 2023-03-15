<?php
/*
 * @copyright   Copyright (C) 2023 TeemIp
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

// Initialize collection plan
require_once(APPROOT.'collectors/src/TeemIpDiscoveryCollectionPlan.class.inc.php');
require_once(APPROOT.'core/orchestrator.class.inc.php');
Orchestrator::UseCollectionPlan('TeemIpDiscoveryCollectionPlan');

