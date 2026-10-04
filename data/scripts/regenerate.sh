#!/bin/sh
set -eu
: "${DATLY_BIN:?set DATLY_BIN to the built Datly v1 executable}"
: "${DISCOVERY_DB:?set DISCOVERY_DB to an infrastructure-provisioned schema fixture}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
for spec in post:createrun get:loadrun post:publishplan patch:beginattempt patch:commitoutcome patch:checkpoint post:recordevents get:stateget patch:statepatch patch:transitionrun patch:attachoperation post:publishartifact get:listruns get:loadplan get:getartifact post:scenariopublish get:scenariolist get:recoveryload patch:repairadmit get:listevents get:listcheckpoints get:leaseeffects get:leasecleanupevidence get:listrecordingevents post:consentcreate get:consentrequests patch:consentdecide get:consentgrants get:consenttrusted get:applicationpolicyread patch:applicationpolicywrite patch:consentconsume patch:consentrevoke get:chromeretirementget patch:chromeretirementwrite post:chromeattemptbindingcreate get:chromeattemptbindingget get:chromeattemptbindinglist; do
 operation=${spec%%:*}
 package=${spec#*:}
 "$DATLY_BIN" transcribe "$operation" -dir "$ROOT" -schema -connector user -driver sqlite3 -dsn "$DISCOVERY_DB" "github.com/viant/mechanize/data/source/$package"
done
