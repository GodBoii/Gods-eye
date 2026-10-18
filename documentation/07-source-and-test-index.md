# Source and test index

Prepared 18 October 2026 against commit `4d27de83ad087703b197432ccbf2870a5ea6164c`. This index records source structure, not executed test results. It excludes generated Go code from the handwritten production count.

The inventory contains 53 handwritten production Go files with 10,431 lines, 40 Go test files, and 156 named test functions. Table-driven cases and fuzz entry points add behavior beyond that count.

## Handwritten production files

| Source | Lines | Top-level functions |
| --- | ---: | --- |
| [cmd/godseye/lab.go](../cmd/godseye/lab.go) | 169 | `lab` |
| [cmd/godseye/main.go](../cmd/godseye/main.go) | 104 | `main`, `run` |
| [cmd/godseye/serve.go](../cmd/godseye/serve.go) | 66 | `serve` |
| [internal/dashboard/server.go](../internal/dashboard/server.go) | 416 | `New`, `Handler`, `send`, `fail`, `decode`, `state`, `runDetail`, `addAsset`, `removeAsset`, `startRun`, `sourceTarget`, `execute`, `cancelRun`, `download` |
| [internal/dashboard/store.go](../internal/dashboard/store.go) | 100 | `validateAsset`, `loadAssets`, `saveAssets` |
| [internal/dashboard/tool_assessment.go](../internal/dashboard/tool_assessment.go) | 42 | `registerToolAssessments` |
| [internal/dashboard/workbench.go](../internal/dashboard/workbench.go) | 128 | `registerWorkbench`, `readEvidence`, `saveEvidence` |
| [internal/report/report.go](../internal/report/report.go) | 76 | `JSON`, `SARIF` |
| [internal/secrets/rules.go](../internal/secrets/rules.go) | 33 | `rules`, `find` |
| [internal/secrets/scan.go](../internal/secrets/scan.go) | 283 | `DefaultLimits`, `Scan`, `scanFile`, `rulesDigest`, `newID`, `unique` |
| [internal/webcheck/check.go](../internal/webcheck/check.go) | 121 | `Inspect`, `publicIP`, `Evaluate` |
| [internal/workbench/capture.go](../internal/workbench/capture.go) | 157 | `InspectCapture`, `ethernetConversation` |
| [internal/workbench/catalog.go](../internal/workbench/catalog.go) | 59 | `Catalog` |
| [internal/workbench/diagnostics.go](../internal/workbench/diagnostics.go) | 222 | `validHost`, `diagnosticAddress`, `TCP`, `DNS`, `isNotFound` |
| [internal/workbench/files.go](../internal/workbench/files.go) | 99 | `InspectFile` |
| [internal/workbench/import.go](../internal/workbench/import.go) | 125 | `Formats`, `Import`, `decodeJSON` |
| [internal/workbench/import_csv.go](../internal/workbench/import_csv.go) | 151 | `columnName`, `importCSV` |
| [internal/workbench/import_json.go](../internal/workbench/import_json.go) | 329 | `importNuclei`, `importHAR`, `importShodan`, `importBBOT`, `importBloodHound`, `importTShark` |
| [internal/workbench/import_xml.go](../internal/workbench/import_xml.go) | 161 | `decodeXML`, `importNmap`, `importBurp`, `importMetasploit` |
| [internal/workbench/model.go](../internal/workbench/model.go) | 192 | `newReport`, `digest`, `text`, `Target`, `gap`, `limit`, `observe`, `finding`, `node`, `edge`, `checkInput` |
| [internal/workbench/policy.go](../internal/workbench/policy.go) | 139 | `stringList`, `IAM` |
| [internal/workbench/store.go](../internal/workbench/store.go) | 155 | `OpenStore`, `trim`, `Save`, `List`, `Get` |
| [internal/workbench/tool_aircrack.go](../internal/workbench/tool_aircrack.go) | 330 | `auditAircrack`, `auditWirelessPCAP`, `wirelessRadiotap`, `wirelessBeacon`, `wirelessSecurityElement` |
| [internal/workbench/tool_airgorah.go](../internal/workbench/tool_airgorah.go) | 250 | `auditAirgorah`, `airgorahSecurity`, `airgorahSnapshot` |
| [internal/workbench/tool_audit.go](../internal/workbench/tool_audit.go) | 124 | `ToolCapabilities`, `AuditTool` |
| [internal/workbench/tool_bbot.go](../internal/workbench/tool_bbot.go) | 285 | `auditBBOT`, `bbotExcluded`, `bbotEntity` |
| [internal/workbench/tool_bloodhound.go](../internal/workbench/tool_bloodhound.go) | 216 | `auditBloodHound`, `bloodHoundID`, `bloodHoundRight` |
| [internal/workbench/tool_burp.go](../internal/workbench/tool_burp.go) | 427 | `auditBurp`, `burpEnvelope`, `burpRoutes`, `burpURL`, `burpOrigin`, `burpMethod`, `burpPath`, `burpSpecificity`, `burpMedia` |
| [internal/workbench/tool_caido.go](../internal/workbench/tool_caido.go) | 254 | `auditCaido`, `caidoEnvelope`, `caidoEndpoint`, `caidoIndex` |
| [internal/workbench/tool_cloudfox.go](../internal/workbench/tool_cloudfox.go) | 403 | `auditCloudFox`, `cloudUnknown`, `cloudIntrinsic`, `cloudBool`, `cloudIngress`, `cloudPolicy`, `cloudRefs` |
| [internal/workbench/tool_cyberchef.go](../internal/workbench/tool_cyberchef.go) | 349 | `auditCyberChef`, `cyberChefObject`, `cyberChefJWT`, `cyberChefPEM` |
| [internal/workbench/tool_engine.go](../internal/workbench/tool_engine.go) | 67 | `Write`, `runAuditEngine` |
| [internal/workbench/tool_evilginx3.go](../internal/workbench/tool_evilginx3.go) | 275 | `auditEvilginx3`, `evilginxReview`, `evilginxDirective`, `evilginxHSTSAge`, `evilginxFrameProtection`, `evilginxAttribute`, `evilginxForms` |
| [internal/workbench/tool_foremost.go](../internal/workbench/tool_foremost.go) | 314 | `auditForemost`, `foremostPNG`, `foremostGIF`, `foremostBMP`, `foremostWAV` |
| [internal/workbench/tool_hashcat.go](../internal/workbench/tool_hashcat.go) | 151 | `auditHashcat` |
| [internal/workbench/tool_hping3.go](../internal/workbench/tool_hping3.go) | 142 | `auditHping3`, `hping3ConnectionState`, `hping3SuccessPercent` |
| [internal/workbench/tool_maltego.go](../internal/workbench/tool_maltego.go) | 224 | `auditMaltego`, `maltegoID`, `maltegoField`, `maltegoProvenance`, `maltegoPath` |
| [internal/workbench/tool_metasploit.go](../internal/workbench/tool_metasploit.go) | 207 | `auditMetasploit`, `metasploitReference` |
| [internal/workbench/tool_netcat.go](../internal/workbench/tool_netcat.go) | 200 | `auditNetcat`, `netcatExchange` |
| [internal/workbench/tool_nmap.go](../internal/workbench/tool_nmap.go) | 250 | `auditNmap`, `nmapArguments`, `nmapNative`, `nmapProbe`, `nmapTLS` |
| [internal/workbench/tool_nuclei.go](../internal/workbench/tool_nuclei.go) | 109 | `auditNuclei`, `nucleiExposureRules`, `nucleiCookieRules` |
| [internal/workbench/tool_passive_recon.go](../internal/workbench/tool_passive_recon.go) | 278 | `auditPassiveRecon`, `passiveTLSCertificate`, `passivePublicAddress`, `passiveScopedName`, `passiveCertificateTime`, `auditPassiveCertificates` |
| [internal/workbench/tool_recon_ng.go](../internal/workbench/tool_recon_ng.go) | 218 | `auditReconNG`, `reconNGSnapshot`, `reconNGDomain`, `reconNGAddresses` |
| [internal/workbench/tool_request.go](../internal/workbench/tool_request.go) | 37 | `toolInput` |
| [internal/workbench/tool_sherlock.go](../internal/workbench/tool_sherlock.go) | 127 | `auditSherlock`, `sherlockProfileURL` |
| [internal/workbench/tool_shodan.go](../internal/workbench/tool_shodan.go) | 302 | `auditShodan`, `shodanToken`, `shodanTime`, `shodanCVEs` |
| [internal/workbench/tool_skipfish.go](../internal/workbench/tool_skipfish.go) | 214 | `auditSkipfish`, `skipfishSafeURL`, `skipfishMarkup`, `skipfishAttribute`, `skipfishHeaders`, `skipfishInsecureMarkup` |
| [internal/workbench/tool_spiderdomain.go](../internal/workbench/tool_spiderdomain.go) | 327 | `auditSpiderdomain`, `enrichDomainDNS`, `auditDomainZone`, `domainZoneName`, `auditDomainMail` |
| [internal/workbench/tool_spiderfoot.go](../internal/workbench/tool_spiderfoot.go) | 312 | `auditSpiderfoot`, `readSpiderfootEvents`, `spiderfootFalsePositive`, `spiderfootModule`, `spiderfootInScope`, `spiderfootScanScope`, `spiderfootEntity`, `spiderfootSource`, `spiderfootEntityScope` |
| [internal/workbench/tool_sqlmap.go](../internal/workbench/tool_sqlmap.go) | 207 | `auditSQLMap`, `sqlErrorFamily`, `sameSQLEndpoint`, `singleSQLQueryChange` |
| [internal/workbench/tool_transport.go](../internal/workbench/tool_transport.go) | 110 | `validateAuditURL`, `fetchAuditURL` |
| [internal/workbench/tool_wireshark.go](../internal/workbench/tool_wireshark.go) | 216 | `auditWireshark`, `inspectPCAPNG`, `captureOptions` |
| [internal/world/feeds.go](../internal/world/feeds.go) | 179 | `New`, `newService`, `validBody`, `containsTLE`, `Snapshot`, `save` |

## Existing behavior tests to transfer

For each row, add Python test references and results to the implementation ledger. Preserve each meaningful table/subtest case, including expected errors and privacy checks. Tests that characterize live local services should remain integration tests against real local listeners rather than mocks of the new implementation.

| Go source | Named test functions | Other test entry points |
| --- | --- | --- |
| [cmd/godseye/lab_test.go](../cmd/godseye/lab_test.go) | `TestLabCLIReportsAndOverwriteProtection`, `TestLabAssessmentCLIUsesNativeModule` |  |
| [cmd/godseye/main_test.go](../cmd/godseye/main_test.go) | `TestCLIReportsAndExitCodes`, `TestCLIRefusesOverwrite` |  |
| [internal/dashboard/server_test.go](../internal/dashboard/server_test.go) | `TestServerInventoryAndBoundaries`, `TestScanWorkflowAndReports`, `TestSingleRunAdmissionAndCancel`, `TestSlowReportDoesNotBlockStateRequests`, `TestInventorySizeLimit` |  |
| [internal/dashboard/tool_assessment_test.go](../internal/dashboard/tool_assessment_test.go) | `TestToolAssessmentAPIExecutesAndPersists`, `TestToolAssessmentsBoundConcurrentExecution` |  |
| [internal/dashboard/workbench_test.go](../internal/dashboard/workbench_test.go) | `TestWorkbenchAPIAndPersistence` |  |
| [internal/report/report_test.go](../internal/report/report_test.go) | `TestSARIFPreservesSourceAndIncompleteStatus` |  |
| [internal/secrets/benchmark_test.go](../internal/secrets/benchmark_test.go) |  | `BenchmarkScanText` |
| [internal/secrets/rules_test.go](../internal/secrets/rules_test.go) | `TestRuleCandidates` |  |
| [internal/secrets/scan_test.go](../internal/secrets/scan_test.go) | `TestScanRedactsAndRoundTrips`, `TestScanLimitsAndCancellation`, `TestScanRejectsInvalidInputs`, `TestScanDoesNotFollowSymlink`, `TestBinaryIsNotReportedClean` |  |
| [internal/webcheck/check_test.go](../internal/webcheck/check_test.go) | `TestDestinationPolicy`, `TestInspectRejectsUnsafeURLs`, `TestEvaluateDoesNotClaimFullProtection` |  |
| [internal/workbench/import_test.go](../internal/workbench/import_test.go) | `TestImportFormats`, `TestMalformedReportsAndBounds`, `TestOutOfScopeAndFalseMatches` |  |
| [internal/workbench/native_test.go](../internal/workbench/native_test.go) | `TestTCPRealListenerAndBoundaries`, `TestIAMPolicyReview`, `TestFileRecoveryAndPCAP`, `TestEvidencePersistsAndRetainsTwenty` | `FuzzImportBoundaries` |
| [internal/workbench/tool_aircrack_test.go](../internal/workbench/tool_aircrack_test.go) | `TestAircrackWirelessProtection`, `TestAircrackRadiotapFCSAndManagement`, `TestAircrackTruncationAndMalformed`, `TestAircrackPCAPBoundsAndCSV`, `TestAircrackMalformedSecurityAndPacketTruncation` | `FuzzAircrackWirelessPCAP` |
| [internal/workbench/tool_airgorah_test.go](../internal/workbench/tool_airgorah_test.go) | `TestAirgorahSnapshotChanges`, `TestAirgorahLegitimateSharedSSID`, `TestAirgorahRejectInvalidInput`, `TestAirgorahBoundsAndAmbiguousEvidence`, `TestAirgorahQuotedSSIDAndUnknownProtection`, `TestAirgorahSSIDControlsSanitized` |  |
| [internal/workbench/tool_bbot_test.go](../internal/workbench/tool_bbot_test.go) | `TestBBOTCoverageAndProvenance`, `TestBBOTCyclesAndConflictingIDs`, `TestBBOTValidation`, `TestBBOTParentScopeAndExcludedResolution` |  |
| [internal/workbench/tool_bloodhound_test.go](../internal/workbench/tool_bloodhound_test.go) | `TestBloodHoundCrossCollectionDirectedPath`, `TestBloodHoundUnknownRightsDuplicatesCyclesAndFlags`, `TestBloodHoundInputValidation`, `TestBloodHoundCollectionAndRecordLimits` |  |
| [internal/workbench/tool_burp_test.go](../internal/workbench/tool_burp_test.go) | `TestBurpContractEvidence`, `TestBurpInvalidAndCancelled`, `TestBurpUnresolvedAndOriginFilter`, `TestBurpPathPriorityAndParameterOverride`, `TestBurpCollectionBounds` |  |
| [internal/workbench/tool_caido_test.go](../internal/workbench/tool_caido_test.go) | `TestCaidoComparisonContractAndPrivacy`, `TestCaidoOriginScopeAndAmbiguity`, `TestCaidoBodyEncodingAndMissing`, `TestCaidoValidationAndCancellation` |  |
| [internal/workbench/tool_cloudfox_test.go](../internal/workbench/tool_cloudfox_test.go) | `TestCloudFoxInsecureTemplate`, `TestCloudFoxSecureAndDefaultEncryption`, `TestCloudFoxUnresolvedValues`, `TestCloudFoxIAMFallbackAndRedaction`, `TestCloudFoxBoundaries`, `TestCloudFoxAllProtocolAndNonAdminIngress` |  |
| [internal/workbench/tool_core_test.go](../internal/workbench/tool_core_test.go) | `TestDNSResolverFailureMarksIncomplete`, `TestAssessmentTransportScopeAndRedaction`, `TestAssessmentTransportBoundsAndCancellation`, `TestToolAssessmentBoundary`, `TestAllReferenceToolsHaveAssessmentRoutes`, `TestAssessmentNormalizesEmptyBrowserInputEncoding` |  |
| [internal/workbench/tool_cyberchef_test.go](../internal/workbench/tool_cyberchef_test.go) | `TestCyberChefJWTPolicyAndRedaction`, `TestCyberChefJWTMatchingPolicy`, `TestCyberChefJWTNoneAndExtensions`, `TestCyberChefRejectsAmbiguousJWT`, `TestCyberChefPEMCertificateReview`, `TestCyberChefPEMValidityAndBundle`, `TestCyberChefInputBoundsAndCancellation` |  |
| [internal/workbench/tool_evilginx3_test.go](../internal/workbench/tool_evilginx3_test.go) | `TestEvilginxBaselinePrivacy`, `TestEvilginxCookieReview`, `TestEvilginxHARValidationAndCancellation`, `TestEvilginxHSTSParsing` |  |
| [internal/workbench/tool_foremost_test.go](../internal/workbench/tool_foremost_test.go) | `TestForemostEmbeddedRanges`, `TestForemostTruncationAndFalseMagic`, `TestForemostBoundsCancellationAndMode` |  |
| [internal/workbench/tool_hashcat_test.go](../internal/workbench/tool_hashcat_test.go) | `TestAuditHashcatMatchingAndPrivacy`, `TestAuditHashcatAlgorithmsAndNoMatch`, `TestAuditHashcatRejectsInvalidRequests`, `TestAuditHashcatErrorPrivacy` |  |
| [internal/workbench/tool_hping3_test.go](../internal/workbench/tool_hping3_test.go) | `TestHping3LiveConnections`, `TestHping3BoundaryValidation`, `TestHping3FailureClassification` |  |
| [internal/workbench/tool_maltego_test.go](../internal/workbench/tool_maltego_test.go) | `TestMaltegoCrossReportGraph`, `TestMaltegoDirectionCyclesAndDisconnected`, `TestMaltegoDistinctKindsAndRedaction`, `TestMaltegoRejectInvalidCollections`, `TestMaltegoBoundsAndCancellation` |  |
| [internal/workbench/tool_metasploit_test.go](../internal/workbench/tool_metasploit_test.go) | `TestAuditMetasploitEvidenceCorrelation`, `TestAuditMetasploitNeverCorrelatesAnotherHostsService`, `TestAuditMetasploitRejectsInvalidReports`, `TestAuditMetasploitCollectionAndCancellation` |  |
| [internal/workbench/tool_netcat_test.go](../internal/workbench/tool_netcat_test.go) | `TestNetcatProtocolExchanges`, `TestNetcatSMTPAndCancellation`, `TestNetcatValidation`, `TestNetcatLiveReportRedaction` |  |
| [internal/workbench/tool_nmap_test.go](../internal/workbench/tool_nmap_test.go) | `TestNmapNativeRealBanner`, `TestNmapRequestBoundaries`, `TestNmapEngineArgumentsPinnedAndBounded`, `TestNmapTLSRealUntrustedCertificate` |  |
| [internal/workbench/tool_nuclei_test.go](../internal/workbench/tool_nuclei_test.go) | `TestNucleiNativeExposureRules`, `TestNucleiCookieEvidenceDoesNotRetainValues`, `TestNucleiRequestModes` |  |
| [internal/workbench/tool_passive_recon_test.go](../internal/workbench/tool_passive_recon_test.go) | `TestPassiveReconScopeAndHistoricalEvidence`, `TestPassiveScopedName`, `TestPassiveReconRejectsInvalidRequests`, `TestPassiveReconDatesAndCancellation`, `TestPassiveReconRecordLimitAndNameLimit`, `TestPassiveReconPublicTLSAddressPolicy` |  |
| [internal/workbench/tool_recon_ng_test.go](../internal/workbench/tool_recon_ng_test.go) | `TestReconNGReconciliation`, `TestReconNGRejectsInvalidInput`, `TestReconNGBoundsAndCancellation`, `TestReconNGDeduplicatesAndNormalizes` |  |
| [internal/workbench/tool_sherlock_test.go](../internal/workbench/tool_sherlock_test.go) | `TestSherlockResponseStatesAndPrivacy`, `TestSherlockSoft404CanonicalAndFreshness`, `TestSherlockRejectsMalformedAndScopedInput` |  |
| [internal/workbench/tool_shodan_test.go](../internal/workbench/tool_shodan_test.go) | `TestAuditShodanHostEvidence`, `TestAuditShodanScopeAndNoPortInference`, `TestAuditShodanFormats`, `TestAuditShodanRejectsMalformedAndExecution`, `TestAuditShodanBounds` |  |
| [internal/workbench/tool_skipfish_test.go](../internal/workbench/tool_skipfish_test.go) | `TestSkipfishCrawlScopeAndSafePaths`, `TestSkipfishPageCapAndCancellation`, `TestSkipfishBodyBaseAndNonHTMLLimits`, `TestSkipfishMarkupAndValidation` |  |
| [internal/workbench/tool_spiderdomain_test.go](../internal/workbench/tool_spiderdomain_test.go) | `TestSpiderdomainZoneConfiguration`, `TestSpiderdomainZoneCompletenessAndMailValidation`, `TestSpiderdomainRejectsInvalidInventory`, `TestSpiderdomainRequestAndCancellation`, `TestSpiderdomainLiveEnrichmentBounds` |  |
| [internal/workbench/tool_spiderfoot_test.go](../internal/workbench/tool_spiderfoot_test.go) | `TestSpiderfootJSONCorrelation`, `TestSpiderfootScopeAndPrivacy`, `TestSpiderfootCSVAndIPv6`, `TestSpiderfootBoundaryValidation`, `TestSpiderfootRecordAndGraphCaps` |  |
| [internal/workbench/tool_sqlmap_test.go](../internal/workbench/tool_sqlmap_test.go) | `TestSQLMapAuthorizedBaselineGET`, `TestSQLMapCapturedDatabaseEvidence`, `TestSQLMapErrorSignatures`, `TestSQLMapBase64AndMissingBodies`, `TestSQLMapMalformedAndEngine`, `TestSQLMapCorrelationRequiresSameEndpointAndOneQueryChange` |  |
| [internal/workbench/tool_wireshark_test.go](../internal/workbench/tool_wireshark_test.go) | `TestWiresharkPCAPNGConversations`, `TestWiresharkPCAPNGRejectsMalformedStructure`, `TestWiresharkPCAPNGLimitedEvidence`, `TestWiresharkOptionsAndRequests`, `TestWiresharkClassicPCAPRegression` | `FuzzWiresharkCaptureInput` |
| [internal/world/feeds_test.go](../internal/world/feeds_test.go) | `TestFreshCacheSurvivesServiceRestart`, `TestFeedCachingAndStaleFailures`, `TestInvalidAndRedirectedFeeds` |  |

## Other integration and contract references

| Source | Why it matters |
| --- | --- |
| [`api/godseye/v1/plugin.proto`](../api/godseye/v1/plugin.proto) | Preserve field numbers, optional presence, enums, messages and the future plugin service contract |
| [`gen/go/godseye/v1/plugin.pb.go`](../gen/go/godseye/v1/plugin.pb.go) | Generated baseline types; generate Python from the source schema rather than translating this file |
| [`apps/web/src/api.ts`](../apps/web/src/api.ts) | Dashboard Zod contracts, status enum, field defaults, mutation headers and error decoding |
| [`apps/web/src/lab/api.ts`](../apps/web/src/lab/api.ts) | Evidence/catalog/summary contracts, raw upload and diagnostic caller behavior |
| [`apps/web/src/lab/Assessments.tsx`](../apps/web/src/lab/Assessments.tsx) | Capability parsing and assessment UI metadata |
| [`apps/web/src/lab/Workbench.tsx`](../apps/web/src/lab/Workbench.tsx) | Upload/assessment forms, JSON request encoding, report selection and saved evidence |
| [`apps/web/src/lab/Evidence.tsx`](../apps/web/src/lab/Evidence.tsx) | Evidence display, graph and original-input recovery downloads |
| [`apps/web/src/world/model.ts`](../apps/web/src/world/model.ts) | World feed body parsing, source semantics and attribution |
| [`apps/web/src/world/WorldView.tsx`](../apps/web/src/world/WorldView.tsx) | Compact World acquisition, map state and interaction |
| [`apps/earth/vite.config.js`](../apps/earth/vite.config.js) | Active keyless configuration, dev/preview middleware and port 4173 |
| [`apps/earth/server/free-providers.js`](../apps/earth/server/free-providers.js) | Active free-edition provider behavior |
| [`apps/web/package.json`](../apps/web/package.json) | Current dashboard build and tests |
| [`apps/earth/package.json`](../apps/earth/package.json) | Node engine constraints and free-edition regression command |
| [`scripts/start.ps1`](../scripts/start.ps1) | Go executable launch/build dependency to replace, capability checks and separate Earth lifetime |
| [`scripts/smoke.ps1`](../scripts/smoke.ps1) | CLI/server integration assertions to retain while adapting invocation |
| [`docs/assessment-modules.md`](../docs/assessment-modules.md) | Current 26 assessment coverage/input/limit descriptions |
| [`docs/assessment-verification-2026-10-18.md`](../docs/assessment-verification-2026-10-18.md) | Latest recorded fixes and operating evidence; historical, not newly rerun |
| [`docs/earth-edition.md`](../docs/earth-edition.md) | Independent Earth features, exclusions and source/data notices |
| [`docs/plugin-protocol.md`](../docs/plugin-protocol.md) | Future plugin validation contract; distinguish blueprint from implemented behavior |
| [`docs/architecture.md`](../docs/architecture.md) | Original Go-oriented blueprint to reconcile after implementation |

## Snapshot maintenance

Before implementing a phase, confirm its source file has not changed since this baseline. If source changes, update the comparison fixtures and the affected requirement rows. This plan does not freeze unrelated ongoing development or authorize overwriting another change.

This planning task did not execute Go/Python application tests or Docker. The Go executable was not on the shell PATH during analysis; Docker CLI availability was observed, but daemon health was not checked. Required baseline verification belongs to Phase 0. No Windows/Linux parity is inferred from the file inventory.
