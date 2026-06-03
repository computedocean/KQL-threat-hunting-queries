```
// ================================================
// TIFCE Pillar 3: Malicious IOCs — Signal Versus Noise
//
// Purpose:
// - Determine whether active TI IOCs that appeared in XDR telemetry
//   were associated with closed Sentinel incidents classified as TruePositive.
//
// Correlation path:
// - SecurityIncident.AlertIds
//   -> SecurityAlert.SystemAlertId
//   -> SecurityAlert.Entities
//
// Scoring:
// - Closed incident with Classification == "TruePositive"
//   = confirmed malicious signal
//
// - Any other closed classification
//   = noise / not confirmed malicious
//
// Supports:
// - file
// - ipv4-addr
// - ipv6-addr
// - network-traffic
// - domain-name
// - url
// - email-addr
//
// Required tables:
// - ThreatIntelIndicators
// - DeviceFileEvents
// - DeviceNetworkEvents
// - EmailUrlInfo
// - EmailAttachmentInfo
// - EmailEvents
// - SecurityIncident
// - SecurityAlert
// ================================================
let CanonicalIOC = (iocType:string, iocValue:string) {
    strcat(tolower(trim(" ", iocType)), ":", tolower(trim(" ", iocValue)))
};
// -----------------------------
// Active TI indicators
// -----------------------------
let ActiveIOCs =
    ThreatIntelIndicators
    | where IsActive == true
      and IsDeleted == false
      and (isnull(ValidUntil) or ValidUntil > now())
    | where isnotempty(SourceSystem)
      and isnotempty(ObservableKey)
      and isnotempty(ObservableValue)
    | extend TIFeed = tostring(SourceSystem)
    | extend IOCTypeRaw = tostring(split(ObservableKey, ":", 0))
    | extend IOCType = replace_regex(tolower(trim(" ", IOCTypeRaw)), @"[\[\]""']", "")
    | where IOCType in (
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "network-traffic",
        "domain-name",
        "url",
        "email-addr"
    )
    | extend IOCValue = tolower(trim(" ", tostring(ObservableValue)))
    | extend IOC = CanonicalIOC(IOCType, IOCValue)
    | summarize by TIFeed, IOCType, IOCValue, IOC;
// -----------------------------
// IOC matches in XDR telemetry
// Same logic as Pillar 2 + email address/domain
// -----------------------------
let TelemetryIOCs =
    union isfuzzy=true
    // Device file hashes
    (
        DeviceFileEvents
        | where isnotempty(SHA256) or isnotempty(SHA1)
        | extend IOCs = pack_array(
            iff(isnotempty(SHA256), CanonicalIOC("file", SHA256), ""),
            iff(isnotempty(SHA1), CanonicalIOC("file", SHA1), "")
        )
        | mv-expand IOC = IOCs to typeof(string)
        | where isnotempty(IOC)
        | extend TelemetrySource = "DeviceFileEvents"
        | project IOC, TelemetrySource
    ),
    // Device network IPs, IPv6, network-traffic, URLs, and domains
    (
        DeviceNetworkEvents
        | where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
        | extend UrlHost = iff(isnotempty(RemoteUrl), tostring(parse_url(RemoteUrl).Host), "")
        | extend RemoteIPType = iff(RemoteIP contains ":", "ipv6-addr", "ipv4-addr")
        | extend IOCs = pack_array(
            iff(isnotempty(RemoteIP), CanonicalIOC(RemoteIPType, RemoteIP), ""),
            iff(isnotempty(RemoteIP), CanonicalIOC("network-traffic", RemoteIP), ""),
            iff(isnotempty(RemoteUrl), CanonicalIOC("url", RemoteUrl), ""),
            iff(isnotempty(UrlHost), CanonicalIOC("domain-name", UrlHost), "")
        )
        | mv-expand IOC = IOCs to typeof(string)
        | where isnotempty(IOC)
        | extend TelemetrySource = "DeviceNetworkEvents"
        | project IOC, TelemetrySource
    ),
    // Email URLs and domains
    (
        EmailUrlInfo
        | where isnotempty(Url) or isnotempty(UrlDomain)
        | extend IOCs = pack_array(
            iff(isnotempty(Url), CanonicalIOC("url", Url), ""),
            iff(isnotempty(UrlDomain), CanonicalIOC("domain-name", UrlDomain), "")
        )
        | mv-expand IOC = IOCs to typeof(string)
        | where isnotempty(IOC)
        | extend TelemetrySource = "EmailUrlInfo"
        | project IOC, TelemetrySource
    ),
    // Email attachment hashes
    (
        EmailAttachmentInfo
        | where isnotempty(SHA256) or isnotempty(SHA1)
        | extend IOCs = pack_array(
            iff(isnotempty(SHA256), CanonicalIOC("file", SHA256), ""),
            iff(isnotempty(SHA1), CanonicalIOC("file", SHA1), "")
        )
        | mv-expand IOC = IOCs to typeof(string)
        | where isnotempty(IOC)
        | extend TelemetrySource = "EmailAttachmentInfo"
        | project IOC, TelemetrySource
    ),
    // Email addresses + derived email domains
    (
        EmailEvents
        | extend SenderFromAddress = tostring(column_ifexists("SenderFromAddress", "")),
                 SenderMailFromAddress = tostring(column_ifexists("SenderMailFromAddress", "")),
                 RecipientEmailAddress = tostring(column_ifexists("RecipientEmailAddress", ""))
        | extend EmailCandidates = pack_array(SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress)
        | mv-expand EmailAddress = EmailCandidates to typeof(string)
        | extend EmailAddress = tolower(trim(" ", EmailAddress))
        | where isnotempty(EmailAddress) and EmailAddress contains "@"
        | extend EmailDomain = tostring(split(EmailAddress, "@", 1))
        | extend IOCs = pack_array(
            CanonicalIOC("email-addr", EmailAddress),
            iff(isnotempty(EmailDomain), CanonicalIOC("domain-name", EmailDomain), "")
        )
        | mv-expand IOC = IOCs to typeof(string)
        | where isnotempty(IOC)
        | extend TelemetrySource = "EmailEvents"
        | project IOC, TelemetrySource
    )
    | summarize
        TelemetryHitCount = count(),
        TelemetrySources = make_set(TelemetrySource)
        by IOC;
// -----------------------------
// Closed Sentinel incidents correlated to SecurityAlert.Entities
// -----------------------------
let IncidentEntityIOCs =
    SecurityIncident
    | where Status == "Closed"
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | extend IncidentClassification =
        case(
            Classification == "TruePositive", "TruePositive",
            Classification == "BenignPositive", "BenignPositive",
            Classification == "FalsePositive", "FalsePositive",
            Classification == "Undetermined", "Undetermined",
            isempty(Classification), "UnclassifiedClosed",
            tostring(Classification)
        )
    | extend IOCAssessment =
        case(
            IncidentClassification == "TruePositive", "TruePositive",
            "NoiseOrNotConfirmedMalicious"
        )
    | mv-expand AlertId = AlertIds to typeof(string)
    | join kind=inner (
        SecurityAlert
        | where isnotempty(Entities)
        | project
            SystemAlertId,
            AlertName,
            AlertSeverity,
            ProductName,
            ProviderName,
            Entities
    ) on $left.AlertId == $right.SystemAlertId
    | extend EntityArray = todynamic(Entities)
    | mv-expand Entity = EntityArray
    | extend EntityType = tolower(tostring(Entity.Type))
    | extend EntityEmail = case(
        isnotempty(tostring(Entity.Address)), tostring(Entity.Address),
        isnotempty(tostring(Entity.EmailAddress)), tostring(Entity.EmailAddress),
        isnotempty(tostring(Entity.Sender)), tostring(Entity.Sender),
        isnotempty(tostring(Entity.SenderFromAddress)), tostring(Entity.SenderFromAddress),
        isnotempty(tostring(Entity.RecipientEmailAddress)), tostring(Entity.RecipientEmailAddress),
        ""
    )
    | extend IOCCandidates = pack_array(
        iff(EntityType == "ip", CanonicalIOC("ipv4-addr", tostring(Entity.Address)), ""),
        iff(EntityType == "ip", CanonicalIOC("ipv6-addr", tostring(Entity.Address)), ""),
        iff(EntityType == "ip", CanonicalIOC("network-traffic", tostring(Entity.Address)), ""),
        iff(EntityType == "url", CanonicalIOC("url", tostring(Entity.Url)), ""),
        iff(EntityType == "dns", CanonicalIOC("domain-name", tostring(Entity.DomainName)), ""),
        iff(EntityType == "filehash", CanonicalIOC("file", tostring(Entity.Value)), ""),
        iff(isnotempty(EntityEmail) and EntityEmail contains "@", CanonicalIOC("email-addr", EntityEmail), ""),
        iff(isnotempty(EntityEmail) and EntityEmail contains "@", CanonicalIOC("domain-name", tostring(split(EntityEmail, "@", 1))), "")
    )
    | mv-expand IncidentIOC = IOCCandidates to typeof(string)
    | where isnotempty(IncidentIOC)
    | project
        IncidentNumber,
        IncidentTitle = Title,
        IncidentSeverity = Severity,
        IncidentStatus = Status,
        IncidentClassification,
        ClassificationReason,
        ClassificationComment,
        IOCAssessment,
        ClosedTime,
        CreatedTime,
        AlertId,
        AlertName,
        AlertSeverity,
        ProductName,
        ProviderName,
        EntityType,
        IncidentIOC;
// -----------------------------
// Final feed-level scoring
// -----------------------------
ActiveIOCs
| join kind=inner TelemetryIOCs on IOC
| mv-expand TelemetrySource = TelemetrySources to typeof(string)
| join kind=leftouter IncidentEntityIOCs on $left.IOC == $right.IncidentIOC
| summarize
    TotalTelemetryMatchedIOCs = dcount(IOC),
    IOCsWithClosedIncidentEvidence = dcountif(IOC, isnotempty(IncidentNumber)),
    TruePositiveIOCs = dcountif(IOC, IOCAssessment == "TruePositive"),
    NoiseOrNotConfirmedIOCs = dcountif(IOC, IOCAssessment == "NoiseOrNotConfirmedMalicious"),
    ClosedIncidentCount = dcount(IncidentNumber),
    TruePositiveIncidentCount = dcountif(IncidentNumber, IncidentClassification == "TruePositive"),
    NoiseOrNotConfirmedIncidentCount = dcountif(
        IncidentNumber,
        isnotempty(IncidentClassification)
        and IncidentClassification != "TruePositive"
    ),
    Classifications = make_set(IncidentClassification),
    ExampleIncidents = make_set(strcat(tostring(IncidentNumber), " - ", tostring(IncidentTitle)), 10),
    TelemetrySources = make_set(TelemetrySource)
    by TIFeed
| extend
    TruePositivePct = round(
        iif(
            TotalTelemetryMatchedIOCs > 0,
            100.0 * todouble(TruePositiveIOCs) / todouble(TotalTelemetryMatchedIOCs),
            0.0
        ),
        2
    ),
    NoisePct = round(
        iif(
            TotalTelemetryMatchedIOCs > 0,
            100.0 * todouble(NoiseOrNotConfirmedIOCs) / todouble(TotalTelemetryMatchedIOCs),
            0.0
        ),
        2
    ),
    IncidentEvidenceCoveragePct = round(
        iif(
            TotalTelemetryMatchedIOCs > 0,
            100.0 * todouble(IOCsWithClosedIncidentEvidence) / todouble(TotalTelemetryMatchedIOCs),
            0.0
        ),
        2
    ),
    SignalVsNoiseScore = TruePositiveIOCs - NoiseOrNotConfirmedIOCs
| order by SignalVsNoiseScore desc, TruePositivePct desc
| project
    Feed = TIFeed,
    TotalTelemetryMatchedIOCs,
    IOCsWithClosedIncidentEvidence,
    TruePositiveIOCs,
    NoiseOrNotConfirmedIOCs,
    TruePositivePct,
    NoisePct,
    IncidentEvidenceCoveragePct,
    ClosedIncidentCount,
    TruePositiveIncidentCount,
    NoiseOrNotConfirmedIncidentCount
```
