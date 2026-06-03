```
// ================================================
// TIFCE Pillar 2: Environmental Relevance
// Query 1: XDR Device + Email telemetry only
//
// Purpose:
// - Identify whether active TI IOCs are found in XDR telemetry.
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
// No observe / block / deny / disposition logic
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
    | extend IOC = CanonicalIOC(IOCType, tostring(ObservableValue))
    | summarize by TIFeed, IOC;
// -----------------------------
// IOC matches in XDR telemetry
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
        | project IOC
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
        | project IOC
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
        | project IOC
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
        | project IOC
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
        | project IOC
    )
    | where isnotempty(IOC)
    | summarize by IOC;
// -----------------------------
// Feed-level relevance scoring
// -----------------------------
ActiveIOCs
| join kind=leftouter (
    TelemetryIOCs
    | project TelemetryIOC = IOC
) on $left.IOC == $right.TelemetryIOC
| summarize
    TotalIOCs = count(),
    FoundIOCs = countif(isnotempty(TelemetryIOC)),
    NotFoundIOCs = countif(isempty(TelemetryIOC))
    by TIFeed
| extend
    EnvironmentalRelevanceScore = FoundIOCs,
    RelevancePct = round(
        iif(TotalIOCs > 0, 100.0 * todouble(FoundIOCs) / todouble(TotalIOCs), 0.0),
        2
    ),
    NotFoundPct = round(
        iif(TotalIOCs > 0, 100.0 * todouble(NotFoundIOCs) / todouble(TotalIOCs), 0.0),
        2
    )
| order by EnvironmentalRelevanceScore desc
| project
    Feed = TIFeed,
    TotalIOCs,
    FoundIOCs,
    NotFoundIOCs,
    RelevancePct,
    NotFoundPct,
    EnvironmentalRelevanceScore;
```
