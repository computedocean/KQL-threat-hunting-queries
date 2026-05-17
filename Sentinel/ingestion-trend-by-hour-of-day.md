# Ingestion Trend by Hour of Day

# Description

The following query helps analyze ingestion patterns by hour to identify peak ingestion times for each plan. Query can be useful for capacity planning and detecting unusual activity windows.

### Microsoft Sentinel
```
let Timeframe = 7d; // Define the required Timeframe
Usage
| where TimeGenerated >= ago(Timeframe)
| where IsBillable == true
| extend Hour = datetime_part("hour", TimeGenerated)
| summarize IngestedGB = sum(Quantity) / 1000.0 by Hour, Plan
| evaluate pivot(Plan, sum(IngestedGB))
| order by Hour asc
| render columnchart
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 17/05/2026    | Initial publish                        |
