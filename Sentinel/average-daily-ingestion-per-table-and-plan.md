# Average Daily Ingestion per Table and Plan

# Description

The following query calculates the average daily ingestion for each table and plan over the last Timeframe of days as defined in the let statement. It also allows you to define the size of fractional part to fit your need and attention to detail. This query help baseline normal usage and identify outliers.

### Microsoft Sentinel
```
let Timeframe = 30d; // Define the required Timeframe
let decfra = 2; // Determine the size of fractional part to fit your need
Usage
| where TimeGenerated >= startofday(ago(Timeframe))
| where IsBillable == true
| summarize DailyGB = sum(Quantity) / 1000.0 by bin(TimeGenerated, 1d), DataType, Plan
| summarize AvgDailyGB = round(avg(DailyGB), decfra) by DataType, Plan
| order by AvgDailyGB desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 17/05/2026    | Initial publish                        |
