# Estimate Potential Savings by Moving Tables to Data Lake

# Description

The following query simulates cost savings if high-volume tables currently on Analytics were moved to Data Lake, using hypothetical prices. While this query could help support cost optimization decisions, don't forget to take into account processing and retention costs.

### Microsoft Sentinel
```
let AnalyticsPricePerGB = 2.48; // Example price per GB for Analytics
let DataLakePricePerGB = 0.05; // Example price per GB for Data Lake
Usage
| where TimeGenerated >= startofday(ago(30d))
| where IsBillable == true
| summarize IngestedGB = round(sum(Quantity) / 1000.0, 2) by DataType, Plan
| where Plan == "Analytics"
| extend CurrentCost = round(IngestedGB * AnalyticsPricePerGB, 2)
| extend IfDataLakeCost = round(IngestedGB * DataLakePricePerGB, 2)
| extend PotentialSavings = round(CurrentCost - IfDataLakeCost, 2)
| where PotentialSavings > 0
| project DataType, IngestedGB, CurrentCost, IfDataLakeCost, PotentialSavings
| order by PotentialSavings desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 17/05/2026    | Initial publish                        |
