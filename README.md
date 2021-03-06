# Collection of Azure Sentinel - Playbook | Logic App (Template)

> Austin Lai | May 13th, 2022

---

<!-- Description -->

A collection of Azure Sentinel - Playbook | Logic App (Template) for your reference.

<!-- /Description -->

## Table of Contents

<!-- TOC -->

- [Collection of Azure Sentinel - Playbook | Logic App Template](#collection-of-azure-sentinel---playbook--logic-app-template)
    - [Table of Contents](#table-of-contents)
    - [Azure Sentinel - Playbook | Logic App Template](#azure-sentinel---playbook--logic-app-template)
        - [Permission required to run Azure Sentinel Incident and Alert Playbook](#permission-required-to-run-azure-sentinel-incident-and-alert-playbook)
        - [Incident based playbook - network policy changes incident alert detected and send email notification](#incident-based-playbook---network-policy-changes-incident-alert-detected-and-send-email-notification)
        - [Alert based playbook - network policy changes alert detected and send email notification](#alert-based-playbook---network-policy-changes-alert-detected-and-send-email-notification)
        - [Ingest Threat Intelligent Feed to Azure Sentinel via API Connection](#ingest-threat-intelligent-feed-to-azure-sentinel-via-api-connection)
        - [Incident based playbook - Extract UserName from detected SSH Brute Force Attack to WatchList](#incident-based-playbook---extract-username-from-detected-ssh-brute-force-attack-to-watchlist)
        - [Alert based playbook - Extract UserName from detected SSH Brute Force Attack to WatchList](#alert-based-playbook---extract-username-from-detected-ssh-brute-force-attack-to-watchlist)

<!-- /TOC -->

## Azure Sentinel - Playbook | Logic App (Template)

### Permission required to run Azure Sentinel Incident and Alert Playbook

- Logic App Contributor
- Microsoft Sentinel Automation Contributor
- Microsoft Sentinel Contributor

Permissions required to run playbook are listed in the above and SHOULD be under **subscription** level

### Incident based playbook - network policy changes incident alert detected and send email notification

Incident based playbook using "Microsoft Sentinel Incident (Preview)" connector.
(Connector specify here only applicable at the time of this writing; it might changed or updated by Microsoft)

Incident based playbook only allow to be run by:

- On "Incident" dashboard, manually run playbook by selecting specific incident and trigger the playbook
- Part of "Automation Rule"
- Playbook will only run if new incident is created and alert is NOT GROUP (since alert will aggregate it and group under same incident ID, hence might not be able to trigger playbook within duration)

<details><summary>Incident-changes_detected_Network_interfaces_should_not_have_public_IPs_policy</summary>

```json
//  Replace "XXXXXX" to your own Subscription ID and Resource Group accordingly
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.Logic/workflows",
            "apiVersion": "2017-07-01",
            "name": "Incident-changes_detected_Network_interfaces_should_not_have_public_IPs_policy",
            "location": "southeastasia",
            "tags": {
                "hidden-SentinelTemplateName": "Send-email-with-formatted-incident-report",
                "hidden-SentinelTemplateVersion": "1.0"
            },
            "identity": {
                "type": "SystemAssigned"
            },
            "properties": {
                "state": "Enabled",
                "definition": {
                    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {
                        "$connections": {
                            "defaultValue": {},
                            "type": "Object"
                        }
                    },
                    "triggers": {
                        "Microsoft_Sentinel_incident": {
                            "type": "ApiConnectionWebhook",
                            "inputs": {
                                "body": {
                                    "callback_url": "@{listCallbackUrl()}"
                                },
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel_1']['connectionId']"
                                    }
                                },
                                "path": "/incident-creation"
                            }
                        }
                    },
                    "actions": {
                        "Condition": {
                            "actions": {
                                "Compose_Incident_link": {
                                    "runAfter": {
                                        "Create_Entitles_HTML_table": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "Compose",
                                    "inputs": "<a href=\"@{triggerBody()?['object']?['properties']?['incidentUrl']}\">@{triggerBody()?['object']?['properties']?['incidentUrl']}</a>"
                                },
                                "Create_Entitles_HTML_table": {
                                    "runAfter": {},
                                    "type": "Table",
                                    "inputs": {
                                        "format": "HTML",
                                        "from": "@triggerBody()?['object']?['properties']?['relatedEntities']"
                                    }
                                },
                                "For_each": {
                                    "foreach": "@triggerBody()?['object']?['properties']?['Alerts']",
                                    "actions": {
                                        "Parse_JSON_-_Alert_Custom_Details": {
                                            "runAfter": {
                                                "Set_variable_-_Alert_Query": [
                                                    "Succeeded"
                                                ]
                                            },
                                            "type": "ParseJson",
                                            "inputs": {
                                                "content": "@items('For_each')?['properties']?['additionalData']?['Custom Details']",
                                                "schema": {
                                                    "properties": {
                                                        "OperationNameValue": {
                                                            "items": {
                                                                "type": "string"
                                                            },
                                                            "type": "array"
                                                        },
                                                        "Properties_d": {
                                                            "items": {
                                                                "type": "string"
                                                            },
                                                            "type": "array"
                                                        }
                                                    },
                                                    "type": "object"
                                                }
                                            }
                                        },
                                        "Set_variable_-_Alert_Custom_Details_-_OperationNameValue": {
                                            "runAfter": {
                                                "Parse_JSON_-_Alert_Custom_Details": [
                                                    "Succeeded"
                                                ]
                                            },
                                            "type": "SetVariable",
                                            "inputs": {
                                                "name": "Alert Custom Details - OperationNameValue",
                                                "value": "@{body('Parse_JSON_-_Alert_Custom_Details')?['OperationNameValue']}"
                                            }
                                        },
                                        "Set_variable_-_Alert_Custom_Details_-_Propertiesd": {
                                            "runAfter": {
                                                "Set_variable_-_Alert_Custom_Details_-_OperationNameValue": [
                                                    "Succeeded"
                                                ]
                                            },
                                            "type": "SetVariable",
                                            "inputs": {
                                                "name": "Alert Custom Details - Properties_d",
                                                "value": "@{body('Parse_JSON_-_Alert_Custom_Details')?['Properties_d']}"
                                            }
                                        },
                                        "Set_variable_-_Alert_Query": {
                                            "runAfter": {},
                                            "type": "SetVariable",
                                            "inputs": {
                                                "name": "Alert Query",
                                                "value": "@items('For_each')?['properties']?['additionalData']?['Query']"
                                            }
                                        }
                                    },
                                    "runAfter": {
                                        "Compose_Incident_link": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "Foreach"
                                },
                                "Send_an_email_with_Incident_details": {
                                    "runAfter": {
                                        "For_each": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "ApiConnection",
                                    "inputs": {
                                        "body": {
                                            "Body": "<p><span style=\"font-size: 16px\"><strong>New incident created in Azure Sentinel - Incident details as shown below:</strong></span><br>\n<br>\n<span style=\"font-size: 14px\"><strong>Incident title:</strong></span><br>\n@{triggerBody()?['object']?['properties']?['title']}<br>\n<br>\n<span style=\"font-size: 14px\"><strong>Incident ID:</strong></span><br>\n@{triggerBody()?['object']?['properties']?['incidentNumber']}<br>\n<br>\n<span style=\"font-size: 14px\"><strong>Creation time:</strong></span><br>\n@{triggerBody()?['object']?['properties']?['createdTimeUtc']}<br>\n<br>\n<span style=\"font-size: 14px\"><strong>Severity:</strong></span><br>\n@{triggerBody()?['object']?['properties']?['severity']}<br>\n<br>\n<span style=\"font-size: 14px\"><strong>Alert providers:</strong></span><br>\n@{join(triggerBody()?['object']?['properties']?['additionalData']?['alertProductNames'], '<br />')}<br>\n<br>\n<span style=\"font-size: 14px\"><strong>Entities:</strong></span><br>\n@{body('Create_Entitles_HTML_table')}<br>\n<br>\n<span style=\"font-size: 14px\"><strong>Alert Custom Details:</strong></span><br>\nOperationNameValue:<br>\n@{variables('Alert Custom Details - OperationNameValue')}<br>\n-----<br>\nProperties_d:<br>\n@{variables('Alert Custom Details - Properties_d')}<br>\n<br>\n<span style=\"font-size: 14px\"><strong>Incident link:</strong></span><br>\n@{outputs('Compose_Incident_link')}<br>\n<br>\n<span style=\"font-size: 14px\"><strong>Alert Query:</strong></span><br>\n@{substring(variables('Alert Query'),0,31)}<br>\n//-----<br>\n@{substring(variables('Alert Query'), 32)}<br>\n<br>\n<br>\n</p>",
                                            "Importance": "Normal",
                                            "Subject": "New Azure Sentinel incident - @{triggerBody()?['object']?['properties']?['title']}",
                                            "To": "azuremonitor.alert@azuremonitor.com"
                                        },
                                        "host": {
                                            "connection": {
                                                "name": "@parameters('$connections')['office365_1']['connectionId']"
                                            }
                                        },
                                        "method": "post",
                                        "path": "/v2/Mail"
                                    }
                                }
                            },
                            "runAfter": {
                                "Initialize_variable_-_Alert_Query": [
                                    "Succeeded"
                                ]
                            },
                            "else": {
                                "actions": {
                                    "Terminate_-_Failed_Condition": {
                                        "runAfter": {},
                                        "type": "Terminate",
                                        "inputs": {
                                            "runError": {
                                                "code": "Not_Match",
                                                "message": "Condition not match with Incident Name contains \"Customized - NRT - Detect changes in Network interfaces should not have public\""
                                            },
                                            "runStatus": "Failed"
                                        }
                                    }
                                }
                            },
                            "expression": {
                                "and": [
                                    {
                                        "contains": [
                                            "@triggerBody()?['object']?['properties']?['title']",
                                            "Customized - NRT - Detect changes in Network interfaces should not have public"
                                        ]
                                    }
                                ]
                            },
                            "type": "If"
                        },
                        "Initialize_variable_-_Alert_Custom_Details_-_OperationNameValue": {
                            "runAfter": {},
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "Alert Custom Details - OperationNameValue",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_Alert_Custom_Details_-_Propertiesd": {
                            "runAfter": {
                                "Initialize_variable_-_Alert_Custom_Details_-_OperationNameValue": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "Alert Custom Details - Properties_d",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_Alert_Query": {
                            "runAfter": {
                                "Initialize_variable_-_Alert_Custom_Details_-_Propertiesd": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "Alert Query",
                                        "type": "string"
                                    }
                                ]
                            }
                        }
                    },
                    "outputs": {}
                },
                "parameters": {
                    "$connections": {
                        "value": {
                            "azuresentinel_1": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/azuresentinel-1",
                                "connectionName": "azuresentinel-1",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/azuresentinel"
                            },
                            "office365_1": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/office365",
                                "connectionName": "office365",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/office365"
                            }
                        }
                    }
                }
            }
        }
    ]
}
```

</details>

[Link to the file of Incident-changes_detected_Network_interfaces_should_not_have_public_IPs_policy here](https://github.com/austin-lai/Collection-of-AzureSentinel-Playbook/blob/master/Incident-changes_detected_Network_interfaces_should_not_have_public_IPs_policy.json)

### Alert based playbook - network policy changes alert detected and send email notification

Alert based playbook using "Microsoft Sentinel Alert (Preview)" connector.
(Connector specify here only applicable at the time of this writing; it might changed or updated by Microsoft)

Alert based playbook only allow to be run by:

- "Alert automation" --- That is part of "Analytic Rule"
- Whenever alert is created

<details><summary>Alert-changes_detected_Network_interfaces_should_not_have_public_IPs_policy</summary>

```json
//  Replace "XXXXXX" to your own Subscription ID and Resource Group accordingly
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.Logic/workflows",
            "apiVersion": "2017-07-01",
            "name": "Alert-changes_detected_Network_interfaces_should_not_have_public_IPs_policy",
            "location": "southeastasia",
            "tags": {
                "hidden-SentinelTemplateName": "Send-email-with-formatted-incident-report",
                "hidden-SentinelTemplateVersion": "1.0"
            },
            "identity": {
                "type": "SystemAssigned"
            },
            "properties": {
                "state": "Enabled",
                "definition": {
                    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {
                        "$connections": {
                            "defaultValue": {},
                            "type": "Object"
                        }
                    },
                    "triggers": {
                        "Microsoft_Sentinel_alert": {
                            "type": "ApiConnectionWebhook",
                            "inputs": {
                                "body": {
                                    "callback_url": "@{listCallbackUrl()}"
                                },
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel_1']['connectionId']"
                                    }
                                },
                                "path": "/subscribe"
                            }
                        }
                    },
                    "actions": {
                        "Condition": {
                            "actions": {
                                "Create_Entitles_HTML_table": {
                                    "runAfter": {},
                                    "type": "Table",
                                    "inputs": {
                                        "format": "HTML",
                                        "from": "@triggerBody()?['Entities']"
                                    }
                                },
                                "Parse_JSON_-_Custom_Details_Strings": {
                                    "runAfter": {
                                        "Create_Entitles_HTML_table": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "ParseJson",
                                    "inputs": {
                                        "content": "@triggerBody()?['ExtendedProperties']?['Custom Details']",
                                        "schema": {
                                            "properties": {
                                                "OperationNameValue": {
                                                    "items": {
                                                        "type": "string"
                                                    },
                                                    "type": "array"
                                                },
                                                "Properties_d": {
                                                    "items": {
                                                        "type": "string"
                                                    },
                                                    "type": "array"
                                                }
                                            },
                                            "type": "object"
                                        }
                                    }
                                },
                                "RAW_-_ExtendedProperties_-_Custom_Details_and_Query": {
                                    "runAfter": {
                                        "Create_Entitles_HTML_table": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "Compose",
                                    "inputs": {
                                        "ExtendedProperties-CustomDetails-Raw": "@triggerBody()?['ExtendedProperties']?['Custom Details']",
                                        "ExtendedProperties-Query-Raw": "@triggerBody()?['ExtendedProperties']?['Query']"
                                    }
                                },
                                "Send_an_email_(V2)": {
                                    "runAfter": {
                                        "Parse_JSON_-_Custom_Details_Strings": [
                                            "Succeeded"
                                        ],
                                        "RAW_-_ExtendedProperties_-_Custom_Details_and_Query": [
                                            "Succeeded"
                                        ],
                                        "Set_variable_-_Query_Strings": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "ApiConnection",
                                    "inputs": {
                                        "body": {
                                            "Body": "<p><span style=\"font-size: 24px\"><strong>New Alert created in Azure Sentinel - Alert details as shown below:</strong></span><br>\n<br>\n<span style=\"font-size: 18px\"><u><strong>Alert title:</strong></u></span><br>\n@{triggerBody()?['AlertDisplayName']}<br>\n<br>\n<span style=\"font-size: 18px\"><u><strong>Alert ID:</strong></u></span><br>\n@{triggerBody()?['SystemAlertId']}<br>\n<br>\n<span style=\"font-size: 18px\"><u><strong>Creation time:</strong></u></span><br>\n@{triggerBody()?['TimeGenerated']}<br>\n<br>\n<span style=\"font-size: 18px\"><u><strong>Severity:</strong></u></span><br>\n@{triggerBody()?['Severity']}<br>\n<br>\n<span style=\"font-size: 18px\"><u><strong>Entities:</strong></u></span><br>\n@{body('Create_Entitles_HTML_table')}<br>\n<br>\n<span style=\"font-size: 18px\"><u><strong>Details (Custom Details):</strong></u></span><br>\n<span style=\"font-size: 14px\"><strong>OperationNameValue:</strong></span><br>\n@{body('Parse_JSON_-_Custom_Details_Strings')?['OperationNameValue']}<br>\n-----<br>\n<span style=\"font-size: 14px\"><strong>Properties_d:</strong></span><br>\n@{body('Parse_JSON_-_Custom_Details_Strings')?['Properties_d']}<br>\n<br>\n<br>\n<span style=\"font-size: 18px\"><u><strong>Alert Query Result:</strong></u></span><br>\n@{substring(variables('Query Replace'), 0,31)}<br>\n//-----<br>\n@{variables('Query Strings')}<br>\n-------------------------<br>\n</p>",
                                            "Importance": "Normal",
                                            "Subject": "New Azure Sentinel Alert - @{triggerBody()?['AlertDisplayName']}",
                                            "To": "azuremonitor.alert@azuremonitor.com"
                                        },
                                        "host": {
                                            "connection": {
                                                "name": "@parameters('$connections')['office365_1']['connectionId']"
                                            }
                                        },
                                        "method": "post",
                                        "path": "/v2/Mail"
                                    }
                                },
                                "Set_variable_-_Query_Replace": {
                                    "runAfter": {
                                        "Create_Entitles_HTML_table": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "Query Replace",
                                        "value": "@{replace(triggerBody()?['ExtendedProperties']?['Query'], '\\n', ' ')}"
                                    }
                                },
                                "Set_variable_-_Query_Strings": {
                                    "runAfter": {
                                        "Set_variable_-_Query_Replace": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "Query Strings",
                                        "value": "@{substring(variables('Query Replace'), 32)}"
                                    }
                                }
                            },
                            "runAfter": {
                                "Initialize_variable_-_Query_Strings": [
                                    "Succeeded"
                                ]
                            },
                            "else": {
                                "actions": {
                                    "Terminate": {
                                        "runAfter": {},
                                        "type": "Terminate",
                                        "inputs": {
                                            "runError": {
                                                "code": "Not_Match",
                                                "message": "Condition not match with Incident Name contains \"Customized - NRT - Detect changes in Network interfaces should not have public\""
                                            },
                                            "runStatus": "Failed"
                                        }
                                    }
                                }
                            },
                            "expression": {
                                "and": [
                                    {
                                        "contains": [
                                            "@triggerBody()?['AlertDisplayName']",
                                            "Customized - NRT - Detect changes in Network interfaces should not have public"
                                        ]
                                    }
                                ]
                            },
                            "type": "If"
                        },
                        "Initialize_variable_-_Query_Replace": {
                            "runAfter": {},
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "Query Replace",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_Query_Strings": {
                            "runAfter": {
                                "Initialize_variable_-_Query_Replace": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "Query Strings",
                                        "type": "string"
                                    }
                                ]
                            }
                        }
                    },
                    "outputs": {}
                },
                "parameters": {
                    "$connections": {
                        "value": {
                            "azuresentinel_1": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/azuresentinel-1",
                                "connectionName": "azuresentinel-1",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/azuresentinel"
                            },
                            "office365_1": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/office365",
                                "connectionName": "office365",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/office365"
                            }
                        }
                    }
                }
            }
        }
    ]
}
```

</details>

[Link to the file of Alert-changes_detected_Network_interfaces_should_not_have_public_IPs_policy here](https://github.com/austin-lai/Collection-of-AzureSentinel-Playbook/blob/master/Alert-changes_detected_Network_interfaces_should_not_have_public_IPs_policy.json)

### Ingest Threat Intelligent Feed to Azure Sentinel via API Connection

In this example, we are using open source Threat Feed which is AlienVault OTX.

First create account with AlienVault OTX and get the API key.

Then register application in Azure and get the API key as well.

Next, create playbook below.

Last, enable "Threat Intelligence Platforms (Preview)" - Data Connectors in Azure Sentinel by clicking the "connect" button once previous step is completed.

<details><summary>Get-AlienVault-OTX-Threat-Indicators</summary>

```json
//  Replace "XXXXXX" to your own clientId, secrets, tenant and X-OTX-API-KEY accordingly
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.Logic/workflows",
            "apiVersion": "2017-07-01",
            "name": "Get-AlienVault-OTX-Threat-Indicators",
            "location": "southeastasia",
            "tags": {
                "LogicAppsCategory": "security"
            },
            "properties": {
                "state": "Enabled",
                "definition": {
                    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {},
                    "triggers": {
                        "Recurrence": {
                            "recurrence": {
                                "frequency": "Day",
                                "interval": 1
                            },
                            "evaluatedRecurrence": {
                                "frequency": "Day",
                                "interval": 1
                            },
                            "type": "Recurrence"
                        }
                    },
                    "actions": {
                        "For_each": {
                            "foreach": "@body('Parse_JSON')?['results']",
                            "actions": {
                                "Switch": {
                                    "runAfter": {},
                                    "cases": {
                                        "Domain": {
                                            "case": "domain",
                                            "actions": {
                                                "Sentinel_domain": {
                                                    "runAfter": {},
                                                    "type": "Http",
                                                    "inputs": {
                                                        "authentication": {
                                                            "audience": "https://graph.microsoft.com",
                                                            "clientId": "XXXXXX",
                                                            "secret": "XXXXXX",
                                                            "tenant": "XXXXXX",
                                                            "type": "ActiveDirectoryOAuth"
                                                        },
                                                        "body": {
                                                            "action": "alert",
                                                            "activityGroupNames": [],
                                                            "confidence": 100,
                                                            "description": "OTX Threat Indicator - @{items('For_each')?['type']}",
                                                            "domainName": "@{items('For_each')?['indicator']}",
                                                            "expirationDateTime": "@{addDays(utcNow(),7)}",
                                                            "externalId": "@{items('For_each')?['id']}",
                                                            "killChain": [],
                                                            "malwareFamilyNames": [],
                                                            "severity": 0,
                                                            "tags": [],
                                                            "targetProduct": "Azure Sentinel",
                                                            "threatType": "WatchList",
                                                            "tlpLevel": "white"
                                                        },
                                                        "headers": {
                                                            "content-type": "application/json"
                                                        },
                                                        "method": "POST",
                                                        "uri": "https://graph.microsoft.com/beta/security/tiIndicators"
                                                    }
                                                }
                                            }
                                        },
                                        "IPv4": {
                                            "case": "IPv4",
                                            "actions": {
                                                "Sentinel_IPv4": {
                                                    "runAfter": {},
                                                    "type": "Http",
                                                    "inputs": {
                                                        "authentication": {
                                                            "audience": "https://graph.microsoft.com",
                                                            "clientId": "XXXXXX",
                                                            "secret": "XXXXXX",
                                                            "tenant": "XXXXXX",
                                                            "type": "ActiveDirectoryOAuth"
                                                        },
                                                        "body": {
                                                            "action": "alert",
                                                            "activityGroupNames": [],
                                                            "confidence": 100,
                                                            "description": "OTX Threat Indicator - @{items('For_each')?['type']}",
                                                            "expirationDateTime": "@{addDays(utcNow(),7)}",
                                                            "externalId": "@{items('For_each')?['id']}",
                                                            "killChain": [],
                                                            "malwareFamilyNames": [],
                                                            "networkIPv4": "@{items('For_each')?['indicator']}",
                                                            "severity": 0,
                                                            "tags": [],
                                                            "targetProduct": "Azure Sentinel",
                                                            "threatType": "WatchList",
                                                            "tlpLevel": "white"
                                                        },
                                                        "headers": {
                                                            "content-type": "application/json"
                                                        },
                                                        "method": "POST",
                                                        "uri": "https://graph.microsoft.com/beta/security/tiIndicators"
                                                    }
                                                }
                                            }
                                        },
                                        "URL": {
                                            "case": "URL",
                                            "actions": {
                                                "Sentinel_URL": {
                                                    "runAfter": {},
                                                    "type": "Http",
                                                    "inputs": {
                                                        "authentication": {
                                                            "audience": "https://graph.microsoft.com",
                                                            "clientId": "XXXXXX",
                                                            "secret": "XXXXXX",
                                                            "tenant": "XXXXXX",
                                                            "type": "ActiveDirectoryOAuth"
                                                        },
                                                        "body": {
                                                            "action": "alert",
                                                            "activityGroupNames": [],
                                                            "confidence": 100,
                                                            "description": "OTX Threat Indicator - @{items('For_each')?['type']}",
                                                            "expirationDateTime": "@{addDays(utcNow(),7)}",
                                                            "externalId": "@{items('For_each')?['id']}",
                                                            "killChain": [],
                                                            "malwareFamilyNames": [],
                                                            "severity": 0,
                                                            "tags": [],
                                                            "targetProduct": "Azure Sentinel",
                                                            "threatType": "WatchList",
                                                            "tlpLevel": "white",
                                                            "url": "@{items('For_each')?['indicator']}"
                                                        },
                                                        "headers": {
                                                            "content-type": "application/json"
                                                        },
                                                        "method": "POST",
                                                        "uri": "https://graph.microsoft.com/beta/security/tiIndicators"
                                                    }
                                                }
                                            }
                                        },
                                        "email": {
                                            "case": "email",
                                            "actions": {
                                                "Sentinel_email": {
                                                    "runAfter": {},
                                                    "type": "Http",
                                                    "inputs": {
                                                        "authentication": {
                                                            "audience": "https://graph.microsoft.com",
                                                            "clientId": "XXXXXX",
                                                            "secret": "XXXXXX",
                                                            "tenant": "XXXXXX",
                                                            "type": "ActiveDirectoryOAuth"
                                                        },
                                                        "body": {
                                                            "action": "alert",
                                                            "activityGroupNames": [],
                                                            "confidence": 100,
                                                            "description": "OTX Threat Indicator - @{items('For_each')?['type']}",
                                                            "emailSenderAddress": "@{items('For_each')?['indicator']}",
                                                            "expirationDateTime": "@{addDays(utcNow(),7)}",
                                                            "externalId": "@{items('For_each')?['id']}",
                                                            "killChain": [],
                                                            "malwareFamilyNames": [],
                                                            "severity": 0,
                                                            "tags": [],
                                                            "targetProduct": "Azure Sentinel",
                                                            "threatType": "WatchList",
                                                            "tlpLevel": "white"
                                                        },
                                                        "headers": {
                                                            "content-type": "application/json"
                                                        },
                                                        "method": "POST",
                                                        "uri": "https://graph.microsoft.com/beta/security/tiIndicators"
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    "default": {
                                        "actions": {}
                                    },
                                    "expression": "@items('For_each')?['type']",
                                    "type": "Switch"
                                }
                            },
                            "runAfter": {
                                "Parse_JSON": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "HTTP": {
                            "runAfter": {},
                            "type": "Http",
                            "inputs": {
                                "headers": {
                                    "X-OTX-API-KEY": "XXXXXX"
                                },
                                "method": "GET",
                                "queries": {
                                    "modified_since": "@{addDays(utcNow(),-1)}",
                                    "types": "IPv4,domain,hostname,url,email"
                                },
                                "uri": "https://otx.alienvault.com/api/v1/indicators/export"
                            }
                        },
                        "Parse_JSON": {
                            "runAfter": {
                                "HTTP": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ParseJson",
                            "inputs": {
                                "content": "@body('HTTP')",
                                "schema": {
                                    "properties": {
                                        "count": {
                                            "type": "integer"
                                        },
                                        "next": {},
                                        "previous": {},
                                        "results": {
                                            "items": {
                                                "properties": {
                                                    "content": {
                                                        "type": "string"
                                                    },
                                                    "description": {},
                                                    "id": {
                                                        "type": "integer"
                                                    },
                                                    "indicator": {
                                                        "type": "string"
                                                    },
                                                    "title": {},
                                                    "type": {
                                                        "type": "string"
                                                    }
                                                },
                                                "required": [
                                                    "indicator",
                                                    "description",
                                                    "title",
                                                    "content",
                                                    "type",
                                                    "id"
                                                ],
                                                "type": "object"
                                            },
                                            "type": "array"
                                        }
                                    },
                                    "type": "object"
                                }
                            }
                        }
                    },
                    "outputs": {}
                },
                "parameters": {}
            }
        }
    ]
}
```

</details>

[Link to the file of Get-AlienVault-OTX-Threat-Indicators here](https://github.com/austin-lai/Collection-of-AzureSentinel-Playbook/blob/master/Get-AlienVault-OTX-Threat-Indicators.json)

### Incident based playbook - Extract UserName from detected SSH Brute Force Attack to WatchList

An analytic rule used to detect SSH Brute Force attacks and generated user list mapping to Account Entity.

Playbook will extract the user list from the result of analytic rule.

Then store in "AccountName" array variable.

It will also get all items from watchlist in parallel thread.

Then, compare "AccountName" to watchlist to determine if username found already exsited in current watchlist.

If yes, then playbook will just ignored the username.

Otherwise, it will add new item in the watchlist.

<details><summary>Incident-Extract-SSHBruteForceAttack-UserList-to-WatchList</summary>

```json
//  Replace "XXXXXX" to your own Subscription ID and Resource Group accordingly
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.Logic/workflows",
            "apiVersion": "2017-07-01",
            "name": "Incident-Extract-SSHBruteForceAttack-UserList-to-WatchList",
            "location": "southeastasia",
            "tags": {
                "LogicAppsCategory": "security",
                "hidden-SentinelTemplateName": "Watchlist-InformSubowner",
                "hidden-SentinelTemplateVersion": "1.0"
            },
            "identity": {
                "type": "SystemAssigned"
            },
            "properties": {
                "state": "Enabled",
                "definition": {
                    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {
                        "$connections": {
                            "defaultValue": {},
                            "type": "Object"
                        }
                    },
                    "triggers": {
                        "Microsoft_Sentinel_incident": {
                            "type": "ApiConnectionWebhook",
                            "inputs": {
                                "body": {
                                    "callback_url": "@{listCallbackUrl()}"
                                },
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel_1']['connectionId']"
                                    }
                                },
                                "path": "/incident-creation"
                            }
                        }
                    },
                    "actions": {
                        "Entities_-_Get_Accounts": {
                            "runAfter": {
                                "Initialize_variable_-_AccountName": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ApiConnection",
                            "inputs": {
                                "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                    }
                                },
                                "method": "post",
                                "path": "/entities/account"
                            }
                        },
                        "For_each_-_Get_Account_Name_from_Entities_and_create_array": {
                            "foreach": "@body('Entities_-_Get_Accounts')?['Accounts']",
                            "actions": {
                                "Set_variable_-_AccountName": {
                                    "runAfter": {
                                        "Set_variable_-_remove_\"": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "AccountName",
                                        "value": "@split(variables('temp2'),',')"
                                    },
                                    "description": "need to remove empty array"
                                },
                                "Set_variable_-_remove_\"": {
                                    "runAfter": {
                                        "Set_variable_-_remove_]": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "temp2",
                                        "value": "@{replace(variables('temp'),'\"','')}"
                                    }
                                },
                                "Set_variable_-_remove_[": {
                                    "runAfter": {
                                        "Set_variable_-_temp": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "temp2",
                                        "value": "@{replace(variables('temp'),'[','')}"
                                    }
                                },
                                "Set_variable_-_remove_]": {
                                    "runAfter": {
                                        "Set_variable_-_remove_[": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "temp",
                                        "value": "@{replace(variables('temp2'),']','')}"
                                    }
                                },
                                "Set_variable_-_temp": {
                                    "runAfter": {},
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "temp",
                                        "value": "@items('For_each_-_Get_Account_Name_from_Entities_and_create_array')?['Name']"
                                    }
                                }
                            },
                            "runAfter": {
                                "Entities_-_Get_Accounts": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "For_each_-_Loop_thru_AccountName_array_variable": {
                            "foreach": "@variables('AccountName')",
                            "actions": {
                                "Condition_-_Check_if_value_of_AccountName_array_variable_is_null": {
                                    "actions": {
                                        "Compose_-_True,_value_of_AccountName_array_variable_is_null": {
                                            "runAfter": {},
                                            "type": "Compose",
                                            "inputs": {
                                                "True": "True, value of AccountName array variable is null !",
                                                "Value": "@item()"
                                            }
                                        }
                                    },
                                    "runAfter": {},
                                    "else": {
                                        "actions": {
                                            "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_null": {
                                                "runAfter": {},
                                                "type": "Compose",
                                                "inputs": {
                                                    "False": "False, value of AccountName array variable is NOT null",
                                                    "Value": "@item()"
                                                }
                                            },
                                            "Condition_-_Check_value_of_AccountName_array_variable_is_in_WatchList": {
                                                "actions": {
                                                    "Compose_-_True,_value_of_AccountName_array_variable_is_in_WatchList": {
                                                        "runAfter": {},
                                                        "type": "Compose",
                                                        "inputs": {
                                                            "True": "True, value of AccountName array variable is in WatchList",
                                                            "Value": "@item()"
                                                        }
                                                    }
                                                },
                                                "runAfter": {
                                                    "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_null": [
                                                        "Succeeded"
                                                    ]
                                                },
                                                "else": {
                                                    "actions": {
                                                        "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_in_WatchList": {
                                                            "runAfter": {},
                                                            "type": "Compose",
                                                            "inputs": {
                                                                "False": "False, value of AccountName array variable is NOT in WatchList",
                                                                "Value": "@item()"
                                                            }
                                                        },
                                                        "Watchlists_-_Add_a_new_watchlist_item": {
                                                            "runAfter": {
                                                                "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_in_WatchList": [
                                                                    "Succeeded"
                                                                ]
                                                            },
                                                            "type": "ApiConnection",
                                                            "inputs": {
                                                                "body": {
                                                                    "SSHBruteForceAttacks-UserList": "@item()"
                                                                },
                                                                "host": {
                                                                    "connection": {
                                                                        "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                                                    }
                                                                },
                                                                "method": "put",
                                                                "path": "/Watchlists/subscriptions/@{encodeURIComponent(triggerBody()?['workspaceInfo']?['SubscriptionId'])}/resourceGroups/@{encodeURIComponent(triggerBody()?['workspaceInfo']?['ResourceGroupName'])}/workspaces/@{encodeURIComponent(triggerBody()?['workspaceId'])}/watchlists/@{encodeURIComponent('SSHBruteForceAttacks-UserList')}/watchlistItem"
                                                            }
                                                        }
                                                    }
                                                },
                                                "expression": {
                                                    "and": [
                                                        {
                                                            "contains": [
                                                                "@variables('watchlist-items-array')",
                                                                "@item()"
                                                            ]
                                                        }
                                                    ]
                                                },
                                                "type": "If"
                                            }
                                        }
                                    },
                                    "expression": {
                                        "and": [
                                            {
                                                "equals": [
                                                    "@item()",
                                                    ""
                                                ]
                                            }
                                        ]
                                    },
                                    "type": "If"
                                }
                            },
                            "runAfter": {
                                "For_each_-_Get_Account_Name_from_Entities_and_create_array": [
                                    "Succeeded"
                                ],
                                "For_each_-_create_array_from_watchlist-items-value": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "For_each_-_create_array_from_watchlist-items-value": {
                            "foreach": "@body('Parse_JSON_-_watchlist-items')?['properties']?['watchlistItems']",
                            "actions": {
                                "Append_to_array_variable_-_watchlist-items-value": {
                                    "runAfter": {},
                                    "type": "AppendToArrayVariable",
                                    "inputs": {
                                        "name": "watchlist-items-array",
                                        "value": "@items('For_each_-_create_array_from_watchlist-items-value')?['properties.itemsKeyValue']?['SSHBruteForceAttacks-UserList']"
                                    }
                                }
                            },
                            "runAfter": {
                                "Parse_JSON_-_watchlist-items": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "Initialize_variable_-_AccountName": {
                            "runAfter": {
                                "Initialize_variable_-_temp2": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "AccountName",
                                        "type": "array"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_temp": {
                            "runAfter": {},
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "temp",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_temp2": {
                            "runAfter": {
                                "Initialize_variable_-_temp": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "temp2",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_watchlist-items-array": {
                            "runAfter": {},
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "watchlist-items-array",
                                        "type": "array"
                                    }
                                ]
                            }
                        },
                        "Parse_JSON_-_watchlist-items": {
                            "runAfter": {
                                "Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ParseJson",
                            "inputs": {
                                "content": "@body('Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist')",
                                "schema": {
                                    "properties": {
                                        "id": {
                                            "type": "string"
                                        },
                                        "properties": {
                                            "properties": {
                                                "watchlistItems": {
                                                    "items": {
                                                        "properties": {
                                                            "etag": {
                                                                "type": "string"
                                                            },
                                                            "id": {
                                                                "type": "string"
                                                            },
                                                            "name": {
                                                                "type": "string"
                                                            },
                                                            "properties.created": {
                                                                "type": "string"
                                                            },
                                                            "properties.createdBy": {
                                                                "properties": {
                                                                    "email": {
                                                                        "type": "string"
                                                                    },
                                                                    "name": {
                                                                        "type": "string"
                                                                    },
                                                                    "objectId": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.entityMapping": {
                                                                "properties": {},
                                                                "type": "object"
                                                            },
                                                            "properties.isDeleted": {
                                                                "type": "boolean"
                                                            },
                                                            "properties.itemsKeyValue": {
                                                                "properties": {
                                                                    "SSHBruteForceAttacks-UserList": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.tenantId": {
                                                                "type": "string"
                                                            },
                                                            "properties.updated": {
                                                                "type": "string"
                                                            },
                                                            "properties.updatedBy": {
                                                                "properties": {
                                                                    "email": {
                                                                        "type": "string"
                                                                    },
                                                                    "name": {
                                                                        "type": "string"
                                                                    },
                                                                    "objectId": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.watchlistItemId": {
                                                                "type": "string"
                                                            },
                                                            "properties.watchlistItemType": {
                                                                "type": "string"
                                                            },
                                                            "systemData": {
                                                                "properties": {
                                                                    "createdAt": {
                                                                        "type": "string"
                                                                    },
                                                                    "createdBy": {
                                                                        "type": "string"
                                                                    },
                                                                    "createdByType": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedAt": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedBy": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedByType": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "type": {
                                                                "type": "string"
                                                            }
                                                        },
                                                        "required": [
                                                            "properties.watchlistItemType",
                                                            "properties.watchlistItemId",
                                                            "properties.tenantId",
                                                            "properties.isDeleted",
                                                            "properties.created",
                                                            "properties.updated",
                                                            "properties.createdBy",
                                                            "properties.updatedBy",
                                                            "properties.itemsKeyValue",
                                                            "properties.entityMapping",
                                                            "etag",
                                                            "id",
                                                            "name",
                                                            "type",
                                                            "systemData"
                                                        ],
                                                        "type": "object"
                                                    },
                                                    "type": "array"
                                                }
                                            },
                                            "type": "object"
                                        },
                                        "type": {
                                            "type": "string"
                                        }
                                    },
                                    "type": "object"
                                }
                            }
                        },
                        "Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist": {
                            "runAfter": {
                                "Initialize_variable_-_watchlist-items-array": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ApiConnection",
                            "inputs": {
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                    }
                                },
                                "method": "get",
                                "path": "/Watchlists/subscriptions/@{encodeURIComponent(triggerBody()?['workspaceInfo']?['SubscriptionId'])}/resourceGroups/@{encodeURIComponent(triggerBody()?['workspaceInfo']?['ResourceGroupName'])}/workspaces/@{encodeURIComponent(triggerBody()?['workspaceId'])}/watchlists/@{encodeURIComponent('SSHBruteForceAttacks-UserList')}/watchlistItems"
                            }
                        }
                    },
                    "outputs": {}
                },
                "parameters": {
                    "$connections": {
                        "value": {
                            "azuresentinel": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/azuresentinel",
                                "connectionName": "azuresentinel",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/azuresentinel"
                            },
                            "azuresentinel_1": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/azuresentinel-1",
                                "connectionName": "azuresentinel-1",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/azuresentinel"
                            }
                        }
                    }
                }
            }
        }
    ]
}
```

</details>

[Link to the file of Incident-Extract-SSHBruteForceAttack-UserList-to-WatchList here](https://github.com/austin-lai/Collection-of-AzureSentinel-Playbook/blob/master/Incident-Extract-SSHBruteForceAttack-UserList-to-WatchList.json)

<details><summary>Incident-Extract-SSHBruteForceAttack-UserList-to-WatchList - Version 2</summary>

    
    Version 2 improve extraction of SSH username:

        - extract ssh username from Account Entity and append all to "temp" string variable
        - using "temp" string variable to perform data processing and ultimately split the string by "," (comma) into array

```json
//  Replace "XXXXXX" to your own Subscription ID and Resource Group accordingly
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.Logic/workflows",
            "apiVersion": "2017-07-01",
            "name": "Incident-Extract-SSHBruteForceAttack-UserList-to-WatchList",
            "location": "southeastasia",
            "tags": {
                "LogicAppsCategory": "security",
                "hidden-SentinelTemplateName": "Watchlist-InformSubowner",
                "hidden-SentinelTemplateVersion": "1.0"
            },
            "identity": {
                "type": "SystemAssigned"
            },
            "properties": {
                "state": "Enabled",
                "definition": {
                    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {
                        "$connections": {
                            "defaultValue": {},
                            "type": "Object"
                        }
                    },
                    "triggers": {
                        "Microsoft_Sentinel_incident": {
                            "type": "ApiConnectionWebhook",
                            "inputs": {
                                "body": {
                                    "callback_url": "@{listCallbackUrl()}"
                                },
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel_1']['connectionId']"
                                    }
                                },
                                "path": "/incident-creation"
                            }
                        }
                    },
                    "actions": {
                        "Compose_-_checking_variable_\"temp\"": {
                            "runAfter": {
                                "For_each_-_Get_Account_Name_from_Entities_and_create_array": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Compose",
                            "inputs": {
                                "temp": "@variables('temp')"
                            }
                        },
                        "Entities_-_Get_Accounts": {
                            "runAfter": {
                                "Initialize_variable_-_AccountName": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ApiConnection",
                            "inputs": {
                                "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                    }
                                },
                                "method": "post",
                                "path": "/entities/account"
                            }
                        },
                        "For_each_-_Get_Account_Name_from_Entities_and_create_array": {
                            "foreach": "@body('Entities_-_Get_Accounts')?['Accounts']",
                            "actions": {
                                "Append_to_string_variable_-_temp": {
                                    "runAfter": {},
                                    "type": "AppendToStringVariable",
                                    "inputs": {
                                        "name": "temp",
                                        "value": "@items('For_each_-_Get_Account_Name_from_Entities_and_create_array')?['Name']"
                                    }
                                }
                            },
                            "runAfter": {
                                "Entities_-_Get_Accounts": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "For_each_-_Loop_thru_AccountName_array_variable": {
                            "foreach": "@variables('AccountName')",
                            "actions": {
                                "Condition_-_Check_if_value_of_AccountName_array_variable_is_null": {
                                    "actions": {
                                        "Compose_-_True,_value_of_AccountName_array_variable_is_null": {
                                            "runAfter": {},
                                            "type": "Compose",
                                            "inputs": {
                                                "True": "True, value of AccountName array variable is null !",
                                                "Value": "@item()"
                                            }
                                        }
                                    },
                                    "runAfter": {},
                                    "else": {
                                        "actions": {
                                            "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_null": {
                                                "runAfter": {},
                                                "type": "Compose",
                                                "inputs": {
                                                    "False": "False, value of AccountName array variable is NOT null",
                                                    "Value": "@item()"
                                                }
                                            },
                                            "Condition_-_Check_value_of_AccountName_array_variable_is_in_WatchList": {
                                                "actions": {
                                                    "Compose_-_True,_value_of_AccountName_array_variable_is_in_WatchList": {
                                                        "runAfter": {},
                                                        "type": "Compose",
                                                        "inputs": {
                                                            "True": "True, value of AccountName array variable is in WatchList",
                                                            "Value": "@item()"
                                                        }
                                                    }
                                                },
                                                "runAfter": {
                                                    "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_null": [
                                                        "Succeeded"
                                                    ]
                                                },
                                                "else": {
                                                    "actions": {
                                                        "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_in_WatchList": {
                                                            "runAfter": {},
                                                            "type": "Compose",
                                                            "inputs": {
                                                                "False": "False, value of AccountName array variable is NOT in WatchList",
                                                                "Value": "@item()"
                                                            }
                                                        },
                                                        "Watchlists_-_Add_a_new_watchlist_item": {
                                                            "runAfter": {
                                                                "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_in_WatchList": [
                                                                    "Succeeded"
                                                                ]
                                                            },
                                                            "type": "ApiConnection",
                                                            "inputs": {
                                                                "body": {
                                                                    "SSHBruteForceAttacks-UserList": "@item()"
                                                                },
                                                                "host": {
                                                                    "connection": {
                                                                        "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                                                    }
                                                                },
                                                                "method": "put",
                                                                "path": "/Watchlists/subscriptions/@{encodeURIComponent(triggerBody()?['workspaceInfo']?['SubscriptionId'])}/resourceGroups/@{encodeURIComponent(triggerBody()?['workspaceInfo']?['ResourceGroupName'])}/workspaces/@{encodeURIComponent(triggerBody()?['workspaceId'])}/watchlists/@{encodeURIComponent('SSHBruteForceAttacks-UserList')}/watchlistItem"
                                                            }
                                                        }
                                                    }
                                                },
                                                "expression": {
                                                    "and": [
                                                        {
                                                            "contains": [
                                                                "@variables('watchlist-items-array')",
                                                                "@item()"
                                                            ]
                                                        }
                                                    ]
                                                },
                                                "type": "If"
                                            }
                                        }
                                    },
                                    "expression": {
                                        "and": [
                                            {
                                                "equals": [
                                                    "@item()",
                                                    ""
                                                ]
                                            }
                                        ]
                                    },
                                    "type": "If"
                                }
                            },
                            "runAfter": {
                                "For_each_-_create_array_from_watchlist-items-value": [
                                    "Succeeded"
                                ],
                                "Set_variable_-_AccountName": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "For_each_-_create_array_from_watchlist-items-value": {
                            "foreach": "@body('Parse_JSON_-_watchlist-items')?['properties']?['watchlistItems']",
                            "actions": {
                                "Append_to_array_variable_-_watchlist-items-value": {
                                    "runAfter": {},
                                    "type": "AppendToArrayVariable",
                                    "inputs": {
                                        "name": "watchlist-items-array",
                                        "value": "@items('For_each_-_create_array_from_watchlist-items-value')?['properties.itemsKeyValue']?['SSHBruteForceAttacks-UserList']"
                                    }
                                }
                            },
                            "runAfter": {
                                "Parse_JSON_-_watchlist-items": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "Initialize_variable_-_AccountName": {
                            "runAfter": {
                                "Initialize_variable_-_temp2": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "AccountName",
                                        "type": "array"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_temp": {
                            "runAfter": {},
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "temp",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_temp2": {
                            "runAfter": {
                                "Initialize_variable_-_temp": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "temp2",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_watchlist-items-array": {
                            "runAfter": {},
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "watchlist-items-array",
                                        "type": "array"
                                    }
                                ]
                            }
                        },
                        "Parse_JSON_-_watchlist-items": {
                            "runAfter": {
                                "Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ParseJson",
                            "inputs": {
                                "content": "@body('Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist')",
                                "schema": {
                                    "properties": {
                                        "id": {
                                            "type": "string"
                                        },
                                        "properties": {
                                            "properties": {
                                                "watchlistItems": {
                                                    "items": {
                                                        "properties": {
                                                            "etag": {
                                                                "type": "string"
                                                            },
                                                            "id": {
                                                                "type": "string"
                                                            },
                                                            "name": {
                                                                "type": "string"
                                                            },
                                                            "properties.created": {
                                                                "type": "string"
                                                            },
                                                            "properties.createdBy": {
                                                                "properties": {
                                                                    "email": {
                                                                        "type": "string"
                                                                    },
                                                                    "name": {
                                                                        "type": "string"
                                                                    },
                                                                    "objectId": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.entityMapping": {
                                                                "properties": {},
                                                                "type": "object"
                                                            },
                                                            "properties.isDeleted": {
                                                                "type": "boolean"
                                                            },
                                                            "properties.itemsKeyValue": {
                                                                "properties": {
                                                                    "SSHBruteForceAttacks-UserList": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.tenantId": {
                                                                "type": "string"
                                                            },
                                                            "properties.updated": {
                                                                "type": "string"
                                                            },
                                                            "properties.updatedBy": {
                                                                "properties": {
                                                                    "email": {
                                                                        "type": "string"
                                                                    },
                                                                    "name": {
                                                                        "type": "string"
                                                                    },
                                                                    "objectId": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.watchlistItemId": {
                                                                "type": "string"
                                                            },
                                                            "properties.watchlistItemType": {
                                                                "type": "string"
                                                            },
                                                            "systemData": {
                                                                "properties": {
                                                                    "createdAt": {
                                                                        "type": "string"
                                                                    },
                                                                    "createdBy": {
                                                                        "type": "string"
                                                                    },
                                                                    "createdByType": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedAt": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedBy": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedByType": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "type": {
                                                                "type": "string"
                                                            }
                                                        },
                                                        "required": [
                                                            "properties.watchlistItemType",
                                                            "properties.watchlistItemId",
                                                            "properties.tenantId",
                                                            "properties.isDeleted",
                                                            "properties.created",
                                                            "properties.updated",
                                                            "properties.createdBy",
                                                            "properties.updatedBy",
                                                            "properties.itemsKeyValue",
                                                            "properties.entityMapping",
                                                            "etag",
                                                            "id",
                                                            "name",
                                                            "type",
                                                            "systemData"
                                                        ],
                                                        "type": "object"
                                                    },
                                                    "type": "array"
                                                }
                                            },
                                            "type": "object"
                                        },
                                        "type": {
                                            "type": "string"
                                        }
                                    },
                                    "type": "object"
                                }
                            }
                        },
                        "Set_variable_-_AccountName": {
                            "runAfter": {
                                "Set_variable_-_remove_\"": [
                                    "Succeeded"
                                ]
                            },
                            "type": "SetVariable",
                            "inputs": {
                                "name": "AccountName",
                                "value": "@split(variables('temp2'),',')"
                            },
                            "description": "need to remove empty array"
                        },
                        "Set_variable_-_remove_\"": {
                            "runAfter": {
                                "Set_variable_-_remove_]": [
                                    "Succeeded"
                                ]
                            },
                            "type": "SetVariable",
                            "inputs": {
                                "name": "temp2",
                                "value": "@{replace(variables('temp'),'\"',',')}"
                            }
                        },
                        "Set_variable_-_remove_[": {
                            "runAfter": {
                                "Compose_-_checking_variable_\"temp\"": [
                                    "Succeeded"
                                ]
                            },
                            "type": "SetVariable",
                            "inputs": {
                                "name": "temp2",
                                "value": "@{replace(variables('temp'),'[','')}"
                            }
                        },
                        "Set_variable_-_remove_]": {
                            "runAfter": {
                                "Set_variable_-_remove_[": [
                                    "Succeeded"
                                ]
                            },
                            "type": "SetVariable",
                            "inputs": {
                                "name": "temp",
                                "value": "@{replace(variables('temp2'),']','')}"
                            }
                        },
                        "Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist": {
                            "runAfter": {
                                "Initialize_variable_-_watchlist-items-array": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ApiConnection",
                            "inputs": {
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                    }
                                },
                                "method": "get",
                                "path": "/Watchlists/subscriptions/@{encodeURIComponent(triggerBody()?['workspaceInfo']?['SubscriptionId'])}/resourceGroups/@{encodeURIComponent(triggerBody()?['workspaceInfo']?['ResourceGroupName'])}/workspaces/@{encodeURIComponent(triggerBody()?['workspaceId'])}/watchlists/@{encodeURIComponent('SSHBruteForceAttacks-UserList')}/watchlistItems"
                            }
                        }
                    },
                    "outputs": {}
                },
                "parameters": {
                    "$connections": {
                        "value": {
                            "azuresentinel": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/azuresentinel",
                                "connectionName": "azuresentinel",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/azuresentinel"
                            },
                            "azuresentinel_1": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/azuresentinel-1",
                                "connectionName": "azuresentinel-1",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/azuresentinel"
                            }
                        }
                    }
                }
            }
        }
    ]
}
```

</details>

[Link to the file of Incident-Extract-SSHBruteForceAttack-UserList-to-WatchList - Version 2 here](https://github.com/austin-lai/Collection-of-AzureSentinel-Playbook/blob/master/Incident-Extract-SSHBruteForceAttack-UserList-to-WatchList-version2.json)

### Alert based playbook - Extract UserName from detected SSH Brute Force Attack to WatchList

<details><summary>Alert-Extract-SSHBruteForceAttack-UserList-to-WatchList</summary>

```json
//  Replace "XXXXXX" to your own Subscription ID and Resource Group accordingly
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {},
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.Logic/workflows",
            "apiVersion": "2017-07-01",
            "name": "Alert-Extract-SSHBruteForceAttack-UserList-to-WatchList",
            "location": "southeastasia",
            "properties": {
                "state": "Enabled",
                "definition": {
                    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {
                        "$connections": {
                            "defaultValue": {},
                            "type": "Object"
                        }
                    },
                    "triggers": {
                        "Microsoft_Sentinel_alert": {
                            "type": "ApiConnectionWebhook",
                            "inputs": {
                                "body": {
                                    "callback_url": "@{listCallbackUrl()}"
                                },
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel_1']['connectionId']"
                                    }
                                },
                                "path": "/subscribe"
                            }
                        }
                    },
                    "actions": {
                        "For_each_-_Loop_thru_AccountName_array_variable": {
                            "foreach": "@variables('AccountName')",
                            "actions": {
                                "Condition_-_Check_if_value_of_AccountName_array_variable_is_null": {
                                    "actions": {
                                        "Compose_-_True,_value_of_AccountName_array_variable_is_null": {
                                            "runAfter": {},
                                            "type": "Compose",
                                            "inputs": {
                                                "True": "True, value of AccountName array variable is null !",
                                                "Value": "@item()"
                                            }
                                        }
                                    },
                                    "runAfter": {},
                                    "else": {
                                        "actions": {
                                            "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_null": {
                                                "runAfter": {},
                                                "type": "Compose",
                                                "inputs": {
                                                    "False": "False, value of AccountName array variable is NOT null",
                                                    "Value": "@item()"
                                                }
                                            },
                                            "Condition_-_Check_value_of_AccountName_array_variable_is_in_WatchList": {
                                                "actions": {
                                                    "Compose_-_True,_value_of_AccountName_array_variable_is_in_WatchList": {
                                                        "runAfter": {},
                                                        "type": "Compose",
                                                        "inputs": {
                                                            "True": "True, value of AccountName array variable is in WatchList",
                                                            "Value": "@item()"
                                                        }
                                                    }
                                                },
                                                "runAfter": {
                                                    "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_null": [
                                                        "Succeeded"
                                                    ]
                                                },
                                                "else": {
                                                    "actions": {
                                                        "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_in_WatchList": {
                                                            "runAfter": {},
                                                            "type": "Compose",
                                                            "inputs": {
                                                                "False": "False, value of AccountName array variable is NOT in WatchList",
                                                                "Value": "@item()"
                                                            }
                                                        },
                                                        "Watchlists_-_Add_a_new_watchlist_item": {
                                                            "runAfter": {
                                                                "Compose_-_False,_value_of_AccountName_array_variable_is_NOT_in_WatchList": [
                                                                    "Succeeded"
                                                                ]
                                                            },
                                                            "type": "ApiConnection",
                                                            "inputs": {
                                                                "body": {
                                                                    "SSHBruteForceAttacks-UserList": "@item()"
                                                                },
                                                                "host": {
                                                                    "connection": {
                                                                        "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                                                    }
                                                                },
                                                                "method": "put",
                                                                "path": "/Watchlists/subscriptions/@{encodeURIComponent(triggerBody()?['WorkspaceSubscriptionId'])}/resourceGroups/@{encodeURIComponent(triggerBody()?['WorkspaceResourceGroup'])}/workspaces/@{encodeURIComponent(triggerBody()?['WorkspaceId'])}/watchlists/@{encodeURIComponent('SSHBruteForceAttacks-UserList')}/watchlistItem"
                                                            }
                                                        }
                                                    }
                                                },
                                                "expression": {
                                                    "and": [
                                                        {
                                                            "contains": [
                                                                "@variables('watchlist-items-array')",
                                                                "@item()"
                                                            ]
                                                        }
                                                    ]
                                                },
                                                "type": "If"
                                            }
                                        }
                                    },
                                    "expression": {
                                        "and": [
                                            {
                                                "equals": [
                                                    "@item()",
                                                    ""
                                                ]
                                            }
                                        ]
                                    },
                                    "type": "If"
                                }
                            },
                            "runAfter": {
                                "Run_if_Alert_Name_with_\"SSH_-_Potential_Brute_Force\"": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "For_each_-_create_array_from_watchlist-items-value": {
                            "foreach": "@body('Parse_JSON_-_watchlist-items')?['properties']?['watchlistItems']",
                            "actions": {
                                "Append_to_array_variable_-_watchlist-items-value": {
                                    "runAfter": {},
                                    "type": "AppendToArrayVariable",
                                    "inputs": {
                                        "name": "watchlist-items-array",
                                        "value": "@items('For_each_-_create_array_from_watchlist-items-value')?['properties.itemsKeyValue']?['SSHBruteForceAttacks-UserList']"
                                    }
                                }
                            },
                            "runAfter": {
                                "Parse_JSON_-_watchlist-items": [
                                    "Succeeded"
                                ]
                            },
                            "type": "Foreach"
                        },
                        "Initialize_variable_-_AccountName": {
                            "runAfter": {
                                "Initialize_variable_-_temp2": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "AccountName",
                                        "type": "array"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_temp": {
                            "runAfter": {},
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "temp",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_temp2": {
                            "runAfter": {
                                "Initialize_variable_-_temp": [
                                    "Succeeded"
                                ]
                            },
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "temp2",
                                        "type": "string"
                                    }
                                ]
                            }
                        },
                        "Initialize_variable_-_watchlist-items-array": {
                            "runAfter": {},
                            "type": "InitializeVariable",
                            "inputs": {
                                "variables": [
                                    {
                                        "name": "watchlist-items-array",
                                        "type": "array"
                                    }
                                ]
                            }
                        },
                        "Parse_JSON_-_watchlist-items": {
                            "runAfter": {
                                "Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ParseJson",
                            "inputs": {
                                "content": "@body('Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist')",
                                "schema": {
                                    "properties": {
                                        "id": {
                                            "type": "string"
                                        },
                                        "properties": {
                                            "properties": {
                                                "watchlistItems": {
                                                    "items": {
                                                        "properties": {
                                                            "etag": {
                                                                "type": "string"
                                                            },
                                                            "id": {
                                                                "type": "string"
                                                            },
                                                            "name": {
                                                                "type": "string"
                                                            },
                                                            "properties.created": {
                                                                "type": "string"
                                                            },
                                                            "properties.createdBy": {
                                                                "properties": {
                                                                    "email": {
                                                                        "type": "string"
                                                                    },
                                                                    "name": {
                                                                        "type": "string"
                                                                    },
                                                                    "objectId": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.entityMapping": {
                                                                "properties": {},
                                                                "type": "object"
                                                            },
                                                            "properties.isDeleted": {
                                                                "type": "boolean"
                                                            },
                                                            "properties.itemsKeyValue": {
                                                                "properties": {
                                                                    "SSHBruteForceAttacks-UserList": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.tenantId": {
                                                                "type": "string"
                                                            },
                                                            "properties.updated": {
                                                                "type": "string"
                                                            },
                                                            "properties.updatedBy": {
                                                                "properties": {
                                                                    "email": {
                                                                        "type": "string"
                                                                    },
                                                                    "name": {
                                                                        "type": "string"
                                                                    },
                                                                    "objectId": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "properties.watchlistItemId": {
                                                                "type": "string"
                                                            },
                                                            "properties.watchlistItemType": {
                                                                "type": "string"
                                                            },
                                                            "systemData": {
                                                                "properties": {
                                                                    "createdAt": {
                                                                        "type": "string"
                                                                    },
                                                                    "createdBy": {
                                                                        "type": "string"
                                                                    },
                                                                    "createdByType": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedAt": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedBy": {
                                                                        "type": "string"
                                                                    },
                                                                    "lastModifiedByType": {
                                                                        "type": "string"
                                                                    }
                                                                },
                                                                "type": "object"
                                                            },
                                                            "type": {
                                                                "type": "string"
                                                            }
                                                        },
                                                        "required": [
                                                            "properties.watchlistItemType",
                                                            "properties.watchlistItemId",
                                                            "properties.tenantId",
                                                            "properties.isDeleted",
                                                            "properties.created",
                                                            "properties.updated",
                                                            "properties.createdBy",
                                                            "properties.updatedBy",
                                                            "properties.itemsKeyValue",
                                                            "properties.entityMapping",
                                                            "etag",
                                                            "id",
                                                            "name",
                                                            "type",
                                                            "systemData"
                                                        ],
                                                        "type": "object"
                                                    },
                                                    "type": "array"
                                                }
                                            },
                                            "type": "object"
                                        },
                                        "type": {
                                            "type": "string"
                                        }
                                    },
                                    "type": "object"
                                }
                            }
                        },
                        "Run_if_Alert_Name_with_\"SSH_-_Potential_Brute_Force\"": {
                            "actions": {
                                "Compose_-_checking_variable_\"temp\"": {
                                    "runAfter": {
                                        "For_each_-_Get_Account_Name_from_Entities_and_create_array": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "Compose",
                                    "inputs": {
                                        "temp": "@variables('temp')"
                                    }
                                },
                                "Entities_-_Get_Accounts": {
                                    "runAfter": {},
                                    "type": "ApiConnection",
                                    "inputs": {
                                        "body": "@triggerBody()?['Entities']",
                                        "host": {
                                            "connection": {
                                                "name": "@parameters('$connections')['azuresentinel_1']['connectionId']"
                                            }
                                        },
                                        "method": "post",
                                        "path": "/entities/account"
                                    }
                                },
                                "For_each_-_Get_Account_Name_from_Entities_and_create_array": {
                                    "foreach": "@body('Entities_-_Get_Accounts')?['Accounts']",
                                    "actions": {
                                        "Append_to_string_variable_-_temp": {
                                            "runAfter": {},
                                            "type": "AppendToStringVariable",
                                            "inputs": {
                                                "name": "temp",
                                                "value": "@items('For_each_-_Get_Account_Name_from_Entities_and_create_array')?['Name']"
                                            }
                                        }
                                    },
                                    "runAfter": {
                                        "Entities_-_Get_Accounts": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "Foreach"
                                },
                                "Set_variable_-_AccountName": {
                                    "runAfter": {
                                        "Set_variable_-_remove_\"": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "AccountName",
                                        "value": "@split(variables('temp2'),',')"
                                    },
                                    "description": "need to remove empty array"
                                },
                                "Set_variable_-_remove_\"": {
                                    "runAfter": {
                                        "Set_variable_-_remove_]": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "temp2",
                                        "value": "@{replace(variables('temp'),'\"',',')}"
                                    }
                                },
                                "Set_variable_-_remove_[": {
                                    "runAfter": {
                                        "Compose_-_checking_variable_\"temp\"": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "temp2",
                                        "value": "@{replace(variables('temp'),'[','')}"
                                    }
                                },
                                "Set_variable_-_remove_]": {
                                    "runAfter": {
                                        "Set_variable_-_remove_[": [
                                            "Succeeded"
                                        ]
                                    },
                                    "type": "SetVariable",
                                    "inputs": {
                                        "name": "temp",
                                        "value": "@{replace(variables('temp2'),']','')}"
                                    }
                                }
                            },
                            "runAfter": {
                                "For_each_-_create_array_from_watchlist-items-value": [
                                    "Succeeded"
                                ],
                                "Initialize_variable_-_AccountName": [
                                    "Succeeded"
                                ]
                            },
                            "expression": {
                                "or": [
                                    {
                                        "contains": [
                                            "@triggerBody()?['AlertDisplayName']",
                                            "SSH - Potential Brute Force"
                                        ]
                                    }
                                ]
                            },
                            "type": "If"
                        },
                        "Watchlists_-_Get_all_watchlist_Items_for_a_given_watchlist": {
                            "runAfter": {
                                "Initialize_variable_-_watchlist-items-array": [
                                    "Succeeded"
                                ]
                            },
                            "type": "ApiConnection",
                            "inputs": {
                                "host": {
                                    "connection": {
                                        "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                                    }
                                },
                                "method": "get",
                                "path": "/Watchlists/subscriptions/@{encodeURIComponent(triggerBody()?['WorkspaceSubscriptionId'])}/resourceGroups/@{encodeURIComponent(triggerBody()?['WorkspaceResourceGroup'])}/workspaces/@{encodeURIComponent(triggerBody()?['WorkspaceId'])}/watchlists/@{encodeURIComponent('SSHBruteForceAttacks-UserList')}/watchlistItems"
                            }
                        }
                    },
                    "outputs": {}
                },
                "parameters": {
                    "$connections": {
                        "value": {
                            "azuresentinel": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/azuresentinel",
                                "connectionName": "azuresentinel",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/azuresentinel"
                            },
                            "azuresentinel_1": {
                                "connectionId": "/subscriptions/XXXXXX/resourceGroups/XXXXXX/providers/Microsoft.Web/connections/azuresentinel-1",
                                "connectionName": "azuresentinel-1",
                                "id": "/subscriptions/XXXXXX/providers/Microsoft.Web/locations/southeastasia/managedApis/azuresentinel"
                            }
                        }
                    }
                }
            }
        }
    ]
}
```

</details>

[Link to the file of Alert-Extract-SSHBruteForceAttack-UserList-to-WatchList here](https://github.com/austin-lai/Collection-of-AzureSentinel-Playbook/blob/master/Alert-Extract-SSHBruteForceAttack-UserList-to-WatchList.json)

<br />

---

> Do let me know any command or step can be improve or you have any question you can contact me via THM message or write down comment below or via FB
