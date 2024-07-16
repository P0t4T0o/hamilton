package msgraph

import (
	"encoding/json"
	"fmt"
	"time"
)

////////// device management from: https://github.com/microsoftgraph/msgraph-metadata/blob/master/openapi/v1.0/openapi.yaml

// DeviceManagement struct for DeviceManagement
type DeviceManagement struct {
	Entity
	DeviceProtectionOverview *DeviceManagementDeviceProtectionOverview `json:"deviceProtectionOverview,omitempty"`
	// Intune Account Id for given tenant
	IntuneAccountId                  *string                                           `json:"intuneAccountId,omitempty"`
	IntuneBrand                      *DeviceManagementIntuneBrand                      `json:"intuneBrand,omitempty"`
	Settings                         *DeviceManagementSettings                         `json:"settings,omitempty"`
	SubscriptionState                *DeviceManagementSubscriptionState                `json:"subscriptionState,omitempty"`
	UserExperienceAnalyticsSettings  *DeviceManagementUserExperienceAnalyticsSettings  `json:"userExperienceAnalyticsSettings,omitempty"`
	WindowsMalwareOverview           *DeviceManagementWindowsMalwareOverview           `json:"windowsMalwareOverview,omitempty"`
	ApplePushNotificationCertificate *DeviceManagementApplePushNotificationCertificate `json:"applePushNotificationCertificate,omitempty"`
	// The Audit Events
	AuditEvents []AuditEvent `json:"auditEvents,omitempty"`
	// The list of Compliance Management Partners configured by the tenant.
	ComplianceManagementPartners []ComplianceManagementPartner        `json:"complianceManagementPartners,omitempty"`
	ConditionalAccessSettings    *OnPremisesConditionalAccessSettings `json:"conditionalAccessSettings,omitempty"`
	// The list of detected apps associated with a device.
	DetectedApps []DetectedApp `json:"detectedApps,omitempty"`
	// The list of device categories with the tenant.
	DeviceCategories []DeviceCategory `json:"deviceCategories,omitempty"`
	// The device compliance policies.
	DeviceCompliancePolicies                 []DeviceCompliancePolicy                  `json:"deviceCompliancePolicies,omitempty"`
	DeviceCompliancePolicyDeviceStateSummary *DeviceCompliancePolicyDeviceStateSummary `json:"deviceCompliancePolicyDeviceStateSummary,omitempty"`
	// The summary states of compliance policy settings for this account.
	DeviceCompliancePolicySettingStateSummaries []DeviceCompliancePolicySettingStateSummary `json:"deviceCompliancePolicySettingStateSummaries,omitempty"`
	DeviceConfigurationDeviceStateSummaries     *DeviceConfigurationDeviceStateSummary      `json:"deviceConfigurationDeviceStateSummaries,omitempty"`
	// The device configurations.
	DeviceConfigurations []DeviceConfiguration `json:"deviceConfigurations,omitempty"`
	// The list of device enrollment configurations
	DeviceEnrollmentConfigurations []DeviceEnrollmentConfiguration `json:"deviceEnrollmentConfigurations,omitempty"`
	// The list of Device Management Partners configured by the tenant.
	DeviceManagementPartners []DeviceManagementPartner `json:"deviceManagementPartners,omitempty"`
	// The list of Exchange Connectors configured by the tenant.
	ExchangeConnectors []DeviceManagementExchangeConnector `json:"exchangeConnectors,omitempty"`
	// Collection of imported Windows autopilot devices.
	ImportedWindowsAutopilotDeviceIdentities []ImportedWindowsAutopilotDeviceIdentity `json:"importedWindowsAutopilotDeviceIdentities,omitempty"`
	// The IOS software update installation statuses for this account.
	IosUpdateStatuses     []IosUpdateDeviceStatus                `json:"iosUpdateStatuses,omitempty"`
	ManagedDeviceOverview *DeviceManagementManagedDeviceOverview `json:"managedDeviceOverview,omitempty"`
	// The list of managed devices.
	ManagedDevices []ManagedDevice `json:"managedDevices,omitempty"`
	// The collection property of MobileAppTroubleshootingEvent.
	MobileAppTroubleshootingEvents []MobileAppTroubleshootingEvent `json:"mobileAppTroubleshootingEvents,omitempty"`
	// The list of Mobile threat Defense connectors configured by the tenant.
	MobileThreatDefenseConnectors []MobileThreatDefenseConnector `json:"mobileThreatDefenseConnectors,omitempty"`
	// The Notification Message Templates.
	NotificationMessageTemplates []NotificationMessageTemplate `json:"notificationMessageTemplates,omitempty"`
	// The remote assist partners.
	RemoteAssistancePartners []RemoteAssistancePartner `json:"remoteAssistancePartners,omitempty"`
	Reports                  *DeviceManagementReports  `json:"reports,omitempty"`
	// The Resource Operations.
	ResourceOperations []ResourceOperation `json:"resourceOperations,omitempty"`
	// The Role Assignments.
	RoleAssignments []DeviceAndAppManagementRoleAssignment `json:"roleAssignments,omitempty"`
	// The Role Definitions.
	RoleDefinitions             []RoleDefinition             `json:"roleDefinitions,omitempty"`
	SoftwareUpdateStatusSummary *SoftwareUpdateStatusSummary `json:"softwareUpdateStatusSummary,omitempty"`
	// The telecom expense management partners.
	TelecomExpenseManagementPartners []TelecomExpenseManagementPartner `json:"telecomExpenseManagementPartners,omitempty"`
	// The terms and conditions associated with device management of the company.
	TermsAndConditions []TermsAndConditions `json:"termsAndConditions,omitempty"`
	// The list of troubleshooting events for the tenant.
	TroubleshootingEvents []DeviceManagementTroubleshootingEvent `json:"troubleshootingEvents,omitempty"`
	// User experience analytics appHealth Application Performance
	UserExperienceAnalyticsAppHealthApplicationPerformance []UserExperienceAnalyticsAppHealthApplicationPerformance `json:"userExperienceAnalyticsAppHealthApplicationPerformance,omitempty"`
	// User experience analytics appHealth Application Performance by App Version details
	UserExperienceAnalyticsAppHealthApplicationPerformanceByAppVersionDetails []UserExperienceAnalyticsAppHealthAppPerformanceByAppVersionDetails `json:"userExperienceAnalyticsAppHealthApplicationPerformanceByAppVersionDetails,omitempty"`
	// User experience analytics appHealth Application Performance by App Version Device Id
	UserExperienceAnalyticsAppHealthApplicationPerformanceByAppVersionDeviceId []UserExperienceAnalyticsAppHealthAppPerformanceByAppVersionDeviceId `json:"userExperienceAnalyticsAppHealthApplicationPerformanceByAppVersionDeviceId,omitempty"`
	// User experience analytics appHealth Application Performance by OS Version
	UserExperienceAnalyticsAppHealthApplicationPerformanceByOSVersion []UserExperienceAnalyticsAppHealthAppPerformanceByOSVersion `json:"userExperienceAnalyticsAppHealthApplicationPerformanceByOSVersion,omitempty"`
	// User experience analytics appHealth Model Performance
	UserExperienceAnalyticsAppHealthDeviceModelPerformance []UserExperienceAnalyticsAppHealthDeviceModelPerformance `json:"userExperienceAnalyticsAppHealthDeviceModelPerformance,omitempty"`
	// User experience analytics appHealth Device Performance
	UserExperienceAnalyticsAppHealthDevicePerformance []UserExperienceAnalyticsAppHealthDevicePerformance `json:"userExperienceAnalyticsAppHealthDevicePerformance,omitempty"`
	// User experience analytics device performance details
	UserExperienceAnalyticsAppHealthDevicePerformanceDetails []UserExperienceAnalyticsAppHealthDevicePerformanceDetails `json:"userExperienceAnalyticsAppHealthDevicePerformanceDetails,omitempty"`
	// User experience analytics appHealth OS version Performance
	UserExperienceAnalyticsAppHealthOSVersionPerformance []UserExperienceAnalyticsAppHealthOSVersionPerformance `json:"userExperienceAnalyticsAppHealthOSVersionPerformance,omitempty"`
	UserExperienceAnalyticsAppHealthOverview             *UserExperienceAnalyticsCategory                       `json:"userExperienceAnalyticsAppHealthOverview,omitempty"`
	// User experience analytics baselines
	UserExperienceAnalyticsBaselines []UserExperienceAnalyticsBaseline `json:"userExperienceAnalyticsBaselines,omitempty"`
	// User experience analytics categories
	UserExperienceAnalyticsCategories []UserExperienceAnalyticsCategory `json:"userExperienceAnalyticsCategories,omitempty"`
	// User experience analytics device performance
	UserExperienceAnalyticsDevicePerformance []UserExperienceAnalyticsDevicePerformance `json:"userExperienceAnalyticsDevicePerformance,omitempty"`
	// User experience analytics device scores
	UserExperienceAnalyticsDeviceScores []UserExperienceAnalyticsDeviceScores `json:"userExperienceAnalyticsDeviceScores,omitempty"`
	// User experience analytics device Startup History
	UserExperienceAnalyticsDeviceStartupHistory []UserExperienceAnalyticsDeviceStartupHistory `json:"userExperienceAnalyticsDeviceStartupHistory,omitempty"`
	// User experience analytics device Startup Processes
	UserExperienceAnalyticsDeviceStartupProcesses []UserExperienceAnalyticsDeviceStartupProcess `json:"userExperienceAnalyticsDeviceStartupProcesses,omitempty"`
	// User experience analytics device Startup Process Performance
	UserExperienceAnalyticsDeviceStartupProcessPerformance []UserExperienceAnalyticsDeviceStartupProcessPerformance `json:"userExperienceAnalyticsDeviceStartupProcessPerformance,omitempty"`
	// User experience analytics metric history
	UserExperienceAnalyticsMetricHistory []UserExperienceAnalyticsMetricHistory `json:"userExperienceAnalyticsMetricHistory,omitempty"`
	// User experience analytics model scores
	UserExperienceAnalyticsModelScores []UserExperienceAnalyticsModelScores             `json:"userExperienceAnalyticsModelScores,omitempty"`
	UserExperienceAnalyticsOverview    *DeviceManagementUserExperienceAnalyticsOverview `json:"userExperienceAnalyticsOverview,omitempty"`
	// User experience analytics device Startup Score History
	UserExperienceAnalyticsScoreHistory                            []UserExperienceAnalyticsScoreHistory                           `json:"userExperienceAnalyticsScoreHistory,omitempty"`
	UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetric *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetric `json:"userExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetric,omitempty"`
	// User experience analytics work from anywhere metrics.
	UserExperienceAnalyticsWorkFromAnywhereMetrics []UserExperienceAnalyticsWorkFromAnywhereMetric `json:"userExperienceAnalyticsWorkFromAnywhereMetrics,omitempty"`
	// The user experience analytics work from anywhere model performance
	UserExperienceAnalyticsWorkFromAnywhereModelPerformance []UserExperienceAnalyticsWorkFromAnywhereModelPerformance `json:"userExperienceAnalyticsWorkFromAnywhereModelPerformance,omitempty"`
	VirtualEndpoint                                         *DeviceManagementVirtualEndpoint                          `json:"virtualEndpoint,omitempty"`
	// The Windows autopilot device identities contained collection.
	WindowsAutopilotDeviceIdentities []WindowsAutopilotDeviceIdentity `json:"windowsAutopilotDeviceIdentities,omitempty"`
	// The windows information protection app learning summaries.
	WindowsInformationProtectionAppLearningSummaries []WindowsInformationProtectionAppLearningSummary `json:"windowsInformationProtectionAppLearningSummaries,omitempty"`
	// The windows information protection network learning summaries.
	WindowsInformationProtectionNetworkLearningSummaries []WindowsInformationProtectionNetworkLearningSummary `json:"windowsInformationProtectionNetworkLearningSummaries,omitempty"`
	// The list of affected malware in the tenant.
	WindowsMalwareInformation []WindowsMalwareInformation `json:"windowsMalwareInformation,omitempty"`
	OdataType                 string                      `json:"@odata.type"`
}

type Entity struct {
	// The unique identifier for an entity. Read-only.
	Id        *string `json:"id,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// WindowsMalwareInformation struct for WindowsMalwareInformation
type WindowsMalwareInformation struct {
	Entity
	// Indicates an informational URL to learn more about the malware
	AdditionalInformationUrl *string                 `json:"additionalInformationUrl,omitempty"`
	Category                 *WindowsMalwareCategory `json:"category,omitempty"`
	// Indicates the name of the malware
	DisplayName *string `json:"displayName,omitempty"`
	// Indicates the last time the malware was detected in UTC
	LastDetectionDateTime *time.Time              `json:"lastDetectionDateTime,omitempty"`
	Severity              *WindowsMalwareSeverity `json:"severity,omitempty"`
	// List of devices affected by current malware with the malware state on each device
	DeviceMalwareStates []MalwareStateForWindowsDevice `json:"deviceMalwareStates,omitempty"`
	OdataType           string                         `json:"@odata.type"`
}

// MalwareStateForWindowsDevice struct for MalwareStateForWindowsDevice
type MalwareStateForWindowsDevice struct {
	Entity
	// Indicates the number of times the malware is detected
	DetectionCount *int32 `json:"detectionCount,omitempty"`
	// Indicates the name of the device being evaluated for malware state
	DeviceName     *string                       `json:"deviceName,omitempty"`
	ExecutionState *WindowsMalwareExecutionState `json:"executionState,omitempty"`
	// Initial detection datetime of the malware
	InitialDetectionDateTime *time.Time `json:"initialDetectionDateTime,omitempty"`
	// The last time this particular threat was changed
	LastStateChangeDateTime *time.Time                 `json:"lastStateChangeDateTime,omitempty"`
	ThreatState             *WindowsMalwareThreatState `json:"threatState,omitempty"`
	OdataType               string                     `json:"@odata.type"`
}

// WindowsInformationProtectionNetworkLearningSummary struct for WindowsInformationProtectionNetworkLearningSummary
type WindowsInformationProtectionNetworkLearningSummary struct {
	Entity
	// Device Count
	DeviceCount *int32 `json:"deviceCount,omitempty"`
	// Website url
	Url       *string `json:"url,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// ApplicationType Possible types of Application
type ApplicationType string

// List of microsoft.graph.applicationType
const (
	MICROSOFTGRAPHAPPLICATIONTYPE_UNIVERSAL ApplicationType = "universal"
	MICROSOFTGRAPHAPPLICATIONTYPE_DESKTOP   ApplicationType = "desktop"
)

// All allowed values of ApplicationType enum
var AllowedApplicationTypeEnumValues = []ApplicationType{
	"universal",
	"desktop",
}

func (v *ApplicationType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ApplicationType(value)
	for _, existing := range AllowedApplicationTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ApplicationType", value)
}

// WindowsInformationProtectionAppLearningSummary struct for WindowsInformationProtectionAppLearningSummary
type WindowsInformationProtectionAppLearningSummary struct {
	Entity
	// Application Name
	ApplicationName *string          `json:"applicationName,omitempty"`
	ApplicationType *ApplicationType `json:"applicationType,omitempty"`
	// Device Count
	DeviceCount *int32 `json:"deviceCount,omitempty"`
	OdataType   string `json:"@odata.type"`
}

// CloudPcUserRoleScopeTagInfo struct for CloudPcUserRoleScopeTagInfo
type CloudPcUserRoleScopeTagInfo struct {
	// Scope tag display name.
	DisplayName *string `json:"displayName,omitempty"`
	// Scope tag identity.
	RoleScopeTagId *string `json:"roleScopeTagId,omitempty"`
	OdataType      string  `json:"@odata.type"`
}

// CloudPcAuditActor struct for CloudPcAuditActor
type CloudPcAuditActor struct {
	// Name of the application.
	ApplicationDisplayName *string `json:"applicationDisplayName,omitempty"`
	// Microsoft Entra application ID.
	ApplicationId *string `json:"applicationId,omitempty"`
	// IP address.
	IpAddress *string `json:"ipAddress,omitempty"`
	// The delegated partner tenant ID.
	RemoteTenantId *string `json:"remoteTenantId,omitempty"`
	// The delegated partner user ID.
	RemoteUserId *string `json:"remoteUserId,omitempty"`
	// Service Principal Name (SPN).
	ServicePrincipalName *string `json:"servicePrincipalName,omitempty"`
	// Microsoft Entra user ID.
	UserId *string `json:"userId,omitempty"`
	// List of user permissions and application permissions when the audit event was performed.
	UserPermissions []string `json:"userPermissions,omitempty"`
	// User Principal Name (UPN).
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	// List of role scope tags.
	UserRoleScopeTags []CloudPcUserRoleScopeTagInfo `json:"userRoleScopeTags,omitempty"`
	OdataType         string                        `json:"@odata.type"`
}

// CloudPcAuditActivityResult the model 'CloudPcAuditActivityResult'
type CloudPcAuditActivityResult string

// List of microsoft.graph.cloudPcAuditActivityResult
const (
	CLOUDPCAUDITACTIVITYRESULT_SUCCESS              CloudPcAuditActivityResult = "success"
	CLOUDPCAUDITACTIVITYRESULT_CLIENT_ERROR         CloudPcAuditActivityResult = "clientError"
	CLOUDPCAUDITACTIVITYRESULT_FAILURE              CloudPcAuditActivityResult = "failure"
	CLOUDPCAUDITACTIVITYRESULT_TIMEOUT              CloudPcAuditActivityResult = "timeout"
	CLOUDPCAUDITACTIVITYRESULT_UNKNOWN_FUTURE_VALUE CloudPcAuditActivityResult = "unknownFutureValue"
)

// All allowed values of CloudPcAuditActivityResult enum
var AllowedCloudPcAuditActivityResultEnumValues = []CloudPcAuditActivityResult{
	"success",
	"clientError",
	"failure",
	"timeout",
	"unknownFutureValue",
}

func (v *CloudPcAuditActivityResult) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcAuditActivityResult(value)
	for _, existing := range AllowedCloudPcAuditActivityResultEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcAuditActivityResult", value)
}

// CloudPcAuditActivityOperationType the model 'CloudPcAuditActivityOperationType'
type CloudPcAuditActivityOperationType string

// List of microsoft.graph.cloudPcAuditActivityOperationType
const (
	CLOUDPCAUDITACTIVITYOPERATIONTYPE_CREATE               CloudPcAuditActivityOperationType = "create"
	CLOUDPCAUDITACTIVITYOPERATIONTYPE_DELETE               CloudPcAuditActivityOperationType = "delete"
	CLOUDPCAUDITACTIVITYOPERATIONTYPE_PATCH                CloudPcAuditActivityOperationType = "patch"
	CLOUDPCAUDITACTIVITYOPERATIONTYPE_UNKNOWN_FUTURE_VALUE CloudPcAuditActivityOperationType = "unknownFutureValue"
)

// All allowed values of CloudPcAuditActivityOperationType enum
var AllowedCloudPcAuditActivityOperationTypeEnumValues = []CloudPcAuditActivityOperationType{
	"create",
	"delete",
	"patch",
	"unknownFutureValue",
}

func (v *CloudPcAuditActivityOperationType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcAuditActivityOperationType(value)
	for _, existing := range AllowedCloudPcAuditActivityOperationTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcAuditActivityOperationType", value)
}

// CloudPcAuditEvent struct for CloudPcAuditEvent
type CloudPcAuditEvent struct {
	Entity
	// The friendly name of the audit activity.
	Activity *string `json:"activity,omitempty"`
	// The date time in UTC when the activity was performed. Read-only.
	ActivityDateTime      *time.Time                         `json:"activityDateTime,omitempty"`
	ActivityOperationType *CloudPcAuditActivityOperationType `json:"activityOperationType,omitempty"`
	ActivityResult        *CloudPcAuditActivityResult        `json:"activityResult,omitempty"`
	// The type of activity that was performed. Read-only.
	ActivityType *string               `json:"activityType,omitempty"`
	Actor        *CloudPcAuditActor    `json:"actor,omitempty"`
	Category     *CloudPcAuditCategory `json:"category,omitempty"`
	// The component name for the audit event. Read-only.
	ComponentName *string `json:"componentName,omitempty"`
	// The client request ID that is used to correlate activity within the system. Read-only.
	CorrelationId *string `json:"correlationId,omitempty"`
	// The display name for the audit event. Read-only.
	DisplayName *string `json:"displayName,omitempty"`
	// The list of cloudPcAuditResource objects. Read-only.
	Resources []CloudPcAuditResource `json:"resources,omitempty"`
	OdataType string                 `json:"@odata.type"`
}

// CloudPcAuditProperty struct for CloudPcAuditProperty
type CloudPcAuditProperty struct {
	// The display name for this property.
	DisplayName *string `json:"displayName,omitempty"`
	// The new value for this property.
	NewValue *string `json:"newValue,omitempty"`
	// The old value for this property.
	OldValue  *string `json:"oldValue,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// CloudPcAuditResource struct for CloudPcAuditResource
type CloudPcAuditResource struct {
	// The display name of the modified resource entity.
	DisplayName *string `json:"displayName,omitempty"`
	// The list of modified properties.
	ModifiedProperties []CloudPcAuditProperty `json:"modifiedProperties,omitempty"`
	// The unique identifier of the modified resource entity.
	ResourceId *string `json:"resourceId,omitempty"`
	OdataType  string  `json:"@odata.type"`
}

// CloudPcAuditCategory the model 'CloudPcAuditCategory'
type CloudPcAuditCategory string

// List of microsoft.graph.cloudPcAuditCategory
const (
	MICROSOFTGRAPHCLOUDPCAUDITCATEGORY_CLOUD_PC             CloudPcAuditCategory = "cloudPC"
	MICROSOFTGRAPHCLOUDPCAUDITCATEGORY_UNKNOWN_FUTURE_VALUE CloudPcAuditCategory = "unknownFutureValue"
)

// All allowed values of CloudPcAuditCategory enum
var AllowedCloudPcAuditCategoryEnumValues = []CloudPcAuditCategory{
	"cloudPC",
	"unknownFutureValue",
}

func (v *CloudPcAuditCategory) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcAuditCategory(value)
	for _, existing := range AllowedCloudPcAuditCategoryEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcAuditCategory", value)
}

// DeviceManagementVirtualEndpoint struct for VirtualEndpoint
type DeviceManagementVirtualEndpoint struct {
	Entity
	// A collection of Cloud PC audit events.
	AuditEvents []CloudPcAuditEvent `json:"auditEvents,omitempty"`
	// A collection of cloud-managed virtual desktops.
	CloudPCs []CloudPC `json:"cloudPCs,omitempty"`
	// A collection of device image resources on Cloud PC.
	DeviceImages []CloudPcDeviceImage `json:"deviceImages,omitempty"`
	// A collection of gallery image resources on Cloud PC.
	GalleryImages []CloudPcGalleryImage `json:"galleryImages,omitempty"`
	// A defined collection of Azure resource information that can be used to establish Azure network connections for Cloud PCs.
	OnPremisesConnections []CloudPcOnPremisesConnection `json:"onPremisesConnections,omitempty"`
	// A collection of Cloud PC provisioning policies.
	ProvisioningPolicies []CloudPcProvisioningPolicy `json:"provisioningPolicies,omitempty"`
	// A collection of Cloud PC user settings.
	UserSettings []CloudPcUserSetting `json:"userSettings,omitempty"`
	OdataType    string               `json:"@odata.type"`
}

// CloudPcOnPremisesConnection struct for CloudPcOnPremisesConnection
type CloudPcOnPremisesConnection struct {
	Entity
	// The fully qualified domain name (FQDN) of the Active Directory domain you want to join. Maximum length is 255. Optional.
	AdDomainName *string `json:"adDomainName,omitempty"`
	// The password associated with the username of an Active Directory account (adDomainUsername).
	AdDomainPassword *string `json:"adDomainPassword,omitempty"`
	// The username of an Active Directory account (user or service account) that has permission to create computer objects in Active Directory. Required format: admin@contoso.com. Optional.
	AdDomainUsername *string `json:"adDomainUsername,omitempty"`
	// The interface URL of the partner service's resource that links to this Azure network connection. Returned only on $select.
	AlternateResourceUrl *string                          `json:"alternateResourceUrl,omitempty"`
	ConnectionType       *CloudPcOnPremisesConnectionType `json:"connectionType,omitempty"`
	// The display name for the Azure network connection.
	DisplayName             *string                                  `json:"displayName,omitempty"`
	HealthCheckStatus       *CloudPcOnPremisesConnectionStatusDetail `json:"healthCheckStatus,omitempty"`
	HealthCheckStatusDetail *CloudPcOnPremisesConnectionStatusDetail `json:"healthCheckStatusDetail,omitempty"`
	// When true, the Azure network connection is in use. When false, the connection isn't in use. You can't delete a connection that’s in use. Returned only on $select. For an example that shows how to get the inUse property, see Example 2: Get the selected properties of an Azure network connection, including healthCheckStatusDetail. Read-only.
	InUse *bool `json:"inUse,omitempty"`
	// The organizational unit (OU) in which the computer account is created. If left null, the OU configured as the default (a well-known computer object container) in the tenant's Active Directory domain (OU) is used. Optional.
	OrganizationalUnit *string `json:"organizationalUnit,omitempty"`
	// The unique identifier of the target resource group used associated with the on-premises network connectivity for Cloud PCs. Required format: '/subscriptions/{subscription-id}/resourceGroups/{resourceGroupName}'
	ResourceGroupId *string `json:"resourceGroupId,omitempty"`
	// The unique identifier of the target subnet used associated with the on-premises network connectivity for Cloud PCs. Required format: '/subscriptions/{subscription-id}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{virtualNetworkId}/subnets/{subnetName}'
	SubnetId *string `json:"subnetId,omitempty"`
	// The unique identifier of the Azure subscription associated with the tenant.
	SubscriptionId *string `json:"subscriptionId,omitempty"`
	// The name of the Azure subscription is used to create an Azure network connection. Read-only.
	SubscriptionName *string `json:"subscriptionName,omitempty"`
	// The unique identifier of the target virtual network used associated with the on-premises network connectivity for Cloud PCs. Required format: '/subscriptions/{subscription-id}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{virtualNetworkName}'
	VirtualNetworkId *string `json:"virtualNetworkId,omitempty"`
	// Indicates the resource location of the target virtual network. For example, the location can be eastus2, westeurope, etc. Read-only (computed value).
	VirtualNetworkLocation *string `json:"virtualNetworkLocation,omitempty"`
	OdataType              string  `json:"@odata.type"`
}

// CloudPcOnPremisesConnectionStatusDetail struct for CloudPcOnPremisesConnectionStatusDetail
type CloudPcOnPremisesConnectionStatusDetail struct {
	// The end time of the connection health check. The Timestamp  is shown in ISO 8601 format and Coordinated Universal Time (UTC). For example, midnight UTC on Jan 1, 2014 appears as 2014-01-01T00:00:00Z. Read-Only.
	EndDateTime *time.Time `json:"endDateTime,omitempty"`
	// A list of all checks that have been run on the connection. Read-Only.
	HealthChecks []CloudPcOnPremisesConnectionHealthCheck `json:"healthChecks,omitempty"`
	// The start time of the health check. The timestamp is shown in ISO 8601 format and Coordinated Universal Time (UTC). For example, midnight UTC on Jan 1, 2014 appear as 2014-01-01T00:00:00Z. Read-Only.
	StartDateTime *time.Time `json:"startDateTime,omitempty"`
	OdataType     string     `json:"@odata.type"`
}

// CloudPcOnPremisesConnectionHealthCheck struct for CloudPcOnPremisesConnectionHealthCheck
type CloudPcOnPremisesConnectionHealthCheck struct {
	// Additional details about the health check or the recommended action. For exmaple, the string value can be download.microsoft.com:443;software-download.microsoft.com:443; Read-only.
	AdditionalDetail *string `json:"additionalDetail,omitempty"`
	// The unique identifier of the health check item-related activities. This identifier can be useful in troubleshooting.
	CorrelationId *string `json:"correlationId,omitempty"`
	// The display name for this health check item.
	DisplayName *string `json:"displayName,omitempty"`
	// The value cannot be modified and is automatically populated when the health check ends. The Timestamp type represents date and time information using ISO 8601 format and is in Coordinated Universal Time (UTC). For example, midnight UTC on Jan 1, 2024 would look like this: '2024-01-01T00:00:00Z'. Returned by default. Read-only.
	EndDateTime *time.Time `json:"endDateTime,omitempty"`
	ErrorType   *string    `json:"errorType,omitempty"`
	// The recommended action to fix the corresponding error. For example, The Active Directory domain join check failed because the password of the domain join user has expired. Read-Only.
	RecommendedAction *string `json:"recommendedAction,omitempty"`
	// The value cannot be modified and is automatically populated when the health check starts. The Timestamp type represents date and time information using ISO 8601 format and is in  Coordinated Universal Time (UTC). For example, midnight UTC on Jan 1, 2024 would look like this: '2024-01-01T00:00:00Z'. Returned by default. Read-only.
	StartDateTime *time.Time                               `json:"startDateTime,omitempty"`
	Status        *CloudPcOnPremisesConnectionStatusDetail `json:"status,omitempty"`
	OdataType     string                                   `json:"@odata.type"`
}

// CloudPcOnPremisesConnectionType the model 'CloudPcOnPremisesConnectionType'
type CloudPcOnPremisesConnectionType string

// List of microsoft.graph.cloudPcOnPremisesConnectionType
const (
	MICROSOFTGRAPHCLOUDPCONPREMISESCONNECTIONTYPE_HYBRID_AZURE_AD_JOIN CloudPcOnPremisesConnectionType = "hybridAzureADJoin"
	MICROSOFTGRAPHCLOUDPCONPREMISESCONNECTIONTYPE_AZURE_AD_JOIN        CloudPcOnPremisesConnectionType = "azureADJoin"
	MICROSOFTGRAPHCLOUDPCONPREMISESCONNECTIONTYPE_UNKNOWN_FUTURE_VALUE CloudPcOnPremisesConnectionType = "unknownFutureValue"
)

// All allowed values of CloudPcOnPremisesConnectionType enum
var AllowedCloudPcOnPremisesConnectionTypeEnumValues = []CloudPcOnPremisesConnectionType{
	"hybridAzureADJoin",
	"azureADJoin",
	"unknownFutureValue",
}

func (v *CloudPcOnPremisesConnectionType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcOnPremisesConnectionType(value)
	for _, existing := range AllowedCloudPcOnPremisesConnectionTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcOnPremisesConnectionType", value)
}

// CloudPcGalleryImage struct for CloudPcGalleryImage
type CloudPcGalleryImage struct {
	Entity
	// The display name of this gallery image. For example, Windows 11 Enterprise + Microsoft 365 Apps 22H2. Read-only.
	DisplayName *string `json:"displayName,omitempty"`
	// The date when the status of the image becomes supportedWithWarning. Users can still provision new Cloud PCs if the current time is later than endDate and earlier than expirationDate. For example, assume the endDate of a gallery image is 2023-9-14 and expirationDate is 2024-3-14, users are able to provision new Cloud PCs if today is 2023-10-01. Read-only.
	EndDate *string `json:"endDate,omitempty"`
	// The date when the image is no longer available. Users are unable to provision new Cloud PCs if the current time is later than expirationDate. The value is usually endDate plus six months. For example, if the startDate is 2025-10-14, the expirationDate is usually 2026-04-14. Read-only.
	ExpirationDate *string `json:"expirationDate,omitempty"`
	// The offer name of this gallery image that is passed to Azure Resource Manager (ARM) to retrieve the image resource. Read-only.
	OfferName *string `json:"offerName,omitempty"`
	// The publisher name of this gallery image that is passed to Azure Resource Manager (ARM) to retrieve the image resource. Read-only.
	PublisherName *string `json:"publisherName,omitempty"`
	// Indicates the size of this image in gigabytes. For example, 64. Read-only.
	SizeInGB *int32 `json:"sizeInGB,omitempty"`
	// The SKU name of this image that is passed to Azure Resource Manager (ARM) to retrieve the image resource. Read-only.
	SkuName *string `json:"skuName,omitempty"`
	// The date when the Cloud PC image is available for provisioning new Cloud PCs. For example, 2022-09-20. Read-only.
	StartDate *string                    `json:"startDate,omitempty"`
	Status    *CloudPcGalleryImageStatus `json:"status,omitempty"`
	OdataType string                     `json:"@odata.type"`
}

// CloudPcGalleryImageStatus the model 'CloudPcGalleryImageStatus'
type CloudPcGalleryImageStatus string

// List of microsoft.graph.cloudPcGalleryImageStatus
const (
	MICROSOFTGRAPHCLOUDPCGALLERYIMAGESTATUS_SUPPORTED              CloudPcGalleryImageStatus = "supported"
	MICROSOFTGRAPHCLOUDPCGALLERYIMAGESTATUS_SUPPORTED_WITH_WARNING CloudPcGalleryImageStatus = "supportedWithWarning"
	MICROSOFTGRAPHCLOUDPCGALLERYIMAGESTATUS_NOT_SUPPORTED          CloudPcGalleryImageStatus = "notSupported"
	MICROSOFTGRAPHCLOUDPCGALLERYIMAGESTATUS_UNKNOWN_FUTURE_VALUE   CloudPcGalleryImageStatus = "unknownFutureValue"
)

// All allowed values of CloudPcGalleryImageStatus enum
var AllowedCloudPcGalleryImageStatusEnumValues = []CloudPcGalleryImageStatus{
	"supported",
	"supportedWithWarning",
	"notSupported",
	"unknownFutureValue",
}

func (v *CloudPcGalleryImageStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcGalleryImageStatus(value)
	for _, existing := range AllowedCloudPcGalleryImageStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcGalleryImageStatus", value)
}

// CloudPcDeviceImage struct for CloudPcDeviceImage
type CloudPcDeviceImage struct {
	Entity
	// The display name of the associated device image. The device image display name and the version are used to uniquely identify the Cloud PC device image. Read-only.
	DisplayName *string                      `json:"displayName,omitempty"`
	ErrorCode   *CloudPcDeviceImageErrorCode `json:"errorCode,omitempty"`
	// The date when the image became unavailable. Read-only.
	ExpirationDate *string `json:"expirationDate,omitempty"`
	// The data and time when the image was last modified. The timestamp represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// The operating system (OS) of the image. For example, Windows 10 Enterprise. Read-only.
	OperatingSystem *string `json:"operatingSystem,omitempty"`
	// The OS build version of the image. For example, 1909. Read-only.
	OsBuildNumber *string                     `json:"osBuildNumber,omitempty"`
	OsStatus      *CloudPcDeviceImageOsStatus `json:"osStatus,omitempty"`
	// The unique identifier (ID) of the source image resource on Azure. The required ID format is: '/subscriptions/{subscription-id}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/images/{imageName}'. Read-only.
	SourceImageResourceId *string                   `json:"sourceImageResourceId,omitempty"`
	Status                *CloudPcDeviceImageStatus `json:"status,omitempty"`
	// The image version. For example, 0.0.1 and 1.5.13. Read-only.
	Version   *string `json:"version,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// CloudPcDeviceImageErrorCode the model 'CloudPcDeviceImageErrorCode'
type CloudPcDeviceImageErrorCode string

// List of microsoft.graph.cloudPcDeviceImageErrorCode
const (
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_INTERNAL_SERVER_ERROR                      CloudPcDeviceImageErrorCode = "internalServerError"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_SOURCE_IMAGE_NOT_FOUND                     CloudPcDeviceImageErrorCode = "sourceImageNotFound"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_OS_VERSION_NOT_SUPPORTED                   CloudPcDeviceImageErrorCode = "osVersionNotSupported"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_SOURCE_IMAGE_INVALID                       CloudPcDeviceImageErrorCode = "sourceImageInvalid"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_SOURCE_IMAGE_NOT_GENERALIZED               CloudPcDeviceImageErrorCode = "sourceImageNotGeneralized"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_UNKNOWN_FUTURE_VALUE                       CloudPcDeviceImageErrorCode = "unknownFutureValue"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_VM_ALREADY_AZURE_ADJOINED                  CloudPcDeviceImageErrorCode = "vmAlreadyAzureAdjoined"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_PAID_SOURCE_IMAGE_NOT_SUPPORT              CloudPcDeviceImageErrorCode = "paidSourceImageNotSupport"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_SOURCE_IMAGE_NOT_SUPPORT_CUSTOMIZE_VM_NAME CloudPcDeviceImageErrorCode = "sourceImageNotSupportCustomizeVMName"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEERRORCODE_SOURCE_IMAGE_SIZE_EXCEEDS_LIMITATION       CloudPcDeviceImageErrorCode = "sourceImageSizeExceedsLimitation"
)

// All allowed values of CloudPcDeviceImageErrorCode enum
var AllowedCloudPcDeviceImageErrorCodeEnumValues = []CloudPcDeviceImageErrorCode{
	"internalServerError",
	"sourceImageNotFound",
	"osVersionNotSupported",
	"sourceImageInvalid",
	"sourceImageNotGeneralized",
	"unknownFutureValue",
	"vmAlreadyAzureAdjoined",
	"paidSourceImageNotSupport",
	"sourceImageNotSupportCustomizeVMName",
	"sourceImageSizeExceedsLimitation",
}

func (v *CloudPcDeviceImageErrorCode) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcDeviceImageErrorCode(value)
	for _, existing := range AllowedCloudPcDeviceImageErrorCodeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcDeviceImageErrorCode", value)
}

// CloudPcDeviceImageOsStatus the model 'CloudPcDeviceImageOsStatus'
type CloudPcDeviceImageOsStatus string

// List of microsoft.graph.cloudPcDeviceImageOsStatus
const (
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEOSSTATUS_SUPPORTED              CloudPcDeviceImageOsStatus = "supported"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEOSSTATUS_SUPPORTED_WITH_WARNING CloudPcDeviceImageOsStatus = "supportedWithWarning"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEOSSTATUS_UNKNOWN                CloudPcDeviceImageOsStatus = "unknown"
	MICROSOFTGRAPHCLOUDPCDEVICEIMAGEOSSTATUS_UNKNOWN_FUTURE_VALUE   CloudPcDeviceImageOsStatus = "unknownFutureValue"
)

// All allowed values of CloudPcDeviceImageOsStatus enum
var AllowedCloudPcDeviceImageOsStatusEnumValues = []CloudPcDeviceImageOsStatus{
	"supported",
	"supportedWithWarning",
	"unknown",
	"unknownFutureValue",
}

func (v *CloudPcDeviceImageOsStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcDeviceImageOsStatus(value)
	for _, existing := range AllowedCloudPcDeviceImageOsStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcDeviceImageOsStatus", value)
}

// CloudPcDeviceImageStatus the model 'CloudPcDeviceImageStatus'
type CloudPcDeviceImageStatus string

// List of microsoft.graph.cloudPcDeviceImageStatus
const (
	CLOUDPCDEVICEIMAGESTATUS_PENDING              CloudPcDeviceImageStatus = "pending"
	CLOUDPCDEVICEIMAGESTATUS_READY                CloudPcDeviceImageStatus = "ready"
	CLOUDPCDEVICEIMAGESTATUS_FAILED               CloudPcDeviceImageStatus = "failed"
	CLOUDPCDEVICEIMAGESTATUS_UNKNOWN_FUTURE_VALUE CloudPcDeviceImageStatus = "unknownFutureValue"
)

// All allowed values of CloudPcDeviceImageStatus enum
var AllowedCloudPcDeviceImageStatusEnumValues = []CloudPcDeviceImageStatus{
	"pending",
	"ready",
	"failed",
	"unknownFutureValue",
}

func (v *CloudPcDeviceImageStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcDeviceImageStatus(value)
	for _, existing := range AllowedCloudPcDeviceImageStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcDeviceImageStatus", value)
}

// CloudPC struct for CloudPC
type CloudPC struct {
	Entity
	// The Microsoft Entra device ID for the Cloud PC, also known as the Azure Active Directory (Azure AD) device ID, that consists of 32 characters in a GUID format. Generated on a VM joined to Microsoft Entra ID. Read-only.
	AadDeviceId *string `json:"aadDeviceId,omitempty"`
	// The display name for the Cloud PC. Maximum length is 64 characters. Read-only. You can use the cloudPC: rename API to modify the Cloud PC name.
	DisplayName *string `json:"displayName,omitempty"`
	// The date and time when the grace period ends and reprovisioning or deprovisioning happen. Required only if the status is inGracePeriod. The timestamp is shown in ISO 8601 format and Coordinated Universal Time (UTC). For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
	GracePeriodEndDateTime *time.Time `json:"gracePeriodEndDateTime,omitempty"`
	// The name of the operating system image used for the Cloud PC. Maximum length is 50 characters. Only letters (A-Z, a-z), numbers (0-9), and special characters (-,,.) are allowed for this property. The property value can't begin or end with an underscore. Read-only.
	ImageDisplayName *string `json:"imageDisplayName,omitempty"`
	// The last modified date and time of the Cloud PC. The timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// The Intune enrolled device ID for the Cloud PC that consists of 32 characters in a GUID format. The managedDeviceId property of Windows 365 Business Cloud PCs is always null as Windows 365 Business Cloud PCs aren't Intune-enrolled automatically by Windows 365. Read-only.
	ManagedDeviceId *string `json:"managedDeviceId,omitempty"`
	// The Intune enrolled device name for the Cloud PC. The managedDeviceName property of Windows 365 Business Cloud PCs is always null as Windows 365 Business Cloud PCs aren't Intune-enrolled automatically by Windows 365. Read-only.
	ManagedDeviceName *string `json:"managedDeviceName,omitempty"`
	// The on-premises connection that applied during the provisioning of Cloud PCs. Read-only.
	OnPremisesConnectionName *string `json:"onPremisesConnectionName,omitempty"`
	// The provisioning policy ID for the Cloud PC that consists of 32 characters in a GUID format. A policy defines the type of Cloud PC the user wants to create. Read-only.
	ProvisioningPolicyId *string `json:"provisioningPolicyId,omitempty"`
	// The provisioning policy that applied during the provisioning of Cloud PCs. Maximum length is 120 characters. Read-only.
	ProvisioningPolicyName *string                  `json:"provisioningPolicyName,omitempty"`
	ProvisioningType       *CloudPcProvisioningType `json:"provisioningType,omitempty"`
	// The service plan ID for the Cloud PC that consists of 32 characters in a GUID format. For more information about service plans, see Product names and service plan identifiers for licensing. Read-only.
	ServicePlanId *string `json:"servicePlanId,omitempty"`
	// The service plan name for the customer-facing Cloud PC entity. Read-only.
	ServicePlanName *string `json:"servicePlanName,omitempty"`
	// The user principal name (UPN) of the user assigned to the Cloud PC. Maximum length is 113 characters. For more information on username policies, see Password policies and account restrictions in Microsoft Entra ID. Read-only.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// CloudPcRestorePointFrequencyType the model 'CloudPcRestorePointFrequencyType'
type CloudPcRestorePointFrequencyType string

// List of microsoft.graph.cloudPcRestorePointFrequencyType
const (
	CLOUDPCRESTOREPOINTFREQUENCYTYPE_DEFAULT              CloudPcRestorePointFrequencyType = "default"
	CLOUDPCRESTOREPOINTFREQUENCYTYPE_FOUR_HOURS           CloudPcRestorePointFrequencyType = "fourHours"
	CLOUDPCRESTOREPOINTFREQUENCYTYPE_SIX_HOURS            CloudPcRestorePointFrequencyType = "sixHours"
	CLOUDPCRESTOREPOINTFREQUENCYTYPE_TWELVE_HOURS         CloudPcRestorePointFrequencyType = "twelveHours"
	CLOUDPCRESTOREPOINTFREQUENCYTYPE_SIXTEEN_HOURS        CloudPcRestorePointFrequencyType = "sixteenHours"
	CLOUDPCRESTOREPOINTFREQUENCYTYPE_TWENTY_FOUR_HOURS    CloudPcRestorePointFrequencyType = "twentyFourHours"
	CLOUDPCRESTOREPOINTFREQUENCYTYPE_UNKNOWN_FUTURE_VALUE CloudPcRestorePointFrequencyType = "unknownFutureValue"
)

// All allowed values of CloudPcRestorePointFrequencyType enum
var AllowedCloudPcRestorePointFrequencyTypeEnumValues = []CloudPcRestorePointFrequencyType{
	"default",
	"fourHours",
	"sixHours",
	"twelveHours",
	"sixteenHours",
	"twentyFourHours",
	"unknownFutureValue",
}

func (v *CloudPcRestorePointFrequencyType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcRestorePointFrequencyType(value)
	for _, existing := range AllowedCloudPcRestorePointFrequencyTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcRestorePointFrequencyType", value)
}

// CloudPcRestorePointSetting struct for CloudPcRestorePointSetting
type CloudPcRestorePointSetting struct {
	FrequencyType *CloudPcRestorePointFrequencyType `json:"frequencyType,omitempty"`
	// If true, the user has the ability to use snapshots to restore Cloud PCs. If false, non-admin users can't use snapshots to restore the Cloud PC.
	UserRestoreEnabled *bool  `json:"userRestoreEnabled,omitempty"`
	OdataType          string `json:"@odata.type"`
}

// CloudPcUserSetting struct for CloudPcUserSetting
type CloudPcUserSetting struct {
	Entity
	// The date and time when the setting was created. The timestamp type represents the date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
	CreatedDateTime *time.Time `json:"createdDateTime,omitempty"`
	// The setting name displayed in the user interface.
	DisplayName *string `json:"displayName,omitempty"`
	// The date and time when the setting was last modified. The timestamp type represents the date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// Indicates whether the local admin option is enabled. The default value is false. To enable the local admin option, change the setting to true. If the local admin option is enabled, the end user can be an admin of the Cloud PC device.
	LocalAdminEnabled *bool `json:"localAdminEnabled,omitempty"`
	// Indicates whether an end user is allowed to reset their Cloud PC. When true, the user is allowed to reset their Cloud PC. When false, end-user initiated reset is not allowed. The default value is false.
	ResetEnabled        *bool                       `json:"resetEnabled,omitempty"`
	RestorePointSetting *CloudPcRestorePointSetting `json:"restorePointSetting,omitempty"`
	// Represents the set of Microsoft 365 groups and security groups in Microsoft Entra ID that have cloudPCUserSetting assigned. Returned only on $expand. For an example, see Get cloudPcUserSetting.
	Assignments []CloudPcManagementAssignmentTarget `json:"assignments,omitempty"`
	OdataType   string                              `json:"@odata.type"`
}

// CloudPcProvisioningPolicyImageType the model 'CloudPcProvisioningPolicyImageType'
type CloudPcProvisioningPolicyImageType string

// List of microsoft.graph.cloudPcProvisioningPolicyImageType
const (
	CLOUDPCPROVISIONINGPOLICYIMAGETYPE_GALLERY              CloudPcProvisioningPolicyImageType = "gallery"
	CLOUDPCPROVISIONINGPOLICYIMAGETYPE_CUSTOM               CloudPcProvisioningPolicyImageType = "custom"
	CLOUDPCPROVISIONINGPOLICYIMAGETYPE_UNKNOWN_FUTURE_VALUE CloudPcProvisioningPolicyImageType = "unknownFutureValue"
)

// All allowed values of CloudPcProvisioningPolicyImageType enum
var AllowedCloudPcProvisioningPolicyImageTypeEnumValues = []CloudPcProvisioningPolicyImageType{
	"gallery",
	"custom",
	"unknownFutureValue",
}

func (v *CloudPcProvisioningPolicyImageType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcProvisioningPolicyImageType(value)
	for _, existing := range AllowedCloudPcProvisioningPolicyImageTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcProvisioningPolicyImageType", value)
}

// CloudPcDomainJoinConfiguration struct for CloudPcDomainJoinConfiguration
type CloudPcDomainJoinConfiguration struct {
	DomainJoinType *CloudPcDomainJoinType `json:"domainJoinType,omitempty"`
	// The Azure network connection ID that matches the virtual network IT admins want the provisioning policy to use when they create Cloud PCs. You can use this property in both domain join types: Azure AD joined or Hybrid Microsoft Entra joined. If you enter an onPremisesConnectionId, leave the regionName property empty.
	OnPremisesConnectionId *string             `json:"onPremisesConnectionId,omitempty"`
	RegionGroup            *CloudPcRegionGroup `json:"regionGroup,omitempty"`
	// The supported Azure region where the IT admin wants the provisioning policy to create Cloud PCs. Within this region, the Windows 365 service creates and manages the underlying virtual network. This option is available only when the IT admin selects Microsoft Entra joined as the domain join type. If you enter a regionName, leave the onPremisesConnectionId property empty.
	RegionName *string `json:"regionName,omitempty"`
	OdataType  string  `json:"@odata.type"`
}

// CloudPcRegionGroup the model 'CloudPcRegionGroup'
type CloudPcRegionGroup string

// List of microsoft.graph.cloudPcRegionGroup
const (
	CLOUDPCREGIONGROUP_DEFAULT              CloudPcRegionGroup = "default"
	CLOUDPCREGIONGROUP_AUSTRALIA            CloudPcRegionGroup = "australia"
	CLOUDPCREGIONGROUP_CANADA               CloudPcRegionGroup = "canada"
	CLOUDPCREGIONGROUP_US_CENTRAL           CloudPcRegionGroup = "usCentral"
	CLOUDPCREGIONGROUP_US_EAST              CloudPcRegionGroup = "usEast"
	CLOUDPCREGIONGROUP_US_WEST              CloudPcRegionGroup = "usWest"
	CLOUDPCREGIONGROUP_FRANCE               CloudPcRegionGroup = "france"
	CLOUDPCREGIONGROUP_GERMANY              CloudPcRegionGroup = "germany"
	CLOUDPCREGIONGROUP_EUROPE_UNION         CloudPcRegionGroup = "europeUnion"
	CLOUDPCREGIONGROUP_UNITED_KINGDOM       CloudPcRegionGroup = "unitedKingdom"
	CLOUDPCREGIONGROUP_JAPAN                CloudPcRegionGroup = "japan"
	CLOUDPCREGIONGROUP_ASIA                 CloudPcRegionGroup = "asia"
	CLOUDPCREGIONGROUP_INDIA                CloudPcRegionGroup = "india"
	CLOUDPCREGIONGROUP_SOUTH_AMERICA        CloudPcRegionGroup = "southAmerica"
	CLOUDPCREGIONGROUP_EUAP                 CloudPcRegionGroup = "euap"
	CLOUDPCREGIONGROUP_US_GOVERNMENT        CloudPcRegionGroup = "usGovernment"
	CLOUDPCREGIONGROUP_US_GOVERNMENT_DOD    CloudPcRegionGroup = "usGovernmentDOD"
	CLOUDPCREGIONGROUP_NORWAY               CloudPcRegionGroup = "norway"
	CLOUDPCREGIONGROUP_SWITZERLAND          CloudPcRegionGroup = "switzerland"
	CLOUDPCREGIONGROUP_SOUTH_KOREA          CloudPcRegionGroup = "southKorea"
	CLOUDPCREGIONGROUP_UNKNOWN_FUTURE_VALUE CloudPcRegionGroup = "unknownFutureValue"
)

// All allowed values of CloudPcRegionGroup enum
var AllowedCloudPcRegionGroupEnumValues = []CloudPcRegionGroup{
	"default",
	"australia",
	"canada",
	"usCentral",
	"usEast",
	"usWest",
	"france",
	"germany",
	"europeUnion",
	"unitedKingdom",
	"japan",
	"asia",
	"india",
	"southAmerica",
	"euap",
	"usGovernment",
	"usGovernmentDOD",
	"norway",
	"switzerland",
	"southKorea",
	"unknownFutureValue",
}

func (v *CloudPcRegionGroup) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcRegionGroup(value)
	for _, existing := range AllowedCloudPcRegionGroupEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcRegionGroup", value)
}

// CloudPcDomainJoinType the model 'CloudPcDomainJoinType'
type CloudPcDomainJoinType string

// List of microsoft.graph.cloudPcDomainJoinType
const (
	CLOUDPCDOMAINJOINTYPE_AZURE_AD_JOIN        CloudPcDomainJoinType = "azureADJoin"
	CLOUDPCDOMAINJOINTYPE_HYBRID_AZURE_AD_JOIN CloudPcDomainJoinType = "hybridAzureADJoin"
	CLOUDPCDOMAINJOINTYPE_UNKNOWN_FUTURE_VALUE CloudPcDomainJoinType = "unknownFutureValue"
)

// All allowed values of CloudPcDomainJoinType enum
var AllowedCloudPcDomainJoinTypeEnumValues = []CloudPcDomainJoinType{
	"azureADJoin",
	"hybridAzureADJoin",
	"unknownFutureValue",
}

func (v *CloudPcDomainJoinType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcDomainJoinType(value)
	for _, existing := range AllowedCloudPcDomainJoinTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcDomainJoinType", value)
}

// CloudPcProvisioningPolicy struct for CloudPcProvisioningPolicy
type CloudPcProvisioningPolicy struct {
	Entity
	// The URL of the alternate resource that links to this provisioning policy. Read-only.
	AlternateResourceUrl *string `json:"alternateResourceUrl,omitempty"`
	// The display name of the Cloud PC group that the Cloud PCs reside in. Read-only.
	CloudPcGroupDisplayName *string `json:"cloudPcGroupDisplayName,omitempty"`
	// The template used to name Cloud PCs provisioned using this policy. The template can contain custom text and replacement tokens, including %USERNAME:x% and %RAND:x%, which represent the user's name and a randomly generated number, respectively. For example, CPC-%USERNAME:4%-%RAND:5% means that the name of the Cloud PC starts with CPC-, followed by a four-character username, a - character, and then five random characters. The total length of the text generated by the template can't exceed 15 characters. Supports $filter, $select, and $orderby.
	CloudPcNamingTemplate *string `json:"cloudPcNamingTemplate,omitempty"`
	// The provisioning policy description. Supports $filter, $select, and $orderBy.
	Description *string `json:"description,omitempty"`
	// The display name for the provisioning policy.
	DisplayName *string `json:"displayName,omitempty"`
	// Specifies a list ordered by priority on how Cloud PCs join Microsoft Entra ID (Azure AD). Supports $select.
	DomainJoinConfigurations []CloudPcDomainJoinConfiguration `json:"domainJoinConfigurations,omitempty"`
	// True if the provisioned Cloud PC can be accessed by single sign-on. False indicates that the provisioned Cloud PC doesn't support this feature. The default value is false. Windows 365 users can use single sign-on to authenticate to Microsoft Entra ID with passwordless options (for example, FIDO keys) to access their Cloud PC. Optional.
	EnableSingleSignOn *bool `json:"enableSingleSignOn,omitempty"`
	// The number of hours to wait before reprovisioning/deprovisioning happens. Read-only.
	GracePeriodInHours *int32 `json:"gracePeriodInHours,omitempty"`
	// The display name of the operating system image that is used for provisioning. For example, Windows 11 Preview + Microsoft 365 Apps 23H2 23H2. Supports $filter, $select, and $orderBy.
	ImageDisplayName *string `json:"imageDisplayName,omitempty"`
	// The unique identifier that represents an operating system image that is used for provisioning new Cloud PCs. The format for a gallery type image is: {publisherNameofferNameskuName}. Supported values for each of the parameters are:publisher: Microsoftwindowsdesktop offer: windows-ent-cpc sku: 21h1-ent-cpc-m365, 21h1-ent-cpc-os, 20h2-ent-cpc-m365, 20h2-ent-cpc-os, 20h1-ent-cpc-m365, 20h1-ent-cpc-os, 19h2-ent-cpc-m365, and 19h2-ent-cpc-os Supports $filter, $select, and $orderBy.
	ImageId   *string                             `json:"imageId,omitempty"`
	ImageType *CloudPcProvisioningPolicyImageType `json:"imageType,omitempty"`
	// When true, the local admin is enabled for Cloud PCs; false indicates that the local admin isn't enabled for Cloud PCs. The default value is false. Supports $filter, $select, and $orderBy.
	LocalAdminEnabled       *bool                    `json:"localAdminEnabled,omitempty"`
	MicrosoftManagedDesktop *MicrosoftManagedDesktop `json:"microsoftManagedDesktop,omitempty"`
	ProvisioningType        *CloudPcProvisioningType `json:"provisioningType,omitempty"`
	WindowsSetting          *CloudPcWindowsSetting   `json:"windowsSetting,omitempty"`
	// A defined collection of provisioning policy assignments. Represents the set of Microsoft 365 groups and security groups in Microsoft Entra ID that have provisioning policy assigned. Returned only on $expand. For an example about how to get the assignments relationship, see Get cloudPcProvisioningPolicy.
	Assignments []CloudPcManagementAssignmentTarget `json:"assignments,omitempty"`
	OdataType   string                              `json:"@odata.type"`
}

// CloudPcManagementAssignmentTarget struct for CloudPcManagementAssignmentTarget
type CloudPcManagementAssignmentTarget struct {
	OdataType string `json:"@odata.type"`
}

// CloudPcWindowsSetting struct for CloudPcWindowsSetting
type CloudPcWindowsSetting struct {
	// The Windows language or region tag to use for language pack configuration and localization of the Cloud PC. The default value is en-US, which corresponds to English (United States).
	Locale    *string `json:"locale,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// CloudPcProvisioningType the model 'CloudPcProvisioningType'
type CloudPcProvisioningType string

// List of microsoft.graph.cloudPcProvisioningType
const (
	CLOUDPCPROVISIONINGTYPE_DEDICATED            CloudPcProvisioningType = "dedicated"
	CLOUDPCPROVISIONINGTYPE_SHARED               CloudPcProvisioningType = "shared"
	CLOUDPCPROVISIONINGTYPE_UNKNOWN_FUTURE_VALUE CloudPcProvisioningType = "unknownFutureValue"
)

// All allowed values of CloudPcProvisioningType enum
var AllowedCloudPcProvisioningTypeEnumValues = []CloudPcProvisioningType{
	"dedicated",
	"shared",
	"unknownFutureValue",
}

func (v *CloudPcProvisioningType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := CloudPcProvisioningType(value)
	for _, existing := range AllowedCloudPcProvisioningTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid CloudPcProvisioningType", value)
}

// MicrosoftManagedDesktopType the model 'MicrosoftManagedDesktopType'
type MicrosoftManagedDesktopType string

// List of microsoft.graph.microsoftManagedDesktopType
const (
	MICROSOFTMANAGEDDESKTOPTYPE_NOT_MANAGED          MicrosoftManagedDesktopType = "notManaged"
	MICROSOFTMANAGEDDESKTOPTYPE_PREMIUM_MANAGED      MicrosoftManagedDesktopType = "premiumManaged"
	MICROSOFTMANAGEDDESKTOPTYPE_STANDARD_MANAGED     MicrosoftManagedDesktopType = "standardManaged"
	MICROSOFTMANAGEDDESKTOPTYPE_STARTER_MANAGED      MicrosoftManagedDesktopType = "starterManaged"
	MICROSOFTMANAGEDDESKTOPTYPE_UNKNOWN_FUTURE_VALUE MicrosoftManagedDesktopType = "unknownFutureValue"
)

// All allowed values of MicrosoftManagedDesktopType enum
var AllowedMicrosoftManagedDesktopTypeEnumValues = []MicrosoftManagedDesktopType{
	"notManaged",
	"premiumManaged",
	"standardManaged",
	"starterManaged",
	"unknownFutureValue",
}

func (v *MicrosoftManagedDesktopType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := MicrosoftManagedDesktopType(value)
	for _, existing := range AllowedMicrosoftManagedDesktopTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid MicrosoftManagedDesktopType", value)
}

// MicrosoftManagedDesktop struct for MicrosoftManagedDesktop
type MicrosoftManagedDesktop struct {
	ManagedType *MicrosoftManagedDesktopType `json:"managedType,omitempty"`
	// The name of the Microsoft Managed Desktop profile that the Windows 365 Cloud PC is associated with.
	Profile   *string `json:"profile,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// UserExperienceAnalyticsWorkFromAnywhereModelPerformanceWorkFromAnywhereScore - The work from anywhere score of the device model. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereModelPerformanceWorkFromAnywhereScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereModelPerformanceWindowsScore - The window score of the device model. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereModelPerformanceWindowsScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudProvisioningScore - The cloud provisioning score of the device model.  Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudProvisioningScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudManagementScore - The cloud management score of the device model. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudManagementScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudIdentityScore - The cloud identity score of the device model. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudIdentityScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereModelPerformance struct for UserExperienceAnalyticsWorkFromAnywhereModelPerformance
type UserExperienceAnalyticsWorkFromAnywhereModelPerformance struct {
	Entity
	CloudIdentityScore     *UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudIdentityScore     `json:"cloudIdentityScore,omitempty"`
	CloudManagementScore   *UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudManagementScore   `json:"cloudManagementScore,omitempty"`
	CloudProvisioningScore *UserExperienceAnalyticsWorkFromAnywhereModelPerformanceCloudProvisioningScore `json:"cloudProvisioningScore,omitempty"`
	HealthStatus           *UserExperienceAnalyticsHealthState                                            `json:"healthStatus,omitempty"`
	// The manufacturer name of the device. Supports: $select, $OrderBy. Read-only.
	Manufacturer *string `json:"manufacturer,omitempty"`
	// The model name of the device. Supports: $select, $OrderBy. Read-only.
	Model *string `json:"model,omitempty"`
	// The devices count for the model. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	ModelDeviceCount      *int32                                                                        `json:"modelDeviceCount,omitempty"`
	WindowsScore          *UserExperienceAnalyticsWorkFromAnywhereModelPerformanceWindowsScore          `json:"windowsScore,omitempty"`
	WorkFromAnywhereScore *UserExperienceAnalyticsWorkFromAnywhereModelPerformanceWorkFromAnywhereScore `json:"workFromAnywhereScore,omitempty"`
	OdataType             string                                                                        `json:"@odata.type"`
}

// UserExperienceAnalyticsWorkFromAnywhereDevice struct for UserExperienceAnalyticsWorkFromAnywhereDevice
type UserExperienceAnalyticsWorkFromAnywhereDevice struct {
	Entity
	// When TRUE, indicates the intune device's autopilot profile is assigned. When FALSE, indicates it's not Assigned. Supports: $select, $OrderBy. Read-only.
	AutoPilotProfileAssigned *bool `json:"autoPilotProfileAssigned,omitempty"`
	// When TRUE, indicates the intune device's autopilot is registered. When FALSE, indicates it's not registered. Supports: $select, $OrderBy. Read-only.
	AutoPilotRegistered *bool `json:"autoPilotRegistered,omitempty"`
	// The Azure Active Directory (Azure AD) device Id. Supports: $select, $OrderBy. Read-only.
	AzureAdDeviceId *string `json:"azureAdDeviceId,omitempty"`
	// The work from anywhere device's Azure Active Directory (Azure AD) join type. Supports: $select, $OrderBy. Read-only.
	AzureAdJoinType *string `json:"azureAdJoinType,omitempty"`
	// When TRUE, indicates the device's Azure Active Directory (Azure AD) is registered. When False, indicates it's not registered. Supports: $select, $OrderBy. Read-only.
	AzureAdRegistered      *bool                                                               `json:"azureAdRegistered,omitempty"`
	CloudIdentityScore     UserExperienceAnalyticsWorkFromAnywhereDeviceCloudIdentityScore     `json:"cloudIdentityScore,omitempty"`
	CloudManagementScore   UserExperienceAnalyticsWorkFromAnywhereDeviceCloudManagementScore   `json:"cloudManagementScore,omitempty"`
	CloudProvisioningScore UserExperienceAnalyticsWorkFromAnywhereDeviceCloudProvisioningScore `json:"cloudProvisioningScore,omitempty"`
	// When TRUE, indicates the device's compliance policy is set to intune. When FALSE, indicates it's not set to intune. Supports: $select, $OrderBy. Read-only.
	CompliancePolicySetToIntune *bool `json:"compliancePolicySetToIntune,omitempty"`
	// The Intune device id of the device. Supports: $select, $OrderBy. Read-only.
	DeviceId *string `json:"deviceId,omitempty"`
	// The name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceName   *string                             `json:"deviceName,omitempty"`
	HealthStatus *UserExperienceAnalyticsHealthState `json:"healthStatus,omitempty"`
	// When TRUE, indicates the device's Cloud Management Gateway for Configuration Manager is enabled. When FALSE, indicates it's not enabled. Supports: $select, $OrderBy. Read-only.
	IsCloudManagedGatewayEnabled *bool `json:"isCloudManagedGatewayEnabled,omitempty"`
	// The management agent of the device. Supports: $select, $OrderBy. Read-only.
	ManagedBy *string `json:"managedBy,omitempty"`
	// The manufacturer name of the device. Supports: $select, $OrderBy. Read-only.
	Manufacturer *string `json:"manufacturer,omitempty"`
	// The model name of the device. Supports: $select, $OrderBy. Read-only.
	Model *string `json:"model,omitempty"`
	// When TRUE, indicates OS check failed for device to upgrade to the latest version of windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	OsCheckFailed *bool `json:"osCheckFailed,omitempty"`
	// The OS description of the device. Supports: $select, $OrderBy. Read-only.
	OsDescription *string `json:"osDescription,omitempty"`
	// The OS version of the device. Supports: $select, $OrderBy. Read-only.
	OsVersion *string `json:"osVersion,omitempty"`
	// When TRUE, indicates the device's other workloads is set to intune. When FALSE, indicates it's not set to intune. Supports: $select, $OrderBy. Read-only.
	OtherWorkloadsSetToIntune *bool `json:"otherWorkloadsSetToIntune,omitempty"`
	// Ownership of the device. Supports: $select, $OrderBy. Read-only.
	Ownership *string `json:"ownership,omitempty"`
	// When TRUE, indicates processor hardware 64-bit architecture check failed for device to upgrade to the latest version of windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	Processor64BitCheckFailed *bool `json:"processor64BitCheckFailed,omitempty"`
	// When TRUE, indicates processor hardware core count check failed for device to upgrade to the latest version of windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	ProcessorCoreCountCheckFailed *bool `json:"processorCoreCountCheckFailed,omitempty"`
	// When TRUE, indicates processor hardware family check failed for device to upgrade to the latest version of windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	ProcessorFamilyCheckFailed *bool `json:"processorFamilyCheckFailed,omitempty"`
	// When TRUE, indicates processor hardware speed check failed for device to upgrade to the latest version of windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	ProcessorSpeedCheckFailed *bool `json:"processorSpeedCheckFailed,omitempty"`
	// When TRUE, indicates RAM hardware check failed for device to upgrade to the latest version of windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	RamCheckFailed *bool `json:"ramCheckFailed,omitempty"`
	// When TRUE, indicates secure boot hardware check failed for device to upgrade to the latest version of windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	SecureBootCheckFailed *bool `json:"secureBootCheckFailed,omitempty"`
	// The serial number of the device. Supports: $select, $OrderBy. Read-only.
	SerialNumber *string `json:"serialNumber,omitempty"`
	// When TRUE, indicates storage hardware check failed for device to upgrade to the latest version of windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	StorageCheckFailed *bool `json:"storageCheckFailed,omitempty"`
	// When TRUE, indicates the device is Tenant Attached. When FALSE, indicates it's not Tenant Attached. Supports: $select, $OrderBy. Read-only.
	TenantAttached *bool `json:"tenantAttached,omitempty"`
	// When TRUE, indicates Trusted Platform Module (TPM) hardware check failed for device to the latest version of upgrade to windows. When FALSE, indicates the check succeeded. Supports: $select, $OrderBy. Read-only.
	TpmCheckFailed        *bool                                                              `json:"tpmCheckFailed,omitempty"`
	UpgradeEligibility    *OperatingSystemUpgradeEligibility                                 `json:"upgradeEligibility,omitempty"`
	WindowsScore          UserExperienceAnalyticsWorkFromAnywhereDeviceWindowsScore          `json:"windowsScore,omitempty"`
	WorkFromAnywhereScore UserExperienceAnalyticsWorkFromAnywhereDeviceWorkFromAnywhereScore `json:"workFromAnywhereScore,omitempty"`
	OdataType             string                                                             `json:"@odata.type"`
}

// UserExperienceAnalyticsWorkFromAnywhereDeviceWorkFromAnywhereScore - Indicates work from anywhere per device overall score. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereDeviceWorkFromAnywhereScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereDeviceWindowsScore - Indicates per device windows score. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereDeviceWindowsScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// OperatingSystemUpgradeEligibility Work From Anywhere windows device upgrade eligibility status.
type OperatingSystemUpgradeEligibility string

// List of microsoft.graph.operatingSystemUpgradeEligibility
const (
	OPERATINGSYSTEMUPGRADEELIGIBILITY_UPGRADED             OperatingSystemUpgradeEligibility = "upgraded"
	OPERATINGSYSTEMUPGRADEELIGIBILITY_UNKNOWN              OperatingSystemUpgradeEligibility = "unknown"
	OPERATINGSYSTEMUPGRADEELIGIBILITY_NOT_CAPABLE          OperatingSystemUpgradeEligibility = "notCapable"
	OPERATINGSYSTEMUPGRADEELIGIBILITY_CAPABLE              OperatingSystemUpgradeEligibility = "capable"
	OPERATINGSYSTEMUPGRADEELIGIBILITY_UNKNOWN_FUTURE_VALUE OperatingSystemUpgradeEligibility = "unknownFutureValue"
)

// All allowed values of OperatingSystemUpgradeEligibility enum
var AllowedOperatingSystemUpgradeEligibilityEnumValues = []OperatingSystemUpgradeEligibility{
	"upgraded",
	"unknown",
	"notCapable",
	"capable",
	"unknownFutureValue",
}

func (v *OperatingSystemUpgradeEligibility) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := OperatingSystemUpgradeEligibility(value)
	for _, existing := range AllowedOperatingSystemUpgradeEligibilityEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid OperatingSystemUpgradeEligibility", value)
}

// UserExperienceAnalyticsWorkFromAnywhereDeviceCloudProvisioningScore - Indicates per device cloud provisioning score. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereDeviceCloudProvisioningScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereDeviceCloudManagementScore - Indicates per device cloud management score. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereDeviceCloudManagementScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereDeviceCloudIdentityScore - Indicates per device cloud identity score. Valid values 0 to 100. Value -1 means associated score is unavailable. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereDeviceCloudIdentityScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereMetric struct for UserExperienceAnalyticsWorkFromAnywhereMetric
type UserExperienceAnalyticsWorkFromAnywhereMetric struct {
	Entity
	// The work from anywhere metric devices. Read-only.
	MetricDevices []UserExperienceAnalyticsWorkFromAnywhereDevice `json:"metricDevices,omitempty"`
	OdataType     string                                          `json:"@odata.type"`
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricTpmCheckFailedPercentage - The percentage of devices for which Trusted Platform Module (TPM) hardware check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricTpmCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricStorageCheckFailedPercentage - The percentage of devices for which storage hardware check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricStorageCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricSecureBootCheckFailedPercentage - The percentage of devices for which secure boot hardware check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricSecureBootCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricRamCheckFailedPercentage - The percentage of devices for which RAM hardware check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricRamCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorSpeedCheckFailedPercentage - The percentage of devices for which processor hardware speed check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorSpeedCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorFamilyCheckFailedPercentage - The percentage of devices for which processor hardware family check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorFamilyCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorCoreCountCheckFailedPercentage - The percentage of devices for which processor hardware core count check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorCoreCountCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessor64BitCheckFailedPercentage - The percentage of devices for which processor hardware 64-bit architecture check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessor64BitCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricOsCheckFailedPercentage - The percentage of devices for which OS check has failed. Valid values 0 to 100. Supports: $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricOsCheckFailedPercentage struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetric struct for UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetric
type UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetric struct {
	Entity
	OsCheckFailedPercentage                 *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricOsCheckFailedPercentage                 `json:"osCheckFailedPercentage,omitempty"`
	Processor64BitCheckFailedPercentage     *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessor64BitCheckFailedPercentage     `json:"processor64BitCheckFailedPercentage,omitempty"`
	ProcessorCoreCountCheckFailedPercentage *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorCoreCountCheckFailedPercentage `json:"processorCoreCountCheckFailedPercentage,omitempty"`
	ProcessorFamilyCheckFailedPercentage    *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorFamilyCheckFailedPercentage    `json:"processorFamilyCheckFailedPercentage,omitempty"`
	ProcessorSpeedCheckFailedPercentage     *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricProcessorSpeedCheckFailedPercentage     `json:"processorSpeedCheckFailedPercentage,omitempty"`
	RamCheckFailedPercentage                *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricRamCheckFailedPercentage                `json:"ramCheckFailedPercentage,omitempty"`
	SecureBootCheckFailedPercentage         *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricSecureBootCheckFailedPercentage         `json:"secureBootCheckFailedPercentage,omitempty"`
	StorageCheckFailedPercentage            *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricStorageCheckFailedPercentage            `json:"storageCheckFailedPercentage,omitempty"`
	// The count of total devices in an organization. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	TotalDeviceCount         *int32                                                                                  `json:"totalDeviceCount,omitempty"`
	TpmCheckFailedPercentage *UserExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetricTpmCheckFailedPercentage `json:"tpmCheckFailedPercentage,omitempty"`
	// The count of devices in an organization eligible for windows upgrade. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	UpgradeEligibleDeviceCount *int32 `json:"upgradeEligibleDeviceCount,omitempty"`
	OdataType                  string `json:"@odata.type"`
}

// UserExperienceAnalyticsScoreHistory struct for UserExperienceAnalyticsScoreHistory
type UserExperienceAnalyticsScoreHistory struct {
	Entity
	// The device startup date time. The value cannot be modified and is automatically populated. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Returned by default.
	StartupDateTime *time.Time `json:"startupDateTime,omitempty"`
	OdataType       string     `json:"@odata.type"`
}

// DeviceManagementUserExperienceAnalyticsOverview struct for UserExperienceAnalyticsOverview
type DeviceManagementUserExperienceAnalyticsOverview struct {
	Entity
	// The user experience analytics insights. Read-only.
	Insights  []UserExperienceAnalyticsInsight `json:"insights,omitempty"`
	OdataType string                           `json:"@odata.type"`
}

// UserExperienceAnalyticsModelScoresEndpointAnalyticsScore - Indicates a weighted average of the various scores. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsModelScoresEndpointAnalyticsScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsModelScoresBatteryHealthScore - Indicates a calulated score indicating the health of the device's battery. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsModelScoresBatteryHealthScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsModelScoresAppReliabilityScore - Indicates a score calculated from application health data to indicate when a device is having problems running one or more applications. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsModelScoresAppReliabilityScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsModelScores struct for UserExperienceAnalyticsModelScores
type UserExperienceAnalyticsModelScores struct {
	Entity
	AppReliabilityScore    *UserExperienceAnalyticsModelScoresAppReliabilityScore    `json:"appReliabilityScore,omitempty"`
	BatteryHealthScore     *UserExperienceAnalyticsModelScoresBatteryHealthScore     `json:"batteryHealthScore,omitempty"`
	EndpointAnalyticsScore *UserExperienceAnalyticsModelScoresEndpointAnalyticsScore `json:"endpointAnalyticsScore,omitempty"`
	HealthStatus           *UserExperienceAnalyticsHealthState                       `json:"healthStatus,omitempty"`
	// The manufacturer name of the device. Examples: Microsoft Corporation, HP, Lenovo. Supports: $select, $OrderBy. Read-only.
	Manufacturer *string `json:"manufacturer,omitempty"`
	// The model name of the device. Supports: $select, $OrderBy. Read-only.
	Model *string `json:"model,omitempty"`
	// Indicates unique devices count of given model in a consolidated report. Supports: $select, $OrderBy. Read-only. Valid values -9.22337203685478E+18 to 9.22337203685478E+18
	ModelDeviceCount        *int64                                                     `json:"modelDeviceCount,omitempty"`
	StartupPerformanceScore *UserExperienceAnalyticsModelScoresStartupPerformanceScore `json:"startupPerformanceScore,omitempty"`
	WorkFromAnywhereScore   *UserExperienceAnalyticsModelScoresWorkFromAnywhereScore   `json:"workFromAnywhereScore,omitempty"`
	OdataType               string                                                     `json:"@odata.type"`
}

// UserExperienceAnalyticsModelScoresWorkFromAnywhereScore - Indicates a weighted score of the work from anywhere on a device level. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsModelScoresWorkFromAnywhereScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsModelScoresStartupPerformanceScore - Indicates a weighted average of boot score and logon score used for measuring startup performance. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsModelScoresStartupPerformanceScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsMetricHistory struct for UserExperienceAnalyticsMetricHistory
type UserExperienceAnalyticsMetricHistory struct {
	Entity
	// The Intune device id of the device.
	DeviceId *string `json:"deviceId,omitempty"`
	// The metric date time. The value cannot be modified and is automatically populated when the metric is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Returned by default.
	MetricDateTime *time.Time `json:"metricDateTime,omitempty"`
	// The user experience analytics metric type.
	MetricType *string `json:"metricType,omitempty"`
	OdataType  string  `json:"@odata.type"`
}

// UserExperienceAnalyticsDeviceStartupProcessPerformance struct for UserExperienceAnalyticsDeviceStartupProcessPerformance
type UserExperienceAnalyticsDeviceStartupProcessPerformance struct {
	Entity
	// The count of devices which initiated this process on startup. Supports: $filter, $select, $OrderBy. Read-only.
	DeviceCount *int64 `json:"deviceCount,omitempty"`
	// The median impact of startup process on device boot time in milliseconds. Supports: $filter, $select, $OrderBy. Read-only.
	MedianImpactInMs *int64 `json:"medianImpactInMs,omitempty"`
	// The name of the startup process. Examples: outlook, excel. Supports: $select, $OrderBy. Read-only.
	ProcessName *string `json:"processName,omitempty"`
	// The product name of the startup process. Examples: Microsoft Outlook, Microsoft Excel. Supports: $select, $OrderBy. Read-only.
	ProductName *string `json:"productName,omitempty"`
	// The publisher of the startup process. Examples: Microsoft Corporation, Contoso Corp. Supports: $select, $OrderBy. Read-only.
	Publisher *string `json:"publisher,omitempty"`
	// The total impact of startup process on device boot time in milliseconds. Supports: $filter, $select, $OrderBy. Read-only.
	TotalImpactInMs *int64 `json:"totalImpactInMs,omitempty"`
	OdataType       string `json:"@odata.type"`
}

// UserExperienceAnalyticsDeviceStartupProcess struct for UserExperienceAnalyticsDeviceStartupProcess
type UserExperienceAnalyticsDeviceStartupProcess struct {
	Entity
	// The Intune device id of the device. Supports: $select, $OrderBy. Read-only.
	ManagedDeviceId *string `json:"managedDeviceId,omitempty"`
	// The name of the process. Examples: outlook, excel. Supports: $select, $OrderBy. Read-only.
	ProcessName *string `json:"processName,omitempty"`
	// The product name of the process. Examples: Microsoft Outlook, Microsoft Excel. Supports: $select, $OrderBy. Read-only.
	ProductName *string `json:"productName,omitempty"`
	// The publisher of the process. Examples: Microsoft Corporation, Contoso Corp. Supports: $select, $OrderBy. Read-only.
	Publisher *string `json:"publisher,omitempty"`
	// The impact of startup process on device boot time in milliseconds. Supports: $select, $OrderBy. Read-only.
	StartupImpactInMs *int32 `json:"startupImpactInMs,omitempty"`
	OdataType         string `json:"@odata.type"`
}

// UserExperienceAnalyticsOperatingSystemRestartCategory Operating System restart category.
type UserExperienceAnalyticsOperatingSystemRestartCategory string

// List of microsoft.graph.userExperienceAnalyticsOperatingSystemRestartCategory
const (
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_UNKNOWN                 UserExperienceAnalyticsOperatingSystemRestartCategory = "unknown"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_RESTART_WITH_UPDATE     UserExperienceAnalyticsOperatingSystemRestartCategory = "restartWithUpdate"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_RESTART_WITHOUT_UPDATE  UserExperienceAnalyticsOperatingSystemRestartCategory = "restartWithoutUpdate"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_BLUE_SCREEN             UserExperienceAnalyticsOperatingSystemRestartCategory = "blueScreen"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_SHUTDOWN_WITH_UPDATE    UserExperienceAnalyticsOperatingSystemRestartCategory = "shutdownWithUpdate"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_SHUTDOWN_WITHOUT_UPDATE UserExperienceAnalyticsOperatingSystemRestartCategory = "shutdownWithoutUpdate"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_LONG_POWER_BUTTON_PRESS UserExperienceAnalyticsOperatingSystemRestartCategory = "longPowerButtonPress"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_BOOT_ERROR              UserExperienceAnalyticsOperatingSystemRestartCategory = "bootError"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_UPDATE                  UserExperienceAnalyticsOperatingSystemRestartCategory = "update"
	USEREXPERIENCEANALYTICSOPERATINGSYSTEMRESTARTCATEGORY_UNKNOWN_FUTURE_VALUE    UserExperienceAnalyticsOperatingSystemRestartCategory = "unknownFutureValue"
)

// All allowed values of UserExperienceAnalyticsOperatingSystemRestartCategory enum
var AllowedUserExperienceAnalyticsOperatingSystemRestartCategoryEnumValues = []UserExperienceAnalyticsOperatingSystemRestartCategory{
	"unknown",
	"restartWithUpdate",
	"restartWithoutUpdate",
	"blueScreen",
	"shutdownWithUpdate",
	"shutdownWithoutUpdate",
	"longPowerButtonPress",
	"bootError",
	"update",
	"unknownFutureValue",
}

func (v *UserExperienceAnalyticsOperatingSystemRestartCategory) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := UserExperienceAnalyticsOperatingSystemRestartCategory(value)
	for _, existing := range AllowedUserExperienceAnalyticsOperatingSystemRestartCategoryEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid UserExperienceAnalyticsOperatingSystemRestartCategory", value)
}

// UserExperienceAnalyticsDeviceStartupHistory struct for UserExperienceAnalyticsDeviceStartupHistory
type UserExperienceAnalyticsDeviceStartupHistory struct {
	Entity
	// The device core boot time in milliseconds. Supports: $select, $OrderBy. Read-only.
	CoreBootTimeInMs *int32 `json:"coreBootTimeInMs,omitempty"`
	// The device core login time in milliseconds. Supports: $select, $OrderBy. Read-only.
	CoreLoginTimeInMs *int32 `json:"coreLoginTimeInMs,omitempty"`
	// The Intune device id of the device. Supports: $select, $OrderBy. Read-only.
	DeviceId *string `json:"deviceId,omitempty"`
	// The impact of device feature updates on boot time in milliseconds. Supports: $select, $OrderBy. Read-only.
	FeatureUpdateBootTimeInMs *int32 `json:"featureUpdateBootTimeInMs,omitempty"`
	// The impact of device group policy client on boot time in milliseconds. Supports: $select, $OrderBy. Read-only.
	GroupPolicyBootTimeInMs *int32 `json:"groupPolicyBootTimeInMs,omitempty"`
	// The impact of device group policy client on login time in milliseconds. Supports: $select, $OrderBy. Read-only.
	GroupPolicyLoginTimeInMs *int32 `json:"groupPolicyLoginTimeInMs,omitempty"`
	// When TRUE, indicates the device boot record is associated with feature updates. When FALSE, indicates the device boot record is not associated with feature updates. Supports: $select, $OrderBy. Read-only.
	IsFeatureUpdate *bool `json:"isFeatureUpdate,omitempty"`
	// When TRUE, indicates the device login is the first login after a reboot. When FALSE, indicates the device login is not the first login after a reboot. Supports: $select, $OrderBy. Read-only.
	IsFirstLogin *bool `json:"isFirstLogin,omitempty"`
	// The user experience analytics device boot record's operating system version. Supports: $select, $OrderBy. Read-only.
	OperatingSystemVersion *string `json:"operatingSystemVersion,omitempty"`
	// The time for desktop to become responsive during login process in milliseconds. Supports: $select, $OrderBy. Read-only.
	ResponsiveDesktopTimeInMs *int32                                                 `json:"responsiveDesktopTimeInMs,omitempty"`
	RestartCategory           *UserExperienceAnalyticsOperatingSystemRestartCategory `json:"restartCategory,omitempty"`
	// OS restart fault bucket. The fault bucket is used to find additional information about a system crash. Supports: $select, $OrderBy. Read-only.
	RestartFaultBucket *string `json:"restartFaultBucket,omitempty"`
	// OS restart stop code. This shows the bug check code which can be used to look up the blue screen reason. Supports: $select, $OrderBy. Read-only.
	RestartStopCode *string `json:"restartStopCode,omitempty"`
	// The device boot start time. The value cannot be modified and is automatically populated when the device performs a reboot. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2022 would look like this: '2022-01-01T00:00:00Z'. Returned by default. Read-only.
	StartTime *time.Time `json:"startTime,omitempty"`
	// The device total boot time in milliseconds. Supports: $select, $OrderBy. Read-only.
	TotalBootTimeInMs *int32 `json:"totalBootTimeInMs,omitempty"`
	// The device total login time in milliseconds. Supports: $select, $OrderBy. Read-only.
	TotalLoginTimeInMs *int32 `json:"totalLoginTimeInMs,omitempty"`
	OdataType          string `json:"@odata.type"`
}

// UserExperienceAnalyticsDeviceScores struct for UserExperienceAnalyticsDeviceScores
type UserExperienceAnalyticsDeviceScores struct {
	Entity
	AppReliabilityScore *UserExperienceAnalyticsDeviceScoresAppReliabilityScore `json:"appReliabilityScore,omitempty"`
	BatteryHealthScore  *UserExperienceAnalyticsDeviceScoresBatteryHealthScore  `json:"batteryHealthScore,omitempty"`
	// The name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceName             *string                                                    `json:"deviceName,omitempty"`
	EndpointAnalyticsScore *UserExperienceAnalyticsDeviceScoresEndpointAnalyticsScore `json:"endpointAnalyticsScore,omitempty"`
	HealthStatus           *UserExperienceAnalyticsHealthState                        `json:"healthStatus,omitempty"`
	// The manufacturer name of the device. Examples: Microsoft Corporation, HP, Lenovo. Supports: $select, $OrderBy. Read-only.
	Manufacturer *string `json:"manufacturer,omitempty"`
	// The model name of the device. Supports: $select, $OrderBy. Read-only.
	Model                   *string                                                     `json:"model,omitempty"`
	StartupPerformanceScore *UserExperienceAnalyticsDeviceScoresStartupPerformanceScore `json:"startupPerformanceScore,omitempty"`
	WorkFromAnywhereScore   *UserExperienceAnalyticsDeviceScoresWorkFromAnywhereScore   `json:"workFromAnywhereScore,omitempty"`
	OdataType               string                                                      `json:"@odata.type"`
}

// UserExperienceAnalyticsDeviceScoresWorkFromAnywhereScore - Indicates a weighted score of the work from anywhere on a device level. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsDeviceScoresWorkFromAnywhereScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsDeviceScoresStartupPerformanceScore - Indicates a weighted average of boot score and logon score used for measuring startup performance. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsDeviceScoresStartupPerformanceScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsDeviceScoresEndpointAnalyticsScore - Indicates a weighted average of the various scores. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsDeviceScoresEndpointAnalyticsScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsDeviceScoresBatteryHealthScore - Indicates a calulated score indicating the health of the device's battery. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsDeviceScoresBatteryHealthScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsDeviceScoresAppReliabilityScore - Indicates a score calculated from application health data to indicate when a device is having problems running one or more applications. Valid values range from 0-100. Value -1 means associated score is unavailable. A higher score indicates a healthier device. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsDeviceScoresAppReliabilityScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsDevicePerformance struct for UserExperienceAnalyticsDevicePerformance
type UserExperienceAnalyticsDevicePerformance struct {
	Entity
	AverageBlueScreens *UserExperienceAnalyticsDevicePerformanceAverageBlueScreens `json:"averageBlueScreens,omitempty"`
	AverageRestarts    *UserExperienceAnalyticsDevicePerformanceAverageRestarts    `json:"averageRestarts,omitempty"`
	// Number of Blue Screens in the last 30 days. Valid values 0 to 9999999
	BlueScreenCount *int32 `json:"blueScreenCount,omitempty"`
	// The user experience analytics device boot score.
	BootScore *int32 `json:"bootScore,omitempty"`
	// The user experience analytics device core boot time in milliseconds.
	CoreBootTimeInMs *int32 `json:"coreBootTimeInMs,omitempty"`
	// The user experience analytics device core login time in milliseconds.
	CoreLoginTimeInMs *int32 `json:"coreLoginTimeInMs,omitempty"`
	// User experience analytics summarized device count.
	DeviceCount *int64 `json:"deviceCount,omitempty"`
	// The user experience analytics device name.
	DeviceName *string   `json:"deviceName,omitempty"`
	DiskType   *DiskType `json:"diskType,omitempty"`
	// The user experience analytics device group policy boot time in milliseconds.
	GroupPolicyBootTimeInMs *int32 `json:"groupPolicyBootTimeInMs,omitempty"`
	// The user experience analytics device group policy login time in milliseconds.
	GroupPolicyLoginTimeInMs *int32                              `json:"groupPolicyLoginTimeInMs,omitempty"`
	HealthStatus             *UserExperienceAnalyticsHealthState `json:"healthStatus,omitempty"`
	// The user experience analytics device login score.
	LoginScore *int32 `json:"loginScore,omitempty"`
	// The user experience analytics device manufacturer.
	Manufacturer *string `json:"manufacturer,omitempty"`
	// The user experience analytics device model.
	Model                        *string                                                               `json:"model,omitempty"`
	ModelStartupPerformanceScore *UserExperienceAnalyticsDevicePerformanceModelStartupPerformanceScore `json:"modelStartupPerformanceScore,omitempty"`
	// The user experience analytics device Operating System version.
	OperatingSystemVersion *string `json:"operatingSystemVersion,omitempty"`
	// The user experience analytics responsive desktop time in milliseconds.
	ResponsiveDesktopTimeInMs *int32 `json:"responsiveDesktopTimeInMs,omitempty"`
	// Number of Restarts in the last 30 days. Valid values 0 to 9999999
	RestartCount            *int32                                                           `json:"restartCount,omitempty"`
	StartupPerformanceScore *UserExperienceAnalyticsDevicePerformanceStartupPerformanceScore `json:"startupPerformanceScore,omitempty"`
	OdataType               string                                                           `json:"@odata.type"`
}

// UserExperienceAnalyticsDevicePerformanceStartupPerformanceScore - The user experience analytics device startup performance score. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsDevicePerformanceStartupPerformanceScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsDevicePerformanceModelStartupPerformanceScore - The user experience analytics model level startup performance score. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsDevicePerformanceModelStartupPerformanceScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// DiskType the model 'DiskType'
type DiskType string

// List of microsoft.graph.diskType
const (
	DISKTYPE_UNKNOWN              DiskType = "unknown"
	DISKTYPE_HDD                  DiskType = "hdd"
	DISKTYPE_SSD                  DiskType = "ssd"
	DISKTYPE_UNKNOWN_FUTURE_VALUE DiskType = "unknownFutureValue"
)

// All allowed values of DiskType enum
var AllowedDiskTypeEnumValues = []DiskType{
	"unknown",
	"hdd",
	"ssd",
	"unknownFutureValue",
}

func (v *DiskType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DiskType(value)
	for _, existing := range AllowedDiskTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DiskType", value)
}

// UserExperienceAnalyticsDevicePerformanceAverageRestarts - Average (mean) number of Restarts per device in the last 30 days. Valid values 0 to 9999999
type UserExperienceAnalyticsDevicePerformanceAverageRestarts struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsDevicePerformanceAverageBlueScreens - Average (mean) number of Blue Screens per device in the last 30 days. Valid values 0 to 9999999
type UserExperienceAnalyticsDevicePerformanceAverageBlueScreens struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsBaseline struct for UserExperienceAnalyticsBaseline
type UserExperienceAnalyticsBaseline struct {
	Entity
	// The date the custom baseline was created. The value cannot be modified and is automatically populated when the baseline is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Returned by default.
	CreatedDateTime *time.Time `json:"createdDateTime,omitempty"`
	// The name of the baseline.
	DisplayName *string `json:"displayName,omitempty"`
	// When TRUE, indicates the current baseline is the commercial median baseline. When FALSE, indicates it is a custom baseline. FALSE by default.
	IsBuiltIn                    *bool                            `json:"isBuiltIn,omitempty"`
	AppHealthMetrics             *UserExperienceAnalyticsCategory `json:"appHealthMetrics,omitempty"`
	BatteryHealthMetrics         *UserExperienceAnalyticsCategory `json:"batteryHealthMetrics,omitempty"`
	BestPracticesMetrics         *UserExperienceAnalyticsCategory `json:"bestPracticesMetrics,omitempty"`
	DeviceBootPerformanceMetrics *UserExperienceAnalyticsCategory `json:"deviceBootPerformanceMetrics,omitempty"`
	RebootAnalyticsMetrics       *UserExperienceAnalyticsCategory `json:"rebootAnalyticsMetrics,omitempty"`
	ResourcePerformanceMetrics   *UserExperienceAnalyticsCategory `json:"resourcePerformanceMetrics,omitempty"`
	WorkFromAnywhereMetrics      *UserExperienceAnalyticsCategory `json:"workFromAnywhereMetrics,omitempty"`
	OdataType                    string                           `json:"@odata.type"`
}

// UserExperienceAnalyticsInsightValue The value in an user experience analytics insight.
type UserExperienceAnalyticsInsightValue struct {
	OdataType string `json:"@odata.type"`
}

// UserExperienceAnalyticsInsightSeverity Indicates severity of insights. Possible values are: None, Informational, Warning, Error.
type UserExperienceAnalyticsInsightSeverity string

// List of microsoft.graph.userExperienceAnalyticsInsightSeverity
const (
	USEREXPERIENCEANALYTICSINSIGHTSEVERITY_NONE                 UserExperienceAnalyticsInsightSeverity = "none"
	USEREXPERIENCEANALYTICSINSIGHTSEVERITY_INFORMATIONAL        UserExperienceAnalyticsInsightSeverity = "informational"
	USEREXPERIENCEANALYTICSINSIGHTSEVERITY_WARNING              UserExperienceAnalyticsInsightSeverity = "warning"
	USEREXPERIENCEANALYTICSINSIGHTSEVERITY_ERROR                UserExperienceAnalyticsInsightSeverity = "error"
	USEREXPERIENCEANALYTICSINSIGHTSEVERITY_UNKNOWN_FUTURE_VALUE UserExperienceAnalyticsInsightSeverity = "unknownFutureValue"
)

// All allowed values of UserExperienceAnalyticsInsightSeverity enum
var AllowedUserExperienceAnalyticsInsightSeverityEnumValues = []UserExperienceAnalyticsInsightSeverity{
	"none",
	"informational",
	"warning",
	"error",
	"unknownFutureValue",
}

func (v *UserExperienceAnalyticsInsightSeverity) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := UserExperienceAnalyticsInsightSeverity(value)
	for _, existing := range AllowedUserExperienceAnalyticsInsightSeverityEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid UserExperienceAnalyticsInsightSeverity", value)
}

// UserExperienceAnalyticsInsight The user experience analytics insight is the recomendation to improve the user experience analytics score.
type UserExperienceAnalyticsInsight struct {
	// The unique identifier of the user experience analytics insight.
	InsightId *string                                 `json:"insightId,omitempty"`
	Severity  *UserExperienceAnalyticsInsightSeverity `json:"severity,omitempty"`
	// The unique identifier of the user experience analytics metric.
	UserExperienceAnalyticsMetricId *string `json:"userExperienceAnalyticsMetricId,omitempty"`
	// The value of the user experience analytics insight.
	Values    []UserExperienceAnalyticsInsightValue `json:"values,omitempty"`
	OdataType string                                `json:"@odata.type"`
}

// UserExperienceAnalyticsCategory struct for UserExperienceAnalyticsCategory
type UserExperienceAnalyticsCategory struct {
	Entity
	// The insights for the category. Read-only.
	Insights []UserExperienceAnalyticsInsight `json:"insights,omitempty"`
	// The metric values for the user experience analytics category. Read-only.
	MetricValues []UserExperienceAnalyticsMetric `json:"metricValues,omitempty"`
	OdataType    string                          `json:"@odata.type"`
}

// UserExperienceAnalyticsMetricValue - The value of the user experience analytics metric.
type UserExperienceAnalyticsMetricValue struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsMetric struct for UserExperienceAnalyticsMetric
type UserExperienceAnalyticsMetric struct {
	Entity
	// The unit of the user experience analytics metric. Examples: none, percentage, count, seconds, score.
	Unit      *string                             `json:"unit,omitempty"`
	Value     *UserExperienceAnalyticsMetricValue `json:"value,omitempty"`
	OdataType string                              `json:"@odata.type"`
}

// UserExperienceAnalyticsAppHealthOSVersionPerformanceOsVersionAppHealthScore - The application health score of the OS version. Valid values 0 to 100. Supports: $filter, $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsAppHealthOSVersionPerformanceOsVersionAppHealthScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsAppHealthOSVersionPerformance struct for UserExperienceAnalyticsAppHealthOSVersionPerformance
type UserExperienceAnalyticsAppHealthOSVersionPerformance struct {
	Entity
	// The number of active devices for the OS version. Valid values 0 to 2147483647. Supports: $filter, $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	ActiveDeviceCount *int32 `json:"activeDeviceCount,omitempty"`
	// The mean time to failure for the application in minutes. Valid values 0 to 2147483647. Supports: $filter, $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	MeanTimeToFailureInMinutes *int32 `json:"meanTimeToFailureInMinutes,omitempty"`
	// The OS build number installed on the device. Supports: $select, $OrderBy. Read-only.
	OsBuildNumber *string `json:"osBuildNumber,omitempty"`
	// The OS version installed on the device. Supports: $select, $OrderBy. Read-only.
	OsVersion               *string                                                                      `json:"osVersion,omitempty"`
	OsVersionAppHealthScore *UserExperienceAnalyticsAppHealthOSVersionPerformanceOsVersionAppHealthScore `json:"osVersionAppHealthScore,omitempty"`
	OdataType               string                                                                       `json:"@odata.type"`
}

// UserExperienceAnalyticsAppHealthDevicePerformanceDetails struct for UserExperienceAnalyticsAppHealthDevicePerformanceDetails
type UserExperienceAnalyticsAppHealthDevicePerformanceDetails struct {
	Entity
	// The friendly name of the application for which the event occurred. Possible values are: outlook.exe, excel.exe. Supports: $select, $OrderBy. Read-only.
	AppDisplayName *string `json:"appDisplayName,omitempty"`
	// The publisher of the application. Supports: $select, $OrderBy. Read-only.
	AppPublisher *string `json:"appPublisher,omitempty"`
	// The version of the application. Possible values are: 1.0.0.1, 75.65.23.9. Supports: $select, $OrderBy. Read-only.
	AppVersion *string `json:"appVersion,omitempty"`
	// The name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceDisplayName *string `json:"deviceDisplayName,omitempty"`
	// The Intune device id of the device. Supports: $select, $OrderBy. Read-only.
	DeviceId *string `json:"deviceId,omitempty"`
	// The time the event occurred. The value cannot be modified and is automatically populated when the statistics are computed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2022 would look like this: '2022-01-01T00:00:00Z'. Returned by default. Read-only.
	EventDateTime *time.Time `json:"eventDateTime,omitempty"`
	// The type of the event. Supports: $select, $OrderBy. Read-only.
	EventType *string `json:"eventType,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// UserExperienceAnalyticsHealthState the model 'UserExperienceAnalyticsHealthState'
type UserExperienceAnalyticsHealthState string

// List of microsoft.graph.userExperienceAnalyticsHealthState
const (
	USEREXPERIENCEANALYTICSHEALTHSTATE_UNKNOWN              UserExperienceAnalyticsHealthState = "unknown"
	USEREXPERIENCEANALYTICSHEALTHSTATE_INSUFFICIENT_DATA    UserExperienceAnalyticsHealthState = "insufficientData"
	USEREXPERIENCEANALYTICSHEALTHSTATE_NEEDS_ATTENTION      UserExperienceAnalyticsHealthState = "needsAttention"
	USEREXPERIENCEANALYTICSHEALTHSTATE_MEETING_GOALS        UserExperienceAnalyticsHealthState = "meetingGoals"
	USEREXPERIENCEANALYTICSHEALTHSTATE_UNKNOWN_FUTURE_VALUE UserExperienceAnalyticsHealthState = "unknownFutureValue"
)

// All allowed values of UserExperienceAnalyticsHealthState enum
var AllowedUserExperienceAnalyticsHealthStateEnumValues = []UserExperienceAnalyticsHealthState{
	"unknown",
	"insufficientData",
	"needsAttention",
	"meetingGoals",
	"unknownFutureValue",
}

func (v *UserExperienceAnalyticsHealthState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := UserExperienceAnalyticsHealthState(value)
	for _, existing := range AllowedUserExperienceAnalyticsHealthStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid UserExperienceAnalyticsHealthState", value)
}

// UserExperienceAnalyticsAppHealthDevicePerformanceDeviceAppHealthScore - The application health score of the device. Valid values 0 to 100. Supports: $filter, $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsAppHealthDevicePerformanceDeviceAppHealthScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsAppHealthDevicePerformance struct for UserExperienceAnalyticsAppHealthDevicePerformance
type UserExperienceAnalyticsAppHealthDevicePerformance struct {
	Entity
	// The number of application crashes for the device. Valid values 0 to 2147483647. Supports: $filter, $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	AppCrashCount *int32 `json:"appCrashCount,omitempty"`
	// The number of application hangs for the device. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	AppHangCount *int32 `json:"appHangCount,omitempty"`
	// The number of distinct application crashes for the device. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	CrashedAppCount      *int32                                                                 `json:"crashedAppCount,omitempty"`
	DeviceAppHealthScore *UserExperienceAnalyticsAppHealthDevicePerformanceDeviceAppHealthScore `json:"deviceAppHealthScore,omitempty"`
	// The name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceDisplayName *string `json:"deviceDisplayName,omitempty"`
	// The Intune device id of the device. Supports: $select, $OrderBy. Read-only.
	DeviceId *string `json:"deviceId,omitempty"`
	// The manufacturer name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceManufacturer *string `json:"deviceManufacturer,omitempty"`
	// The model name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceModel  *string                             `json:"deviceModel,omitempty"`
	HealthStatus *UserExperienceAnalyticsHealthState `json:"healthStatus,omitempty"`
	// The mean time to failure for the application in minutes. Valid values 0 to 2147483647. Supports: $filter, $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	MeanTimeToFailureInMinutes *int32 `json:"meanTimeToFailureInMinutes,omitempty"`
	// The date and time when the statistics were last computed. The value cannot be modified and is automatically populated when the statistics are computed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2022 would look like this: '2022-01-01T00:00:00Z'. Returned by default. Read-only.
	ProcessedDateTime *time.Time `json:"processedDateTime,omitempty"`
	OdataType         string     `json:"@odata.type"`
}

// UserExperienceAnalyticsAppHealthDeviceModelPerformanceModelAppHealthScore - The application health score of the device model. Valid values 0 to 100. Supports: $filter, $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsAppHealthDeviceModelPerformanceModelAppHealthScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsAppHealthDeviceModelPerformance struct for UserExperienceAnalyticsAppHealthDeviceModelPerformance
type UserExperienceAnalyticsAppHealthDeviceModelPerformance struct {
	Entity
	// The number of active devices for the model. Valid values 0 to 2147483647. Supports: $filter, $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	ActiveDeviceCount *int32 `json:"activeDeviceCount,omitempty"`
	// The manufacturer name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceManufacturer *string `json:"deviceManufacturer,omitempty"`
	// The model name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceModel  *string                             `json:"deviceModel,omitempty"`
	HealthStatus *UserExperienceAnalyticsHealthState `json:"healthStatus,omitempty"`
	// The mean time to failure for the application in minutes. Valid values 0 to 2147483647. Supports: $filter, $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	MeanTimeToFailureInMinutes *int32                                                                     `json:"meanTimeToFailureInMinutes,omitempty"`
	ModelAppHealthScore        *UserExperienceAnalyticsAppHealthDeviceModelPerformanceModelAppHealthScore `json:"modelAppHealthScore,omitempty"`
	OdataType                  string                                                                     `json:"@odata.type"`
}

// UserExperienceAnalyticsAppHealthAppPerformanceByOSVersion struct for UserExperienceAnalyticsAppHealthAppPerformanceByOSVersion
type UserExperienceAnalyticsAppHealthAppPerformanceByOSVersion struct {
	Entity
	// The number of devices where the application has been active. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	ActiveDeviceCount *int32 `json:"activeDeviceCount,omitempty"`
	// The number of crashes for the application. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	AppCrashCount *int32 `json:"appCrashCount,omitempty"`
	// The friendly name of the application. Possible values are: Outlook, Excel. Supports: $select, $OrderBy. Read-only.
	AppDisplayName *string `json:"appDisplayName,omitempty"`
	// The name of the application. Possible values are: outlook.exe, excel.exe. Supports: $select, $OrderBy. Read-only.
	AppName *string `json:"appName,omitempty"`
	// The publisher of the application. Supports: $select, $OrderBy. Read-only.
	AppPublisher *string `json:"appPublisher,omitempty"`
	// The total usage time of the application in minutes. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	AppUsageDuration *int32 `json:"appUsageDuration,omitempty"`
	// The mean time to failure for the application in minutes. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	MeanTimeToFailureInMinutes *int32 `json:"meanTimeToFailureInMinutes,omitempty"`
	// The OS build number of the application. Supports: $select, $OrderBy. Read-only.
	OsBuildNumber *string `json:"osBuildNumber,omitempty"`
	// The OS version of the application. Supports: $select, $OrderBy. Read-only.
	OsVersion *string `json:"osVersion,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// UserExperienceAnalyticsAppHealthAppPerformanceByAppVersionDeviceId struct for UserExperienceAnalyticsAppHealthAppPerformanceByAppVersionDeviceId
type UserExperienceAnalyticsAppHealthAppPerformanceByAppVersionDeviceId struct {
	Entity
	// The number of crashes for the app. Valid values -2147483648 to 2147483647
	AppCrashCount *int32 `json:"appCrashCount,omitempty"`
	// The friendly name of the application.
	AppDisplayName *string `json:"appDisplayName,omitempty"`
	// The name of the application.
	AppName *string `json:"appName,omitempty"`
	// The publisher of the application.
	AppPublisher *string `json:"appPublisher,omitempty"`
	// The version of the application.
	AppVersion *string `json:"appVersion,omitempty"`
	// The name of the device. Supports: $select, $OrderBy. Read-only.
	DeviceDisplayName *string `json:"deviceDisplayName,omitempty"`
	// The Intune device id of the device. Supports: $select, $OrderBy. Read-only.
	DeviceId *string `json:"deviceId,omitempty"`
	// The date and time when the statistics were last computed. The value cannot be modified and is automatically populated when the statistics are computed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2022 would look like this: '2022-01-01T00:00:00Z'. Returned by default. Read-only.
	ProcessedDateTime *time.Time `json:"processedDateTime,omitempty"`
	OdataType         string     `json:"@odata.type"`
}

// UserExperienceAnalyticsAppHealthAppPerformanceByAppVersionDetails struct for UserExperienceAnalyticsAppHealthAppPerformanceByAppVersionDetails
type UserExperienceAnalyticsAppHealthAppPerformanceByAppVersionDetails struct {
	Entity
	// The number of crashes for the app. Valid values -2147483648 to 2147483647
	AppCrashCount *int32 `json:"appCrashCount,omitempty"`
	// The friendly name of the application.
	AppDisplayName *string `json:"appDisplayName,omitempty"`
	// The name of the application.
	AppName *string `json:"appName,omitempty"`
	// The publisher of the application.
	AppPublisher *string `json:"appPublisher,omitempty"`
	// The version of the application.
	AppVersion *string `json:"appVersion,omitempty"`
	// The total number of devices that have reported one or more application crashes for this application and version. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	DeviceCountWithCrashes *int32 `json:"deviceCountWithCrashes,omitempty"`
	// When TRUE, indicates the version of application is the latest version for that application that is in use. When FALSE, indicates the version is not the latest version. FALSE by default. Supports: $select, $OrderBy.
	IsLatestUsedVersion *bool `json:"isLatestUsedVersion,omitempty"`
	// When TRUE, indicates the version of application is the most used version for that application. When FALSE, indicates the version is not the most used version. FALSE by default. Supports: $select, $OrderBy. Read-only.
	IsMostUsedVersion *bool  `json:"isMostUsedVersion,omitempty"`
	OdataType         string `json:"@odata.type"`
}

// UserExperienceAnalyticsAppHealthApplicationPerformanceAppHealthScore - The health score of the application. Valid values 0 to 100. Supports: $filter, $select, $OrderBy. Read-only. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type UserExperienceAnalyticsAppHealthApplicationPerformanceAppHealthScore struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// UserExperienceAnalyticsAppHealthApplicationPerformance struct for UserExperienceAnalyticsAppHealthApplicationPerformance
type UserExperienceAnalyticsAppHealthApplicationPerformance struct {
	Entity
	// The health score of the application. Valid values 0 to 100. Supports: $filter, $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	ActiveDeviceCount *int32 `json:"activeDeviceCount,omitempty"`
	// The number of crashes for the application. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	AppCrashCount *int32 `json:"appCrashCount,omitempty"`
	// The friendly name of the application. Possible values are: Outlook, Excel. Supports: $select, $OrderBy. Read-only.
	AppDisplayName *string `json:"appDisplayName,omitempty"`
	// The number of hangs for the application. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	AppHangCount   *int32                                                                `json:"appHangCount,omitempty"`
	AppHealthScore *UserExperienceAnalyticsAppHealthApplicationPerformanceAppHealthScore `json:"appHealthScore,omitempty"`
	// The name of the application. Possible values are: outlook.exe, excel.exe. Supports: $select, $OrderBy. Read-only.
	AppName *string `json:"appName,omitempty"`
	// The publisher of the application. Supports: $select, $OrderBy. Read-only.
	AppPublisher *string `json:"appPublisher,omitempty"`
	// The total usage time of the application in minutes. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	AppUsageDuration *int32 `json:"appUsageDuration,omitempty"`
	// The mean time to failure for the application in minutes. Valid values 0 to 2147483647. Supports: $select, $OrderBy. Read-only. Valid values -2147483648 to 2147483647
	MeanTimeToFailureInMinutes *int32 `json:"meanTimeToFailureInMinutes,omitempty"`
	OdataType                  string `json:"@odata.type"`
}

// DeviceManagementTroubleshootingEvent struct for DeviceManagementTroubleshootingEvent
type DeviceManagementTroubleshootingEvent struct {
	Entity
	// Id used for tracing the failure in the service.
	CorrelationId *string `json:"correlationId,omitempty"`
	// Time when the event occurred .
	EventDateTime *time.Time `json:"eventDateTime,omitempty"`
	OdataType     string     `json:"@odata.type"`
}

// TermsAndConditionsAssignment struct for TermsAndConditionsAssignment
type TermsAndConditionsAssignment struct {
	Entity
	Target    *DeviceAndAppManagementAssignmentTarget `json:"target,omitempty"`
	OdataType string                                  `json:"@odata.type"`
}

// TermsAndConditionsAcceptanceStatus struct for TermsAndConditionsAcceptanceStatus
type TermsAndConditionsAcceptanceStatus struct {
	Entity
	// DateTime when the terms were last accepted by the user.
	AcceptedDateTime *time.Time `json:"acceptedDateTime,omitempty"`
	// Most recent version number of the T&C accepted by the user.
	AcceptedVersion *int32 `json:"acceptedVersion,omitempty"`
	// Display name of the user whose acceptance the entity represents.
	UserDisplayName *string `json:"userDisplayName,omitempty"`
	// The userPrincipalName of the User that accepted the term.
	UserPrincipalName  *string             `json:"userPrincipalName,omitempty"`
	TermsAndConditions *TermsAndConditions `json:"termsAndConditions,omitempty"`
	OdataType          string              `json:"@odata.type"`
}

// TermsAndConditions struct for TermsAndConditions
type TermsAndConditions struct {
	Entity
	// Administrator-supplied explanation of the terms and conditions, typically describing what it means to accept the terms and conditions set out in the T&C policy. This is shown to the user on prompts to accept the T&C policy.
	AcceptanceStatement *string `json:"acceptanceStatement,omitempty"`
	// Administrator-supplied body text of the terms and conditions, typically the terms themselves. This is shown to the user on prompts to accept the T&C policy.
	BodyText *string `json:"bodyText,omitempty"`
	// DateTime the object was created.
	CreatedDateTime *time.Time `json:"createdDateTime,omitempty"`
	// Administrator-supplied description of the T&C policy.
	Description *string `json:"description,omitempty"`
	// Administrator-supplied name for the T&C policy.
	DisplayName *string `json:"displayName,omitempty"`
	// DateTime the object was last modified.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// Administrator-supplied title of the terms and conditions. This is shown to the user on prompts to accept the T&C policy.
	Title *string `json:"title,omitempty"`
	// Integer indicating the current version of the terms. Incremented when an administrator makes a change to the terms and wishes to require users to re-accept the modified T&C policy.
	Version *int32 `json:"version,omitempty"`
	// The list of acceptance statuses for this T&C policy.
	AcceptanceStatuses []TermsAndConditionsAcceptanceStatus `json:"acceptanceStatuses,omitempty"`
	// The list of assignments for this T&C policy.
	Assignments []TermsAndConditionsAssignment `json:"assignments,omitempty"`
	OdataType   string                         `json:"@odata.type"`
}

// TelecomExpenseManagementPartner struct for TelecomExpenseManagementPartner
type TelecomExpenseManagementPartner struct {
	Entity
	// Whether the partner's AAD app has been authorized to access Intune.
	AppAuthorized *bool `json:"appAuthorized,omitempty"`
	// Display name of the TEM partner.
	DisplayName *string `json:"displayName,omitempty"`
	// Whether Intune's connection to the TEM service is currently enabled or disabled.
	Enabled *bool `json:"enabled,omitempty"`
	// Timestamp of the last request sent to Intune by the TEM partner.
	LastConnectionDateTime *time.Time `json:"lastConnectionDateTime,omitempty"`
	// URL of the TEM partner's administrative control panel, where an administrator can configure their TEM service.
	Url       *string `json:"url,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// SoftwareUpdateStatusSummary struct for SoftwareUpdateStatusSummary
type SoftwareUpdateStatusSummary struct {
	Entity
	// Number of compliant devices.
	CompliantDeviceCount *int32 `json:"compliantDeviceCount,omitempty"`
	// Number of compliant users.
	CompliantUserCount *int32 `json:"compliantUserCount,omitempty"`
	// Number of conflict devices.
	ConflictDeviceCount *int32 `json:"conflictDeviceCount,omitempty"`
	// Number of conflict users.
	ConflictUserCount *int32 `json:"conflictUserCount,omitempty"`
	// The name of the policy.
	DisplayName *string `json:"displayName,omitempty"`
	// Number of devices had error.
	ErrorDeviceCount *int32 `json:"errorDeviceCount,omitempty"`
	// Number of users had error.
	ErrorUserCount *int32 `json:"errorUserCount,omitempty"`
	// Number of non compliant devices.
	NonCompliantDeviceCount *int32 `json:"nonCompliantDeviceCount,omitempty"`
	// Number of non compliant users.
	NonCompliantUserCount *int32 `json:"nonCompliantUserCount,omitempty"`
	// Number of not applicable devices.
	NotApplicableDeviceCount *int32 `json:"notApplicableDeviceCount,omitempty"`
	// Number of not applicable users.
	NotApplicableUserCount *int32 `json:"notApplicableUserCount,omitempty"`
	// Number of remediated devices.
	RemediatedDeviceCount *int32 `json:"remediatedDeviceCount,omitempty"`
	// Number of remediated users.
	RemediatedUserCount *int32 `json:"remediatedUserCount,omitempty"`
	// Number of unknown devices.
	UnknownDeviceCount *int32 `json:"unknownDeviceCount,omitempty"`
	// Number of unknown users.
	UnknownUserCount *int32 `json:"unknownUserCount,omitempty"`
	OdataType        string `json:"@odata.type"`
}

// RoleDefinition struct for RoleDefinition
type RoleDefinition struct {
	Entity
	// Description of the Role definition.
	Description *string `json:"description,omitempty"`
	// Display Name of the Role definition.
	DisplayName *string `json:"displayName,omitempty"`
	// Type of Role. Set to True if it is built-in, or set to False if it is a custom role definition.
	IsBuiltIn *bool `json:"isBuiltIn,omitempty"`
	// List of Role Permissions this role is allowed to perform. These must match the actionName that is defined as part of the rolePermission.
	RolePermissions []RolePermission `json:"rolePermissions,omitempty"`
	// List of Role assignments for this role definition.
	RoleAssignments []RoleAssignment `json:"roleAssignments,omitempty"`
	OdataType       string           `json:"@odata.type"`
}

// ResourceAction Set of allowed and not allowed actions for a resource.
type ResourceAction struct {
	// Allowed Actions
	AllowedResourceActions []*string `json:"allowedResourceActions,omitempty"`
	// Not Allowed Actions.
	NotAllowedResourceActions []*string `json:"notAllowedResourceActions,omitempty"`
	OdataType                 string    `json:"@odata.type"`
}

// RolePermission Contains the set of ResourceActions determining the allowed and not allowed permissions for each role.
type RolePermission struct {
	// Resource Actions each containing a set of allowed and not allowed permissions.
	ResourceActions []ResourceAction `json:"resourceActions,omitempty"`
	OdataType       string           `json:"@odata.type"`
}

// RoleAssignment struct for RoleAssignment
type RoleAssignment struct {
	Entity
	// Description of the Role Assignment.
	Description *string `json:"description,omitempty"`
	// The display or friendly name of the role Assignment.
	DisplayName *string `json:"displayName,omitempty"`
	// List of ids of role scope member security groups.  These are IDs from Azure Active Directory.
	ResourceScopes []*string       `json:"resourceScopes,omitempty"`
	RoleDefinition *RoleDefinition `json:"roleDefinition,omitempty"`
	OdataType      string          `json:"@odata.type"`
}

// DeviceAndAppManagementRoleAssignment struct for DeviceAndAppManagementRoleAssignment
type DeviceAndAppManagementRoleAssignment struct {
	RoleAssignment
	// The list of ids of role member security groups. These are IDs from Azure Active Directory.
	Members   []*string `json:"members,omitempty"`
	OdataType string    `json:"@odata.type"`
}

// ResourceOperation struct for ResourceOperation
type ResourceOperation struct {
	Entity
	// Type of action this operation is going to perform. The actionName should be concise and limited to as few words as possible.
	ActionName *string `json:"actionName,omitempty"`
	// Description of the resource operation. The description is used in mouse-over text for the operation when shown in the Azure Portal.
	Description *string `json:"description,omitempty"`
	// Name of the Resource this operation is performed on.
	ResourceName *string `json:"resourceName,omitempty"`
	OdataType    string  `json:"@odata.type"`
}

// DeviceManagementReportStatus Possible statuses associated with a generated report.
type DeviceManagementReportStatus string

// List of microsoft.graph.deviceManagementReportStatus
const (
	DEVICEMANAGEMENTREPORTSTATUS_UNKNOWN     DeviceManagementReportStatus = "unknown"
	DEVICEMANAGEMENTREPORTSTATUS_NOT_STARTED DeviceManagementReportStatus = "notStarted"
	DEVICEMANAGEMENTREPORTSTATUS_IN_PROGRESS DeviceManagementReportStatus = "inProgress"
	DEVICEMANAGEMENTREPORTSTATUS_COMPLETED   DeviceManagementReportStatus = "completed"
	DEVICEMANAGEMENTREPORTSTATUS_FAILED      DeviceManagementReportStatus = "failed"
)

// All allowed values of DeviceManagementReportStatus enum
var AllowedDeviceManagementReportStatusEnumValues = []DeviceManagementReportStatus{
	"unknown",
	"notStarted",
	"inProgress",
	"completed",
	"failed",
}

func (v *DeviceManagementReportStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementReportStatus(value)
	for _, existing := range AllowedDeviceManagementReportStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementReportStatus", value)
}

// DeviceManagementExportJobLocalizationType Configures how the requested export job is localized.
type DeviceManagementExportJobLocalizationType string

// List of microsoft.graph.deviceManagementExportJobLocalizationType
const (
	DEVICEMANAGEMENTEXPORTJOBLOCALIZATIONTYPE_LOCALIZED_VALUES_AS_ADDITIONAL_COLUMN DeviceManagementExportJobLocalizationType = "localizedValuesAsAdditionalColumn"
	DEVICEMANAGEMENTEXPORTJOBLOCALIZATIONTYPE_REPLACE_LOCALIZABLE_VALUES            DeviceManagementExportJobLocalizationType = "replaceLocalizableValues"
)

// All allowed values of DeviceManagementExportJobLocalizationType enum
var AllowedDeviceManagementExportJobLocalizationTypeEnumValues = []DeviceManagementExportJobLocalizationType{
	"localizedValuesAsAdditionalColumn",
	"replaceLocalizableValues",
}

func (v *DeviceManagementExportJobLocalizationType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementExportJobLocalizationType(value)
	for _, existing := range AllowedDeviceManagementExportJobLocalizationTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementExportJobLocalizationType", value)
}

// DeviceManagementReportFileFormat Possible values for the file format of a report.
type DeviceManagementReportFileFormat string

// List of microsoft.graph.deviceManagementReportFileFormat
const (
	DEVICEMANAGEMENTREPORTFILEFORMAT_CSV                  DeviceManagementReportFileFormat = "csv"
	DEVICEMANAGEMENTREPORTFILEFORMAT_PDF                  DeviceManagementReportFileFormat = "pdf"
	DEVICEMANAGEMENTREPORTFILEFORMAT_JSON                 DeviceManagementReportFileFormat = "json"
	DEVICEMANAGEMENTREPORTFILEFORMAT_UNKNOWN_FUTURE_VALUE DeviceManagementReportFileFormat = "unknownFutureValue"
)

// All allowed values of DeviceManagementReportFileFormat enum
var AllowedDeviceManagementReportFileFormatEnumValues = []DeviceManagementReportFileFormat{
	"csv",
	"pdf",
	"json",
	"unknownFutureValue",
}

func (v *DeviceManagementReportFileFormat) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementReportFileFormat(value)
	for _, existing := range AllowedDeviceManagementReportFileFormatEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementReportFileFormat", value)
}

// DeviceManagementExportJob struct for DeviceManagementExportJob
type DeviceManagementExportJob struct {
	Entity
	// Time that the exported report expires
	ExpirationDateTime *time.Time `json:"expirationDateTime,omitempty"`
	// Filters applied on the report
	Filter           *string                                    `json:"filter,omitempty"`
	Format           *DeviceManagementReportFileFormat          `json:"format,omitempty"`
	LocalizationType *DeviceManagementExportJobLocalizationType `json:"localizationType,omitempty"`
	// Name of the report
	ReportName *string `json:"reportName,omitempty"`
	// Time that the exported report was requested
	RequestDateTime *time.Time `json:"requestDateTime,omitempty"`
	// Columns selected from the report
	Select []*string `json:"select,omitempty"`
	// A snapshot is an identifiable subset of the dataset represented by the ReportName. A sessionId or CachedReportConfiguration id can be used here. If a sessionId is specified, Filter, Select, and OrderBy are applied to the data represented by the sessionId. Filter, Select, and OrderBy cannot be specified together with a CachedReportConfiguration id.
	SnapshotId *string                       `json:"snapshotId,omitempty"`
	Status     *DeviceManagementReportStatus `json:"status,omitempty"`
	// Temporary location of the exported report
	Url       *string `json:"url,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// DeviceManagementReports struct for DeviceManagementReports
type DeviceManagementReports struct {
	Entity
	// Entity representing a job to export a report
	ExportJobs []DeviceManagementExportJob `json:"exportJobs,omitempty"`
	OdataType  string                      `json:"@odata.type"`
}

// RemoteAssistanceOnboardingStatus The current TeamViewer connector status
type RemoteAssistanceOnboardingStatus string

// List of microsoft.graph.remoteAssistanceOnboardingStatus
const (
	REMOTEASSISTANCEONBOARDINGSTATUS_NOT_ONBOARDED RemoteAssistanceOnboardingStatus = "notOnboarded"
	REMOTEASSISTANCEONBOARDINGSTATUS_ONBOARDING    RemoteAssistanceOnboardingStatus = "onboarding"
	REMOTEASSISTANCEONBOARDINGSTATUS_ONBOARDED     RemoteAssistanceOnboardingStatus = "onboarded"
)

// All allowed values of RemoteAssistanceOnboardingStatus enum
var AllowedRemoteAssistanceOnboardingStatusEnumValues = []RemoteAssistanceOnboardingStatus{
	"notOnboarded",
	"onboarding",
	"onboarded",
}

func (v *RemoteAssistanceOnboardingStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := RemoteAssistanceOnboardingStatus(value)
	for _, existing := range AllowedRemoteAssistanceOnboardingStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid RemoteAssistanceOnboardingStatus", value)
}

// RemoteAssistancePartner struct for RemoteAssistancePartner
type RemoteAssistancePartner struct {
	Entity
	// Display name of the partner.
	DisplayName *string `json:"displayName,omitempty"`
	// Timestamp of the last request sent to Intune by the TEM partner.
	LastConnectionDateTime *time.Time                        `json:"lastConnectionDateTime,omitempty"`
	OnboardingStatus       *RemoteAssistanceOnboardingStatus `json:"onboardingStatus,omitempty"`
	// URL of the partner's onboarding portal, where an administrator can configure their Remote Assistance service.
	OnboardingUrl *string `json:"onboardingUrl,omitempty"`
	OdataType     string  `json:"@odata.type"`
}

// LocalizedNotificationMessage struct for LocalizedNotificationMessage
type LocalizedNotificationMessage struct {
	Entity
	// Flag to indicate whether or not this is the default locale for language fallback. This flag can only be set. To unset, set this property to true on another Localized Notification Message.
	IsDefault *bool `json:"isDefault,omitempty"`
	// DateTime the object was last modified.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// The Locale for which this message is destined.
	Locale *string `json:"locale,omitempty"`
	// The Message Template content.
	MessageTemplate *string `json:"messageTemplate,omitempty"`
	// The Message Template Subject.
	Subject   *string `json:"subject,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// NotificationTemplateBrandingOptions Branding Options for the Message Template. Branding is defined in the Intune Admin Console.
type NotificationTemplateBrandingOptions string

// List of microsoft.graph.notificationTemplateBrandingOptions
const (
	NOTIFICATIONTEMPLATEBRANDINGOPTIONS_NONE                        NotificationTemplateBrandingOptions = "none"
	NOTIFICATIONTEMPLATEBRANDINGOPTIONS_INCLUDE_COMPANY_LOGO        NotificationTemplateBrandingOptions = "includeCompanyLogo"
	NOTIFICATIONTEMPLATEBRANDINGOPTIONS_INCLUDE_COMPANY_NAME        NotificationTemplateBrandingOptions = "includeCompanyName"
	NOTIFICATIONTEMPLATEBRANDINGOPTIONS_INCLUDE_CONTACT_INFORMATION NotificationTemplateBrandingOptions = "includeContactInformation"
	NOTIFICATIONTEMPLATEBRANDINGOPTIONS_INCLUDE_COMPANY_PORTAL_LINK NotificationTemplateBrandingOptions = "includeCompanyPortalLink"
	NOTIFICATIONTEMPLATEBRANDINGOPTIONS_INCLUDE_DEVICE_DETAILS      NotificationTemplateBrandingOptions = "includeDeviceDetails"
	NOTIFICATIONTEMPLATEBRANDINGOPTIONS_UNKNOWN_FUTURE_VALUE        NotificationTemplateBrandingOptions = "unknownFutureValue"
)

// All allowed values of NotificationTemplateBrandingOptions enum
var AllowedNotificationTemplateBrandingOptionsEnumValues = []NotificationTemplateBrandingOptions{
	"none",
	"includeCompanyLogo",
	"includeCompanyName",
	"includeContactInformation",
	"includeCompanyPortalLink",
	"includeDeviceDetails",
	"unknownFutureValue",
}

func (v *NotificationTemplateBrandingOptions) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := NotificationTemplateBrandingOptions(value)
	for _, existing := range AllowedNotificationTemplateBrandingOptionsEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid NotificationTemplateBrandingOptions", value)
}

// NotificationMessageTemplate struct for NotificationMessageTemplate
type NotificationMessageTemplate struct {
	Entity
	BrandingOptions *NotificationTemplateBrandingOptions `json:"brandingOptions,omitempty"`
	// The default locale to fallback onto when the requested locale is not available.
	DefaultLocale *string `json:"defaultLocale,omitempty"`
	// Display name for the Notification Message Template.
	DisplayName *string `json:"displayName,omitempty"`
	// DateTime the object was last modified.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// List of Scope Tags for this Entity instance.
	RoleScopeTagIds []*string `json:"roleScopeTagIds,omitempty"`
	// The list of localized messages for this Notification Message Template.
	LocalizedNotificationMessages []LocalizedNotificationMessage `json:"localizedNotificationMessages,omitempty"`
	OdataType                     string                         `json:"@odata.type"`
}

// MobileThreatPartnerTenantState Partner state of this tenant.
type MobileThreatPartnerTenantState string

// List of microsoft.graph.mobileThreatPartnerTenantState
const (
	MOBILETHREATPARTNERTENANTSTATE_UNAVAILABLE          MobileThreatPartnerTenantState = "unavailable"
	MOBILETHREATPARTNERTENANTSTATE_AVAILABLE            MobileThreatPartnerTenantState = "available"
	MOBILETHREATPARTNERTENANTSTATE_ENABLED              MobileThreatPartnerTenantState = "enabled"
	MOBILETHREATPARTNERTENANTSTATE_UNRESPONSIVE         MobileThreatPartnerTenantState = "unresponsive"
	MOBILETHREATPARTNERTENANTSTATE_UNKNOWN_FUTURE_VALUE MobileThreatPartnerTenantState = "unknownFutureValue"
)

// All allowed values of MobileThreatPartnerTenantState enum
var AllowedMobileThreatPartnerTenantStateEnumValues = []MobileThreatPartnerTenantState{
	"unavailable",
	"available",
	"enabled",
	"unresponsive",
	"unknownFutureValue",
}

func (v *MobileThreatPartnerTenantState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := MobileThreatPartnerTenantState(value)
	for _, existing := range AllowedMobileThreatPartnerTenantStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid MobileThreatPartnerTenantState", value)
}

// MobileThreatDefenseConnector struct for MobileThreatDefenseConnector
type MobileThreatDefenseConnector struct {
	Entity
	// When TRUE, indicates the Mobile Threat Defense partner may collect metadata about installed applications from Intune for IOS devices. When FALSE, indicates the Mobile Threat Defense partner may not collect metadata about installed applications from Intune for IOS devices. Default value is FALSE.
	AllowPartnerToCollectIOSApplicationMetadata *bool `json:"allowPartnerToCollectIOSApplicationMetadata,omitempty"`
	// When TRUE, indicates the Mobile Threat Defense partner may collect metadata about personally installed applications from Intune for IOS devices. When FALSE, indicates the Mobile Threat Defense partner may not collect metadata about personally installed applications from Intune for IOS devices. Default value is FALSE.
	AllowPartnerToCollectIOSPersonalApplicationMetadata *bool `json:"allowPartnerToCollectIOSPersonalApplicationMetadata,omitempty"`
	// For Android, set whether Intune must receive data from the Mobile Threat Defense partner prior to marking a device compliant
	AndroidDeviceBlockedOnMissingPartnerData *bool `json:"androidDeviceBlockedOnMissingPartnerData,omitempty"`
	// For Android, set whether data from the Mobile Threat Defense partner should be used during compliance evaluations
	AndroidEnabled *bool `json:"androidEnabled,omitempty"`
	// When TRUE, inidicates that data from the Mobile Threat Defense partner can be used during Mobile Application Management (MAM) evaluations for Android devices. When FALSE, inidicates that data from the Mobile Threat Defense partner should not be used during Mobile Application Management (MAM) evaluations for Android devices. Only one partner per platform may be enabled for Mobile Application Management (MAM) evaluation. Default value is FALSE.
	AndroidMobileApplicationManagementEnabled *bool `json:"androidMobileApplicationManagementEnabled,omitempty"`
	// For IOS, set whether Intune must receive data from the Mobile Threat Defense partner prior to marking a device compliant
	IosDeviceBlockedOnMissingPartnerData *bool `json:"iosDeviceBlockedOnMissingPartnerData,omitempty"`
	// For IOS, get or set whether data from the Mobile Threat Defense partner should be used during compliance evaluations
	IosEnabled *bool `json:"iosEnabled,omitempty"`
	// When TRUE, inidicates that data from the Mobile Threat Defense partner can be used during Mobile Application Management (MAM) evaluations for IOS devices. When FALSE, inidicates that data from the Mobile Threat Defense partner should not be used during Mobile Application Management (MAM) evaluations for IOS devices. Only one partner per platform may be enabled for Mobile Application Management (MAM) evaluation. Default value is FALSE.
	IosMobileApplicationManagementEnabled *bool `json:"iosMobileApplicationManagementEnabled,omitempty"`
	// DateTime of last Heartbeat recieved from the Mobile Threat Defense partner
	LastHeartbeatDateTime *time.Time `json:"lastHeartbeatDateTime,omitempty"`
	// When TRUE, inidicates that configuration profile management via Microsoft Defender for Endpoint is enabled. When FALSE, inidicates that configuration profile management via Microsoft Defender for Endpoint is disabled. Default value is FALSE.
	MicrosoftDefenderForEndpointAttachEnabled *bool                           `json:"microsoftDefenderForEndpointAttachEnabled,omitempty"`
	PartnerState                              *MobileThreatPartnerTenantState `json:"partnerState,omitempty"`
	// Get or Set days the per tenant tolerance to unresponsiveness for this partner integration
	PartnerUnresponsivenessThresholdInDays *int32 `json:"partnerUnresponsivenessThresholdInDays,omitempty"`
	// Get or set whether to block devices on the enabled platforms that do not meet the minimum version requirements of the Mobile Threat Defense partner
	PartnerUnsupportedOsVersionBlocked *bool `json:"partnerUnsupportedOsVersionBlocked,omitempty"`
	// When TRUE, inidicates that Intune must receive data from the Mobile Threat Defense partner prior to marking a device compliant for Windows. When FALSE, inidicates that Intune may make a device compliant without receiving data from the Mobile Threat Defense partner for Windows. Default value is FALSE.
	WindowsDeviceBlockedOnMissingPartnerData *bool `json:"windowsDeviceBlockedOnMissingPartnerData,omitempty"`
	// When TRUE, inidicates that data from the Mobile Threat Defense partner can be used during compliance evaluations for Windows. When FALSE, inidicates that data from the Mobile Threat Defense partner should not be used during compliance evaluations for Windows. Default value is FALSE.
	WindowsEnabled *bool  `json:"windowsEnabled,omitempty"`
	OdataType      string `json:"@odata.type"`
}

// AppLogCollectionRequest struct for AppLogCollectionRequest
type AppLogCollectionRequest struct {
	Entity
	// Time at which the upload log request reached a completed state if not completed yet NULL will be returned.
	CompletedDateTime *time.Time `json:"completedDateTime,omitempty"`
	// List of log folders.
	CustomLogFolders []*string `json:"customLogFolders,omitempty"`
	// Indicates error message if any during the upload process.
	ErrorMessage *string            `json:"errorMessage,omitempty"`
	Status       *AppLogUploadState `json:"status,omitempty"`
	OdataType    string             `json:"@odata.type"`
}

// MobileAppTroubleshootingEvent struct for MobileAppTroubleshootingEvent
type MobileAppTroubleshootingEvent struct {
	Entity
	// Indicates collection of App Log Upload Request.
	AppLogCollectionRequests []AppLogCollectionRequest `json:"appLogCollectionRequests,omitempty"`
	OdataType                string                    `json:"@odata.type"`
}

// DeviceOperatingSystemSummary Device operating system summary.
type DeviceOperatingSystemSummary struct {
	// The count of Corporate work profile Android devices. Also known as Corporate Owned Personally Enabled (COPE). Valid values -1 to 2147483647
	AndroidCorporateWorkProfileCount *int32 `json:"androidCorporateWorkProfileCount,omitempty"`
	// Number of android device count.
	AndroidCount *int32 `json:"androidCount,omitempty"`
	// Number of dedicated Android devices.
	AndroidDedicatedCount *int32 `json:"androidDedicatedCount,omitempty"`
	// Number of device admin Android devices.
	AndroidDeviceAdminCount *int32 `json:"androidDeviceAdminCount,omitempty"`
	// Number of fully managed Android devices.
	AndroidFullyManagedCount *int32 `json:"androidFullyManagedCount,omitempty"`
	// Number of work profile Android devices.
	AndroidWorkProfileCount *int32 `json:"androidWorkProfileCount,omitempty"`
	// Number of ConfigMgr managed devices.
	ConfigMgrDeviceCount *int32 `json:"configMgrDeviceCount,omitempty"`
	// Number of iOS device count.
	IosCount *int32 `json:"iosCount,omitempty"`
	// Number of Mac OS X device count.
	MacOSCount *int32 `json:"macOSCount,omitempty"`
	// Number of unknown device count.
	UnknownCount *int32 `json:"unknownCount,omitempty"`
	// Number of Windows device count.
	WindowsCount *int32 `json:"windowsCount,omitempty"`
	// Number of Windows mobile device count.
	WindowsMobileCount *int32 `json:"windowsMobileCount,omitempty"`
	OdataType          string `json:"@odata.type"`
}

// DeviceExchangeAccessStateSummary Device Exchange Access State summary
type DeviceExchangeAccessStateSummary struct {
	// Total count of devices with Exchange Access State: Allowed.
	AllowedDeviceCount *int32 `json:"allowedDeviceCount,omitempty"`
	// Total count of devices with Exchange Access State: Blocked.
	BlockedDeviceCount *int32 `json:"blockedDeviceCount,omitempty"`
	// Total count of devices with Exchange Access State: Quarantined.
	QuarantinedDeviceCount *int32 `json:"quarantinedDeviceCount,omitempty"`
	// Total count of devices for which no Exchange Access State could be found.
	UnavailableDeviceCount *int32 `json:"unavailableDeviceCount,omitempty"`
	// Total count of devices with Exchange Access State: Unknown.
	UnknownDeviceCount *int32 `json:"unknownDeviceCount,omitempty"`
	OdataType          string `json:"@odata.type"`
}

// DeviceManagementManagedDeviceOverview struct for ManagedDeviceOverview
type DeviceManagementManagedDeviceOverview struct {
	Entity
	DeviceExchangeAccessStateSummary *DeviceExchangeAccessStateSummary `json:"deviceExchangeAccessStateSummary,omitempty"`
	DeviceOperatingSystemSummary     *DeviceOperatingSystemSummary     `json:"deviceOperatingSystemSummary,omitempty"`
	// The number of devices enrolled in both MDM and EAS
	DualEnrolledDeviceCount *int32 `json:"dualEnrolledDeviceCount,omitempty"`
	// Total enrolled device count. Does not include PC devices managed via Intune PC Agent
	EnrolledDeviceCount *int32 `json:"enrolledDeviceCount,omitempty"`
	// The number of devices enrolled in MDM
	MdmEnrolledCount *int32 `json:"mdmEnrolledCount,omitempty"`
	OdataType        string `json:"@odata.type"`
}

// IosUpdatesInstallStatus the model 'IosUpdatesInstallStatus'
type IosUpdatesInstallStatus string

// List of microsoft.graph.iosUpdatesInstallStatus
const (
	IOSUPDATESINSTALLSTATUS_DEVICE_OS_HIGHER_THAN_DESIRED_OS_VERSION IosUpdatesInstallStatus = "deviceOsHigherThanDesiredOsVersion"
	IOSUPDATESINSTALLSTATUS_SHARED_DEVICE_USER_LOGGED_IN_ERROR       IosUpdatesInstallStatus = "sharedDeviceUserLoggedInError"
	IOSUPDATESINSTALLSTATUS_NOT_SUPPORTED_OPERATION                  IosUpdatesInstallStatus = "notSupportedOperation"
	IOSUPDATESINSTALLSTATUS_INSTALL_FAILED                           IosUpdatesInstallStatus = "installFailed"
	IOSUPDATESINSTALLSTATUS_INSTALL_PHONE_CALL_IN_PROGRESS           IosUpdatesInstallStatus = "installPhoneCallInProgress"
	IOSUPDATESINSTALLSTATUS_INSTALL_INSUFFICIENT_POWER               IosUpdatesInstallStatus = "installInsufficientPower"
	IOSUPDATESINSTALLSTATUS_INSTALL_INSUFFICIENT_SPACE               IosUpdatesInstallStatus = "installInsufficientSpace"
	IOSUPDATESINSTALLSTATUS_INSTALLING                               IosUpdatesInstallStatus = "installing"
	IOSUPDATESINSTALLSTATUS_DOWNLOAD_INSUFFICIENT_NETWORK            IosUpdatesInstallStatus = "downloadInsufficientNetwork"
	IOSUPDATESINSTALLSTATUS_DOWNLOAD_INSUFFICIENT_POWER              IosUpdatesInstallStatus = "downloadInsufficientPower"
	IOSUPDATESINSTALLSTATUS_DOWNLOAD_INSUFFICIENT_SPACE              IosUpdatesInstallStatus = "downloadInsufficientSpace"
	IOSUPDATESINSTALLSTATUS_DOWNLOAD_REQUIRES_COMPUTER               IosUpdatesInstallStatus = "downloadRequiresComputer"
	IOSUPDATESINSTALLSTATUS_DOWNLOAD_FAILED                          IosUpdatesInstallStatus = "downloadFailed"
	IOSUPDATESINSTALLSTATUS_DOWNLOADING                              IosUpdatesInstallStatus = "downloading"
	IOSUPDATESINSTALLSTATUS_SUCCESS                                  IosUpdatesInstallStatus = "success"
	IOSUPDATESINSTALLSTATUS_AVAILABLE                                IosUpdatesInstallStatus = "available"
	IOSUPDATESINSTALLSTATUS_IDLE                                     IosUpdatesInstallStatus = "idle"
	IOSUPDATESINSTALLSTATUS_UNKNOWN                                  IosUpdatesInstallStatus = "unknown"
)

// All allowed values of IosUpdatesInstallStatus enum
var AllowedIosUpdatesInstallStatusEnumValues = []IosUpdatesInstallStatus{
	"deviceOsHigherThanDesiredOsVersion",
	"sharedDeviceUserLoggedInError",
	"notSupportedOperation",
	"installFailed",
	"installPhoneCallInProgress",
	"installInsufficientPower",
	"installInsufficientSpace",
	"installing",
	"downloadInsufficientNetwork",
	"downloadInsufficientPower",
	"downloadInsufficientSpace",
	"downloadRequiresComputer",
	"downloadFailed",
	"downloading",
	"success",
	"available",
	"idle",
	"unknown",
}

func (v *IosUpdatesInstallStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := IosUpdatesInstallStatus(value)
	for _, existing := range AllowedIosUpdatesInstallStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid IosUpdatesInstallStatus", value)
}

// IosUpdateDeviceStatus struct for IosUpdateDeviceStatus
type IosUpdateDeviceStatus struct {
	Entity
	// The DateTime when device compliance grace period expires
	ComplianceGracePeriodExpirationDateTime *time.Time `json:"complianceGracePeriodExpirationDateTime,omitempty"`
	// Device name of the DevicePolicyStatus.
	DeviceDisplayName *string `json:"deviceDisplayName,omitempty"`
	// The device id that is being reported.
	DeviceId *string `json:"deviceId,omitempty"`
	// The device model that is being reported
	DeviceModel   *string                  `json:"deviceModel,omitempty"`
	InstallStatus *IosUpdatesInstallStatus `json:"installStatus,omitempty"`
	// Last modified date time of the policy report.
	LastReportedDateTime *time.Time `json:"lastReportedDateTime,omitempty"`
	// The device version that is being reported.
	OsVersion *string           `json:"osVersion,omitempty"`
	Status    *ComplianceStatus `json:"status,omitempty"`
	// The User id that is being reported.
	UserId *string `json:"userId,omitempty"`
	// The User Name that is being reported
	UserName *string `json:"userName,omitempty"`
	// UserPrincipalName.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// ImportedWindowsAutopilotDeviceIdentityImportStatus the model 'ImportedWindowsAutopilotDeviceIdentityImportStatus'
type ImportedWindowsAutopilotDeviceIdentityImportStatus string

// List of microsoft.graph.importedWindowsAutopilotDeviceIdentityImportStatus
const (
	IMPORTEDWINDOWSAUTOPILOTDEVICEIDENTITYIMPORTSTATUS_UNKNOWN  ImportedWindowsAutopilotDeviceIdentityImportStatus = "unknown"
	IMPORTEDWINDOWSAUTOPILOTDEVICEIDENTITYIMPORTSTATUS_PENDING  ImportedWindowsAutopilotDeviceIdentityImportStatus = "pending"
	IMPORTEDWINDOWSAUTOPILOTDEVICEIDENTITYIMPORTSTATUS_PARTIAL  ImportedWindowsAutopilotDeviceIdentityImportStatus = "partial"
	IMPORTEDWINDOWSAUTOPILOTDEVICEIDENTITYIMPORTSTATUS_COMPLETE ImportedWindowsAutopilotDeviceIdentityImportStatus = "complete"
	IMPORTEDWINDOWSAUTOPILOTDEVICEIDENTITYIMPORTSTATUS_ERROR    ImportedWindowsAutopilotDeviceIdentityImportStatus = "error"
)

// All allowed values of ImportedWindowsAutopilotDeviceIdentityImportStatus enum
var AllowedImportedWindowsAutopilotDeviceIdentityImportStatusEnumValues = []ImportedWindowsAutopilotDeviceIdentityImportStatus{
	"unknown",
	"pending",
	"partial",
	"complete",
	"error",
}

func (v *ImportedWindowsAutopilotDeviceIdentityImportStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ImportedWindowsAutopilotDeviceIdentityImportStatus(value)
	for _, existing := range AllowedImportedWindowsAutopilotDeviceIdentityImportStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ImportedWindowsAutopilotDeviceIdentityImportStatus", value)
}

// ImportedWindowsAutopilotDeviceIdentityState struct for ImportedWindowsAutopilotDeviceIdentityState
type ImportedWindowsAutopilotDeviceIdentityState struct {
	// Device error code reported by Device Directory Service(DDS).
	DeviceErrorCode *int32 `json:"deviceErrorCode,omitempty"`
	// Device error name reported by Device Directory Service(DDS).
	DeviceErrorName    *string                                             `json:"deviceErrorName,omitempty"`
	DeviceImportStatus *ImportedWindowsAutopilotDeviceIdentityImportStatus `json:"deviceImportStatus,omitempty"`
	// Device Registration ID for successfully added device reported by Device Directory Service(DDS).
	DeviceRegistrationId *string `json:"deviceRegistrationId,omitempty"`
	OdataType            string  `json:"@odata.type"`
}

// ImportedWindowsAutopilotDeviceIdentity struct for ImportedWindowsAutopilotDeviceIdentity
type ImportedWindowsAutopilotDeviceIdentity struct {
	Entity
	// UPN of the user the device will be assigned
	AssignedUserPrincipalName *string `json:"assignedUserPrincipalName,omitempty"`
	// Group Tag of the Windows autopilot device.
	GroupTag *string `json:"groupTag,omitempty"`
	// Hardware Blob of the Windows autopilot device.
	HardwareIdentifier *string `json:"hardwareIdentifier,omitempty"`
	// The Import Id of the Windows autopilot device.
	ImportId *string `json:"importId,omitempty"`
	// Product Key of the Windows autopilot device.
	ProductKey *string `json:"productKey,omitempty"`
	// Serial number of the Windows autopilot device.
	SerialNumber *string                                      `json:"serialNumber,omitempty"`
	State        *ImportedWindowsAutopilotDeviceIdentityState `json:"state,omitempty"`
	OdataType    string                                       `json:"@odata.type"`
}

// DeviceManagementExchangeConnectorStatus The current status of the Exchange Connector.
type DeviceManagementExchangeConnectorStatus string

// List of microsoft.graph.deviceManagementExchangeConnectorStatus
const (
	DEVICEMANAGEMENTEXCHANGECONNECTORSTATUS_NONE                 DeviceManagementExchangeConnectorStatus = "none"
	DEVICEMANAGEMENTEXCHANGECONNECTORSTATUS_CONNECTION_PENDING   DeviceManagementExchangeConnectorStatus = "connectionPending"
	DEVICEMANAGEMENTEXCHANGECONNECTORSTATUS_CONNECTED            DeviceManagementExchangeConnectorStatus = "connected"
	DEVICEMANAGEMENTEXCHANGECONNECTORSTATUS_DISCONNECTED         DeviceManagementExchangeConnectorStatus = "disconnected"
	DEVICEMANAGEMENTEXCHANGECONNECTORSTATUS_UNKNOWN_FUTURE_VALUE DeviceManagementExchangeConnectorStatus = "unknownFutureValue"
)

// All allowed values of DeviceManagementExchangeConnectorStatus enum
var AllowedDeviceManagementExchangeConnectorStatusEnumValues = []DeviceManagementExchangeConnectorStatus{
	"none",
	"connectionPending",
	"connected",
	"disconnected",
	"unknownFutureValue",
}

func (v *DeviceManagementExchangeConnectorStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementExchangeConnectorStatus(value)
	for _, existing := range AllowedDeviceManagementExchangeConnectorStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementExchangeConnectorStatus", value)
}

// DeviceManagementExchangeConnectorType The type of Exchange Connector.
type DeviceManagementExchangeConnectorType string

// List of microsoft.graph.deviceManagementExchangeConnectorType
const (
	DEVICEMANAGEMENTEXCHANGECONNECTORTYPE_ON_PREMISES          DeviceManagementExchangeConnectorType = "onPremises"
	DEVICEMANAGEMENTEXCHANGECONNECTORTYPE_HOSTED               DeviceManagementExchangeConnectorType = "hosted"
	DEVICEMANAGEMENTEXCHANGECONNECTORTYPE_SERVICE_TO_SERVICE   DeviceManagementExchangeConnectorType = "serviceToService"
	DEVICEMANAGEMENTEXCHANGECONNECTORTYPE_DEDICATED            DeviceManagementExchangeConnectorType = "dedicated"
	DEVICEMANAGEMENTEXCHANGECONNECTORTYPE_UNKNOWN_FUTURE_VALUE DeviceManagementExchangeConnectorType = "unknownFutureValue"
)

// All allowed values of DeviceManagementExchangeConnectorType enum
var AllowedDeviceManagementExchangeConnectorTypeEnumValues = []DeviceManagementExchangeConnectorType{
	"onPremises",
	"hosted",
	"serviceToService",
	"dedicated",
	"unknownFutureValue",
}

func (v *DeviceManagementExchangeConnectorType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementExchangeConnectorType(value)
	for _, existing := range AllowedDeviceManagementExchangeConnectorTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementExchangeConnectorType", value)
}

// DeviceManagementExchangeConnector struct for DeviceManagementExchangeConnector
type DeviceManagementExchangeConnector struct {
	Entity
	// The name of the server hosting the Exchange Connector.
	ConnectorServerName *string `json:"connectorServerName,omitempty"`
	// An alias assigned to the Exchange server
	ExchangeAlias         *string                                `json:"exchangeAlias,omitempty"`
	ExchangeConnectorType *DeviceManagementExchangeConnectorType `json:"exchangeConnectorType,omitempty"`
	// Exchange Organization to the Exchange server
	ExchangeOrganization *string `json:"exchangeOrganization,omitempty"`
	// Last sync time for the Exchange Connector
	LastSyncDateTime *time.Time `json:"lastSyncDateTime,omitempty"`
	// Email address used to configure the Service To Service Exchange Connector.
	PrimarySmtpAddress *string `json:"primarySmtpAddress,omitempty"`
	// The name of the Exchange server.
	ServerName *string                                  `json:"serverName,omitempty"`
	Status     *DeviceManagementExchangeConnectorStatus `json:"status,omitempty"`
	// The version of the ExchangeConnectorAgent
	Version   *string `json:"version,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// EnrollmentConfigurationAssignment struct for EnrollmentConfigurationAssignment
type EnrollmentConfigurationAssignment struct {
	Entity
	Target    *DeviceAndAppManagementAssignmentTarget `json:"target,omitempty"`
	OdataType string                                  `json:"@odata.type"`
}

// DeviceEnrollmentConfiguration struct for DeviceEnrollmentConfiguration
type DeviceEnrollmentConfiguration struct {
	Entity
	// Created date time in UTC of the device enrollment configuration
	CreatedDateTime *time.Time `json:"createdDateTime,omitempty"`
	// The description of the device enrollment configuration
	Description *string `json:"description,omitempty"`
	// The display name of the device enrollment configuration
	DisplayName *string `json:"displayName,omitempty"`
	// Last modified date time in UTC of the device enrollment configuration
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// Priority is used when a user exists in multiple groups that are assigned enrollment configuration. Users are subject only to the configuration with the lowest priority value.
	Priority *int32 `json:"priority,omitempty"`
	// The version of the device enrollment configuration
	Version *int32 `json:"version,omitempty"`
	// The list of group assignments for the device configuration profile
	Assignments []EnrollmentConfigurationAssignment `json:"assignments,omitempty"`
	OdataType   string                              `json:"@odata.type"`
}

// DeviceManagementPartnerAssignment User group targeting for Device Management Partner
type DeviceManagementPartnerAssignment struct {
	Target    *DeviceAndAppManagementAssignmentTarget `json:"target,omitempty"`
	OdataType string                                  `json:"@odata.type"`
}

// DeviceManagementPartner struct for DeviceManagementPartner
type DeviceManagementPartner struct {
	Entity
	// Partner display name
	DisplayName *string `json:"displayName,omitempty"`
	// User groups that specifies whether enrollment is through partner.
	GroupsRequiringPartnerEnrollment []DeviceAndAppManagementAssignmentTarget `json:"groupsRequiringPartnerEnrollment,omitempty"`
	// Whether device management partner is configured or not
	IsConfigured *bool `json:"isConfigured,omitempty"`
	// Timestamp of last heartbeat after admin enabled option Connect to Device management Partner
	LastHeartbeatDateTime *time.Time                          `json:"lastHeartbeatDateTime,omitempty"`
	PartnerAppType        *DeviceManagementPartnerAppType     `json:"partnerAppType,omitempty"`
	PartnerState          *DeviceManagementPartnerTenantState `json:"partnerState,omitempty"`
	// Partner Single tenant App id
	SingleTenantAppId *string `json:"singleTenantAppId,omitempty"`
	// DateTime in UTC when PartnerDevices will be marked as NonCompliant
	WhenPartnerDevicesWillBeMarkedAsNonCompliantDateTime *time.Time `json:"whenPartnerDevicesWillBeMarkedAsNonCompliantDateTime,omitempty"`
	// DateTime in UTC when PartnerDevices will be removed
	WhenPartnerDevicesWillBeRemovedDateTime *time.Time `json:"whenPartnerDevicesWillBeRemovedDateTime,omitempty"`
	OdataType                               string     `json:"@odata.type"`
}

// DeviceManagementPartnerAppType Partner App Type.
type DeviceManagementPartnerAppType string

// List of microsoft.graph.deviceManagementPartnerAppType
const (
	DEVICEMANAGEMENTPARTNERAPPTYPE_UNKNOWN           DeviceManagementPartnerAppType = "unknown"
	DEVICEMANAGEMENTPARTNERAPPTYPE_SINGLE_TENANT_APP DeviceManagementPartnerAppType = "singleTenantApp"
	DEVICEMANAGEMENTPARTNERAPPTYPE_MULTI_TENANT_APP  DeviceManagementPartnerAppType = "multiTenantApp"
)

// All allowed values of DeviceManagementPartnerAppType enum
var AllowedDeviceManagementPartnerAppTypeEnumValues = []DeviceManagementPartnerAppType{
	"unknown",
	"singleTenantApp",
	"multiTenantApp",
}

func (v *DeviceManagementPartnerAppType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementPartnerAppType(value)
	for _, existing := range AllowedDeviceManagementPartnerAppTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementPartnerAppType", value)
}

// DeviceConfiguration struct for DeviceConfiguration
type DeviceConfiguration struct {
	Entity
	// DateTime the object was created.
	CreatedDateTime *time.Time `json:"createdDateTime,omitempty"`
	// Admin provided description of the Device Configuration.
	Description *string `json:"description,omitempty"`
	// Admin provided name of the device configuration.
	DisplayName *string `json:"displayName,omitempty"`
	// DateTime the object was last modified.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// Version of the device configuration.
	Version *int32 `json:"version,omitempty"`
	// The list of assignments for the device configuration profile.
	Assignments []DeviceConfigurationAssignment `json:"assignments,omitempty"`
	// Device Configuration Setting State Device Summary
	DeviceSettingStateSummaries []SettingStateDeviceSummary `json:"deviceSettingStateSummaries,omitempty"`
	// Device configuration installation status by device.
	DeviceStatuses       []DeviceConfigurationDeviceStatus  `json:"deviceStatuses,omitempty"`
	DeviceStatusOverview *DeviceConfigurationDeviceOverview `json:"deviceStatusOverview,omitempty"`
	// Device configuration installation status by user.
	UserStatuses       []DeviceConfigurationUserStatus  `json:"userStatuses,omitempty"`
	UserStatusOverview *DeviceConfigurationUserOverview `json:"userStatusOverview,omitempty"`
	OdataType          string                           `json:"@odata.type"`
}

// DeviceConfigurationAssignment struct for DeviceConfigurationAssignment
type DeviceConfigurationAssignment struct {
	Entity
	Target    *DeviceAndAppManagementAssignmentTarget `json:"target,omitempty"`
	OdataType string                                  `json:"@odata.type"`
}

// DeviceConfigurationUserOverview struct for DeviceConfigurationUserOverview
type DeviceConfigurationUserOverview struct {
	Entity
	// Version of the policy for that overview
	ConfigurationVersion *int32 `json:"configurationVersion,omitempty"`
	// Number of error Users
	ErrorCount *int32 `json:"errorCount,omitempty"`
	// Number of failed Users
	FailedCount *int32 `json:"failedCount,omitempty"`
	// Last update time
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	// Number of not applicable users
	NotApplicableCount *int32 `json:"notApplicableCount,omitempty"`
	// Number of pending Users
	PendingCount *int32 `json:"pendingCount,omitempty"`
	// Number of succeeded Users
	SuccessCount *int32 `json:"successCount,omitempty"`
	OdataType    string `json:"@odata.type"`
}

// DeviceConfigurationUserStatus struct for DeviceConfigurationUserStatus
type DeviceConfigurationUserStatus struct {
	Entity
	// Devices count for that user.
	DevicesCount *int32 `json:"devicesCount,omitempty"`
	// Last modified date time of the policy report.
	LastReportedDateTime *time.Time        `json:"lastReportedDateTime,omitempty"`
	Status               *ComplianceStatus `json:"status,omitempty"`
	// User name of the DevicePolicyStatus.
	UserDisplayName *string `json:"userDisplayName,omitempty"`
	// UserPrincipalName.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// DeviceConfigurationDeviceOverview struct for DeviceConfigurationDeviceOverview
type DeviceConfigurationDeviceOverview struct {
	Entity
	// Version of the policy for that overview
	ConfigurationVersion *int32 `json:"configurationVersion,omitempty"`
	// Number of error devices
	ErrorCount *int32 `json:"errorCount,omitempty"`
	// Number of failed devices
	FailedCount *int32 `json:"failedCount,omitempty"`
	// Last update time
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	// Number of not applicable devices
	NotApplicableCount *int32 `json:"notApplicableCount,omitempty"`
	// Number of pending devices
	PendingCount *int32 `json:"pendingCount,omitempty"`
	// Number of succeeded devices
	SuccessCount *int32 `json:"successCount,omitempty"`
	OdataType    string `json:"@odata.type"`
}

// DeviceConfigurationDeviceStatus struct for DeviceConfigurationDeviceStatus
type DeviceConfigurationDeviceStatus struct {
	Entity
	// The DateTime when device compliance grace period expires
	ComplianceGracePeriodExpirationDateTime *time.Time `json:"complianceGracePeriodExpirationDateTime,omitempty"`
	// Device name of the DevicePolicyStatus.
	DeviceDisplayName *string `json:"deviceDisplayName,omitempty"`
	// The device model that is being reported
	DeviceModel *string `json:"deviceModel,omitempty"`
	// Last modified date time of the policy report.
	LastReportedDateTime *time.Time        `json:"lastReportedDateTime,omitempty"`
	Status               *ComplianceStatus `json:"status,omitempty"`
	// The User Name that is being reported
	UserName *string `json:"userName,omitempty"`
	// UserPrincipalName.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// DeviceConfigurationDeviceStateSummary struct for DeviceConfigurationDeviceStateSummary
type DeviceConfigurationDeviceStateSummary struct {
	Entity
	// Number of compliant devices
	CompliantDeviceCount *int32 `json:"compliantDeviceCount,omitempty"`
	// Number of conflict devices
	ConflictDeviceCount *int32 `json:"conflictDeviceCount,omitempty"`
	// Number of error devices
	ErrorDeviceCount *int32 `json:"errorDeviceCount,omitempty"`
	// Number of NonCompliant devices
	NonCompliantDeviceCount *int32 `json:"nonCompliantDeviceCount,omitempty"`
	// Number of not applicable devices
	NotApplicableDeviceCount *int32 `json:"notApplicableDeviceCount,omitempty"`
	// Number of remediated devices
	RemediatedDeviceCount *int32 `json:"remediatedDeviceCount,omitempty"`
	// Number of unknown devices
	UnknownDeviceCount *int32 `json:"unknownDeviceCount,omitempty"`
	OdataType          string `json:"@odata.type"`
}

// DeviceComplianceSettingState struct for DeviceComplianceSettingState
type DeviceComplianceSettingState struct {
	Entity
	// The DateTime when device compliance grace period expires
	ComplianceGracePeriodExpirationDateTime *time.Time `json:"complianceGracePeriodExpirationDateTime,omitempty"`
	// The Device Id that is being reported
	DeviceId *string `json:"deviceId,omitempty"`
	// The device model that is being reported
	DeviceModel *string `json:"deviceModel,omitempty"`
	// The Device Name that is being reported
	DeviceName *string `json:"deviceName,omitempty"`
	// The setting class name and property name.
	Setting *string `json:"setting,omitempty"`
	// The Setting Name that is being reported
	SettingName *string           `json:"settingName,omitempty"`
	State       *ComplianceStatus `json:"state,omitempty"`
	// The User email address that is being reported
	UserEmail *string `json:"userEmail,omitempty"`
	// The user Id that is being reported
	UserId *string `json:"userId,omitempty"`
	// The User Name that is being reported
	UserName *string `json:"userName,omitempty"`
	// The User PrincipalName that is being reported
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// DeviceCompliancePolicySettingStateSummary struct for DeviceCompliancePolicySettingStateSummary
type DeviceCompliancePolicySettingStateSummary struct {
	Entity
	// Number of compliant devices
	CompliantDeviceCount *int32 `json:"compliantDeviceCount,omitempty"`
	// Number of conflict devices
	ConflictDeviceCount *int32 `json:"conflictDeviceCount,omitempty"`
	// Number of error devices
	ErrorDeviceCount *int32 `json:"errorDeviceCount,omitempty"`
	// Number of NonCompliant devices
	NonCompliantDeviceCount *int32 `json:"nonCompliantDeviceCount,omitempty"`
	// Number of not applicable devices
	NotApplicableDeviceCount *int32              `json:"notApplicableDeviceCount,omitempty"`
	PlatformType             *PolicyPlatformType `json:"platformType,omitempty"`
	// Number of remediated devices
	RemediatedDeviceCount *int32 `json:"remediatedDeviceCount,omitempty"`
	// The setting class name and property name.
	Setting *string `json:"setting,omitempty"`
	// Name of the setting.
	SettingName *string `json:"settingName,omitempty"`
	// Number of unknown devices
	UnknownDeviceCount *int32 `json:"unknownDeviceCount,omitempty"`
	// Not yet documented
	DeviceComplianceSettingStates []DeviceComplianceSettingState `json:"deviceComplianceSettingStates,omitempty"`
	OdataType                     string                         `json:"@odata.type"`
}

// DeviceCompliancePolicyDeviceStateSummary struct for DeviceCompliancePolicyDeviceStateSummary
type DeviceCompliancePolicyDeviceStateSummary struct {
	Entity
	// Number of compliant devices
	CompliantDeviceCount *int32 `json:"compliantDeviceCount,omitempty"`
	// Number of devices that have compliance managed by System Center Configuration Manager
	ConfigManagerCount *int32 `json:"configManagerCount,omitempty"`
	// Number of conflict devices
	ConflictDeviceCount *int32 `json:"conflictDeviceCount,omitempty"`
	// Number of error devices
	ErrorDeviceCount *int32 `json:"errorDeviceCount,omitempty"`
	// Number of devices that are in grace period
	InGracePeriodCount *int32 `json:"inGracePeriodCount,omitempty"`
	// Number of NonCompliant devices
	NonCompliantDeviceCount *int32 `json:"nonCompliantDeviceCount,omitempty"`
	// Number of not applicable devices
	NotApplicableDeviceCount *int32 `json:"notApplicableDeviceCount,omitempty"`
	// Number of remediated devices
	RemediatedDeviceCount *int32 `json:"remediatedDeviceCount,omitempty"`
	// Number of unknown devices
	UnknownDeviceCount *int32 `json:"unknownDeviceCount,omitempty"`
	OdataType          string `json:"@odata.type"`
}

// DeviceCompliancePolicy struct for DeviceCompliancePolicy
type DeviceCompliancePolicy struct {
	Entity
	// DateTime the object was created.
	CreatedDateTime *time.Time `json:"createdDateTime,omitempty"`
	// Admin provided description of the Device Configuration.
	Description *string `json:"description,omitempty"`
	// Admin provided name of the device configuration.
	DisplayName *string `json:"displayName,omitempty"`
	// DateTime the object was last modified.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// Version of the device configuration.
	Version *int32 `json:"version,omitempty"`
	// The collection of assignments for this compliance policy.
	Assignments []DeviceCompliancePolicyAssignment `json:"assignments,omitempty"`
	// Compliance Setting State Device Summary
	DeviceSettingStateSummaries []SettingStateDeviceSummary `json:"deviceSettingStateSummaries,omitempty"`
	// List of DeviceComplianceDeviceStatus.
	DeviceStatuses       []DeviceComplianceDeviceStatus  `json:"deviceStatuses,omitempty"`
	DeviceStatusOverview *DeviceComplianceDeviceOverview `json:"deviceStatusOverview,omitempty"`
	// The list of scheduled action per rule for this compliance policy. This is a required property when creating any individual per-platform compliance policies.
	ScheduledActionsForRule []DeviceComplianceScheduledActionForRule `json:"scheduledActionsForRule,omitempty"`
	// List of DeviceComplianceUserStatus.
	UserStatuses       []DeviceComplianceUserStatus  `json:"userStatuses,omitempty"`
	UserStatusOverview *DeviceComplianceUserOverview `json:"userStatusOverview,omitempty"`
	OdataType          string                        `json:"@odata.type"`
}

// DeviceComplianceUserOverview struct for DeviceComplianceUserOverview
type DeviceComplianceUserOverview struct {
	Entity
	// Version of the policy for that overview
	ConfigurationVersion *int32 `json:"configurationVersion,omitempty"`
	// Number of error Users
	ErrorCount *int32 `json:"errorCount,omitempty"`
	// Number of failed Users
	FailedCount *int32 `json:"failedCount,omitempty"`
	// Last update time
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	// Number of not applicable users
	NotApplicableCount *int32 `json:"notApplicableCount,omitempty"`
	// Number of pending Users
	PendingCount *int32 `json:"pendingCount,omitempty"`
	// Number of succeeded Users
	SuccessCount *int32 `json:"successCount,omitempty"`
	OdataType    string `json:"@odata.type"`
}

// DeviceComplianceUserStatus struct for DeviceComplianceUserStatus
type DeviceComplianceUserStatus struct {
	Entity
	// Devices count for that user.
	DevicesCount *int32 `json:"devicesCount,omitempty"`
	// Last modified date time of the policy report.
	LastReportedDateTime *time.Time        `json:"lastReportedDateTime,omitempty"`
	Status               *ComplianceStatus `json:"status,omitempty"`
	// User name of the DevicePolicyStatus.
	UserDisplayName *string `json:"userDisplayName,omitempty"`
	// UserPrincipalName.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// DeviceComplianceActionType Scheduled Action Type Enum
type DeviceComplianceActionType string

// List of microsoft.graph.deviceComplianceActionType
const (
	DEVICECOMPLIANCEACTIONTYPE_NO_ACTION                       DeviceComplianceActionType = "noAction"
	DEVICECOMPLIANCEACTIONTYPE_NOTIFICATION                    DeviceComplianceActionType = "notification"
	DEVICECOMPLIANCEACTIONTYPE_BLOCK                           DeviceComplianceActionType = "block"
	DEVICECOMPLIANCEACTIONTYPE_RETIRE                          DeviceComplianceActionType = "retire"
	DEVICECOMPLIANCEACTIONTYPE_WIPE                            DeviceComplianceActionType = "wipe"
	DEVICECOMPLIANCEACTIONTYPE_REMOVE_RESOURCE_ACCESS_PROFILES DeviceComplianceActionType = "removeResourceAccessProfiles"
	DEVICECOMPLIANCEACTIONTYPE_PUSH_NOTIFICATION               DeviceComplianceActionType = "pushNotification"
)

// All allowed values of DeviceComplianceActionType enum
var AllowedDeviceComplianceActionTypeEnumValues = []DeviceComplianceActionType{
	"noAction",
	"notification",
	"block",
	"retire",
	"wipe",
	"removeResourceAccessProfiles",
	"pushNotification",
}

func (v *DeviceComplianceActionType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceComplianceActionType(value)
	for _, existing := range AllowedDeviceComplianceActionTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceComplianceActionType", value)
}

// DeviceComplianceActionItem struct for DeviceComplianceActionItem
type DeviceComplianceActionItem struct {
	Entity
	ActionType *DeviceComplianceActionType `json:"actionType,omitempty"`
	// Number of hours to wait till the action will be enforced. Valid values 0 to 8760
	GracePeriodHours *int32 `json:"gracePeriodHours,omitempty"`
	// A list of group IDs to speicify who to CC this notification message to.
	NotificationMessageCCList []*string `json:"notificationMessageCCList,omitempty"`
	// What notification Message template to use
	NotificationTemplateId *string `json:"notificationTemplateId,omitempty"`
	OdataType              string  `json:"@odata.type"`
}

// DeviceComplianceScheduledActionForRule struct for DeviceComplianceScheduledActionForRule
type DeviceComplianceScheduledActionForRule struct {
	Entity
	// Name of the rule which this scheduled action applies to. Currently scheduled actions are created per policy instead of per rule, thus RuleName is always set to default value PasswordRequired.
	RuleName *string `json:"ruleName,omitempty"`
	// The list of scheduled action configurations for this compliance policy. Compliance policy must have one and only one block scheduled action.
	ScheduledActionConfigurations []DeviceComplianceActionItem `json:"scheduledActionConfigurations,omitempty"`
	OdataType                     string                       `json:"@odata.type"`
}

// DeviceComplianceDeviceOverview struct for DeviceComplianceDeviceOverview
type DeviceComplianceDeviceOverview struct {
	Entity
	// Version of the policy for that overview
	ConfigurationVersion *int32 `json:"configurationVersion,omitempty"`
	// Number of error devices
	ErrorCount *int32 `json:"errorCount,omitempty"`
	// Number of failed devices
	FailedCount *int32 `json:"failedCount,omitempty"`
	// Last update time
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	// Number of not applicable devices
	NotApplicableCount *int32 `json:"notApplicableCount,omitempty"`
	// Number of pending devices
	PendingCount *int32 `json:"pendingCount,omitempty"`
	// Number of succeeded devices
	SuccessCount *int32 `json:"successCount,omitempty"`
	OdataType    string `json:"@odata.type"`
}

// DeviceComplianceDeviceStatus struct for DeviceComplianceDeviceStatus
type DeviceComplianceDeviceStatus struct {
	Entity
	// The DateTime when device compliance grace period expires
	ComplianceGracePeriodExpirationDateTime *time.Time `json:"complianceGracePeriodExpirationDateTime,omitempty"`
	// Device name of the DevicePolicyStatus.
	DeviceDisplayName *string `json:"deviceDisplayName,omitempty"`
	// The device model that is being reported
	DeviceModel *string `json:"deviceModel,omitempty"`
	// Last modified date time of the policy report.
	LastReportedDateTime *time.Time        `json:"lastReportedDateTime,omitempty"`
	Status               *ComplianceStatus `json:"status,omitempty"`
	// The User Name that is being reported
	UserName *string `json:"userName,omitempty"`
	// UserPrincipalName.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// SettingStateDeviceSummary struct for SettingStateDeviceSummary
type SettingStateDeviceSummary struct {
	Entity
	// Device Compliant count for the setting
	CompliantDeviceCount *int32 `json:"compliantDeviceCount,omitempty"`
	// Device conflict error count for the setting
	ConflictDeviceCount *int32 `json:"conflictDeviceCount,omitempty"`
	// Device error count for the setting
	ErrorDeviceCount *int32 `json:"errorDeviceCount,omitempty"`
	// Name of the InstancePath for the setting
	InstancePath *string `json:"instancePath,omitempty"`
	// Device NonCompliant count for the setting
	NonCompliantDeviceCount *int32 `json:"nonCompliantDeviceCount,omitempty"`
	// Device Not Applicable count for the setting
	NotApplicableDeviceCount *int32 `json:"notApplicableDeviceCount,omitempty"`
	// Device Compliant count for the setting
	RemediatedDeviceCount *int32 `json:"remediatedDeviceCount,omitempty"`
	// Name of the setting
	SettingName *string `json:"settingName,omitempty"`
	// Device Unkown count for the setting
	UnknownDeviceCount *int32 `json:"unknownDeviceCount,omitempty"`
	OdataType          string `json:"@odata.type"`
}

// DeviceCompliancePolicyAssignment struct for DeviceCompliancePolicyAssignment
type DeviceCompliancePolicyAssignment struct {
	Entity
	Target    *DeviceAndAppManagementAssignmentTarget `json:"target,omitempty"`
	OdataType string                                  `json:"@odata.type"`
}

// DetectedApp struct for DetectedApp
type DetectedApp struct {
	Entity
	// The number of devices that have installed this application
	DeviceCount *int32 `json:"deviceCount,omitempty"`
	// Name of the discovered application. Read-only
	DisplayName *string                  `json:"displayName,omitempty"`
	Platform    *DetectedAppPlatformType `json:"platform,omitempty"`
	// Indicates the publisher of the discovered application. For example: 'Microsoft'.  The default value is an empty string.
	Publisher *string `json:"publisher,omitempty"`
	// Discovered application size in bytes. Read-only
	SizeInByte *int64 `json:"sizeInByte,omitempty"`
	// Version of the discovered application. Read-only
	Version *string `json:"version,omitempty"`
	// The devices that have the discovered application installed
	ManagedDevices []ManagedDevice `json:"managedDevices,omitempty"`
	OdataType      string          `json:"@odata.type"`
}

// ManagedDevice struct for ManagedDevice
type ManagedDevice struct {
	Entity
	// The code that allows the Activation Lock on managed device to be bypassed. Default, is Null (Non-Default property) for this property when returned as part of managedDevice entity in LIST call. To retrieve actual values GET call needs to be made, with device id and included in select parameter. Supports: $select. $Search is not supported. Read-only. This property is read-only.
	ActivationLockBypassCode *string `json:"activationLockBypassCode,omitempty"`
	// Android security patch level. This property is read-only.
	AndroidSecurityPatchLevel *string `json:"androidSecurityPatchLevel,omitempty"`
	// The unique identifier for the Azure Active Directory device. Read only. This property is read-only.
	AzureADDeviceId *string `json:"azureADDeviceId,omitempty"`
	// Whether the device is Azure Active Directory registered. This property is read-only.
	AzureADRegistered *bool `json:"azureADRegistered,omitempty"`
	// The DateTime when device compliance grace period expires. This property is read-only.
	ComplianceGracePeriodExpirationDateTime   *time.Time                                 `json:"complianceGracePeriodExpirationDateTime,omitempty"`
	ComplianceState                           *ComplianceState                           `json:"complianceState,omitempty"`
	ConfigurationManagerClientEnabledFeatures *ConfigurationManagerClientEnabledFeatures `json:"configurationManagerClientEnabledFeatures,omitempty"`
	// List of ComplexType deviceActionResult objects. This property is read-only.
	DeviceActionResults []DeviceActionResult `json:"deviceActionResults,omitempty"`
	// Device category display name. Default is an empty string. Supports $filter operator 'eq' and 'or'. This property is read-only.
	DeviceCategoryDisplayName    *string                       `json:"deviceCategoryDisplayName,omitempty"`
	DeviceEnrollmentType         *DeviceEnrollmentType         `json:"deviceEnrollmentType,omitempty"`
	DeviceHealthAttestationState *DeviceHealthAttestationState `json:"deviceHealthAttestationState,omitempty"`
	// Name of the device. This property is read-only.
	DeviceName              *string                  `json:"deviceName,omitempty"`
	DeviceRegistrationState *DeviceRegistrationState `json:"deviceRegistrationState,omitempty"`
	// Whether the device is Exchange ActiveSync activated. This property is read-only.
	EasActivated *bool `json:"easActivated,omitempty"`
	// Exchange ActivationSync activation time of the device. This property is read-only.
	EasActivationDateTime *time.Time `json:"easActivationDateTime,omitempty"`
	// Exchange ActiveSync Id of the device. This property is read-only.
	EasDeviceId *string `json:"easDeviceId,omitempty"`
	// Email(s) for the user associated with the device. This property is read-only.
	EmailAddress *string `json:"emailAddress,omitempty"`
	// Enrollment time of the device. Supports $filter operator 'lt' and 'gt'. This property is read-only.
	EnrolledDateTime *time.Time `json:"enrolledDateTime,omitempty"`
	// Name of the enrollment profile assigned to the device. Default value is empty string, indicating no enrollment profile was assgined. This property is read-only.
	EnrollmentProfileName *string `json:"enrollmentProfileName,omitempty"`
	// Indicates Ethernet MAC Address of the device. Default, is Null (Non-Default property) for this property when returned as part of managedDevice entity. Individual get call with select query options is needed to retrieve actual values. Example: deviceManagement/managedDevices({managedDeviceId})?$select=ethernetMacAddress Supports: $select. $Search is not supported. Read-only. This property is read-only.
	EthernetMacAddress        *string                                    `json:"ethernetMacAddress,omitempty"`
	ExchangeAccessState       *DeviceManagementExchangeAccessState       `json:"exchangeAccessState,omitempty"`
	ExchangeAccessStateReason *DeviceManagementExchangeAccessStateReason `json:"exchangeAccessStateReason,omitempty"`
	// Last time the device contacted Exchange. This property is read-only.
	ExchangeLastSuccessfulSyncDateTime *time.Time `json:"exchangeLastSuccessfulSyncDateTime,omitempty"`
	// Free Storage in Bytes. Default value is 0. Read-only. This property is read-only.
	FreeStorageSpaceInBytes *int64 `json:"freeStorageSpaceInBytes,omitempty"`
	// Integrated Circuit Card Identifier, it is A SIM card's unique identification number. Default is an empty string. To retrieve actual values GET call needs to be made, with device id and included in select parameter. Supports: $select. $Search is not supported. Read-only. This property is read-only.
	Iccid *string `json:"iccid,omitempty"`
	// IMEI. This property is read-only.
	Imei *string `json:"imei,omitempty"`
	// Device encryption status. This property is read-only.
	IsEncrypted *bool `json:"isEncrypted,omitempty"`
	// Device supervised status. This property is read-only.
	IsSupervised *bool `json:"isSupervised,omitempty"`
	// Whether the device is jail broken or rooted. Default is an empty string. Supports $filter operator 'eq' and 'or'. This property is read-only.
	JailBroken *string `json:"jailBroken,omitempty"`
	// The date and time that the device last completed a successful sync with Intune. Supports $filter operator 'lt' and 'gt'. This property is read-only.
	LastSyncDateTime *time.Time `json:"lastSyncDateTime,omitempty"`
	// Automatically generated name to identify a device. Can be overwritten to a user friendly name.
	ManagedDeviceName      *string                 `json:"managedDeviceName,omitempty"`
	ManagedDeviceOwnerType *ManagedDeviceOwnerType `json:"managedDeviceOwnerType,omitempty"`
	ManagementAgent        *ManagementAgentType    `json:"managementAgent,omitempty"`
	// Reports device management certificate expiration date. This property is read-only.
	ManagementCertificateExpirationDate *time.Time `json:"managementCertificateExpirationDate,omitempty"`
	// Manufacturer of the device. This property is read-only.
	Manufacturer *string `json:"manufacturer,omitempty"`
	// MEID. This property is read-only.
	Meid *string `json:"meid,omitempty"`
	// Model of the device. This property is read-only.
	Model *string `json:"model,omitempty"`
	// Notes on the device created by IT Admin. Default is null. To retrieve actual values GET call needs to be made, with device id and included in select parameter. Supports: $select. $Search is not supported.
	Notes *string `json:"notes,omitempty"`
	// Operating system of the device. Windows, iOS, etc. This property is read-only.
	OperatingSystem *string `json:"operatingSystem,omitempty"`
	// Operating system version of the device. This property is read-only.
	OsVersion                  *string                                  `json:"osVersion,omitempty"`
	PartnerReportedThreatState *ManagedDevicePartnerReportedHealthState `json:"partnerReportedThreatState,omitempty"`
	// Phone number of the device. This property is read-only.
	PhoneNumber *string `json:"phoneNumber,omitempty"`
	// Total Memory in Bytes. Default is 0. To retrieve actual values GET call needs to be made, with device id and included in select parameter. Supports: $select. Read-only. This property is read-only.
	PhysicalMemoryInBytes *int64 `json:"physicalMemoryInBytes,omitempty"`
	// An error string that identifies issues when creating Remote Assistance session objects. This property is read-only.
	RemoteAssistanceSessionErrorDetails *string `json:"remoteAssistanceSessionErrorDetails,omitempty"`
	// Url that allows a Remote Assistance session to be established with the device. Default is an empty string. To retrieve actual values GET call needs to be made, with device id and included in select parameter. This property is read-only.
	RemoteAssistanceSessionUrl *string `json:"remoteAssistanceSessionUrl,omitempty"`
	// Reports if the managed iOS device is user approval enrollment. This property is read-only.
	RequireUserEnrollmentApproval *bool `json:"requireUserEnrollmentApproval,omitempty"`
	// SerialNumber. This property is read-only.
	SerialNumber *string `json:"serialNumber,omitempty"`
	// Subscriber Carrier. This property is read-only.
	SubscriberCarrier *string `json:"subscriberCarrier,omitempty"`
	// Total Storage in Bytes. This property is read-only.
	TotalStorageSpaceInBytes *int64 `json:"totalStorageSpaceInBytes,omitempty"`
	// Unique Device Identifier for iOS and macOS devices. Default is an empty string. To retrieve actual values GET call needs to be made, with device id and included in select parameter. Supports: $select. $Search is not supported. Read-only. This property is read-only.
	Udid *string `json:"udid,omitempty"`
	// User display name. This property is read-only.
	UserDisplayName *string `json:"userDisplayName,omitempty"`
	// Unique Identifier for the user associated with the device. This property is read-only.
	UserId *string `json:"userId,omitempty"`
	// Device user principal name. This property is read-only.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	// Wi-Fi MAC. This property is read-only.
	WiFiMacAddress *string         `json:"wiFiMacAddress,omitempty"`
	DeviceCategory *DeviceCategory `json:"deviceCategory,omitempty"`
	// Device compliance policy states for this device.
	DeviceCompliancePolicyStates []DeviceCompliancePolicyState `json:"deviceCompliancePolicyStates,omitempty"`
	// Device configuration states for this device.
	DeviceConfigurationStates []DeviceConfigurationState `json:"deviceConfigurationStates,omitempty"`
	// List of log collection requests
	LogCollectionRequests []DeviceLogCollectionResponse `json:"logCollectionRequests,omitempty"`
	// The primary users associated with the managed device.
	Users                  []User                  `json:"users,omitempty"`
	WindowsProtectionState *WindowsProtectionState `json:"windowsProtectionState,omitempty"`
	OdataType              string                  `json:"@odata.type"`
}

// WindowsProtectionState struct for WindowsProtectionState
type WindowsProtectionState struct {
	Entity
	// Current anti malware version
	AntiMalwareVersion *string                   `json:"antiMalwareVersion,omitempty"`
	DeviceState        *WindowsDeviceHealthState `json:"deviceState,omitempty"`
	// Current endpoint protection engine's version
	EngineVersion *string `json:"engineVersion,omitempty"`
	// When TRUE indicates full scan is overdue, when FALSE indicates full scan is not overdue. Defaults to setting on client device.
	FullScanOverdue *bool `json:"fullScanOverdue,omitempty"`
	// When TRUE indicates full scan is required, when FALSE indicates full scan is not required. Defaults to setting on client device.
	FullScanRequired *bool `json:"fullScanRequired,omitempty"`
	// When TRUE indicates the device is a virtual machine, when FALSE indicates the device is not a virtual machine. Defaults to setting on client device.
	IsVirtualMachine *bool `json:"isVirtualMachine,omitempty"`
	// Last quick scan datetime
	LastFullScanDateTime *time.Time `json:"lastFullScanDateTime,omitempty"`
	// Last full scan signature version
	LastFullScanSignatureVersion *string `json:"lastFullScanSignatureVersion,omitempty"`
	// Last quick scan datetime
	LastQuickScanDateTime *time.Time `json:"lastQuickScanDateTime,omitempty"`
	// Last quick scan signature version
	LastQuickScanSignatureVersion *string `json:"lastQuickScanSignatureVersion,omitempty"`
	// Last device health status reported time
	LastReportedDateTime *time.Time `json:"lastReportedDateTime,omitempty"`
	// When TRUE indicates anti malware is enabled when FALSE indicates anti malware is not enabled.
	MalwareProtectionEnabled *bool `json:"malwareProtectionEnabled,omitempty"`
	// When TRUE indicates network inspection system enabled, when FALSE indicates network inspection system is not enabled. Defaults to setting on client device.
	NetworkInspectionSystemEnabled *bool                         `json:"networkInspectionSystemEnabled,omitempty"`
	ProductStatus                  *WindowsDefenderProductStatus `json:"productStatus,omitempty"`
	// When TRUE indicates quick scan is overdue, when FALSE indicates quick scan is not overdue. Defaults to setting on client device.
	QuickScanOverdue *bool `json:"quickScanOverdue,omitempty"`
	// When TRUE indicates real time protection is enabled, when FALSE indicates real time protection is not enabled. Defaults to setting on client device.
	RealTimeProtectionEnabled *bool `json:"realTimeProtectionEnabled,omitempty"`
	// When TRUE indicates reboot is required, when FALSE indicates when TRUE indicates reboot is not required. Defaults to setting on client device.
	RebootRequired *bool `json:"rebootRequired,omitempty"`
	// When TRUE indicates signature is out of date, when FALSE indicates signature is not out of date. Defaults to setting on client device.
	SignatureUpdateOverdue *bool `json:"signatureUpdateOverdue,omitempty"`
	// Current malware definitions version
	SignatureVersion *string `json:"signatureVersion,omitempty"`
	// When TRUE indicates the Windows Defender tamper protection feature is enabled, when FALSE indicates the Windows Defender tamper protection feature is not enabled. Defaults to setting on client device.
	TamperProtectionEnabled *bool `json:"tamperProtectionEnabled,omitempty"`
	// Device malware list
	DetectedMalwareState []WindowsDeviceMalwareState `json:"detectedMalwareState,omitempty"`
	OdataType            string                      `json:"@odata.type"`
}

// WindowsDeviceMalwareState struct for WindowsDeviceMalwareState
type WindowsDeviceMalwareState struct {
	Entity
	// Information URL to learn more about the malware
	AdditionalInformationUrl *string                 `json:"additionalInformationUrl,omitempty"`
	Category                 *WindowsMalwareCategory `json:"category,omitempty"`
	// Number of times the malware is detected
	DetectionCount *int32 `json:"detectionCount,omitempty"`
	// Malware name
	DisplayName    *string                       `json:"displayName,omitempty"`
	ExecutionState *WindowsMalwareExecutionState `json:"executionState,omitempty"`
	// Initial detection datetime of the malware
	InitialDetectionDateTime *time.Time `json:"initialDetectionDateTime,omitempty"`
	// The last time this particular threat was changed
	LastStateChangeDateTime *time.Time                 `json:"lastStateChangeDateTime,omitempty"`
	Severity                *WindowsMalwareSeverity    `json:"severity,omitempty"`
	State                   *WindowsMalwareState       `json:"state,omitempty"`
	ThreatState             *WindowsMalwareThreatState `json:"threatState,omitempty"`
	OdataType               string                     `json:"@odata.type"`
}

// WindowsMalwareState Malware current status
type WindowsMalwareState string

// List of microsoft.graph.windowsMalwareState
const (
	WINDOWSMALWARESTATE_UNKNOWN           WindowsMalwareState = "unknown"
	WINDOWSMALWARESTATE_DETECTED          WindowsMalwareState = "detected"
	WINDOWSMALWARESTATE_CLEANED           WindowsMalwareState = "cleaned"
	WINDOWSMALWARESTATE_QUARANTINED       WindowsMalwareState = "quarantined"
	WINDOWSMALWARESTATE_REMOVED           WindowsMalwareState = "removed"
	WINDOWSMALWARESTATE_ALLOWED           WindowsMalwareState = "allowed"
	WINDOWSMALWARESTATE_BLOCKED           WindowsMalwareState = "blocked"
	WINDOWSMALWARESTATE_CLEAN_FAILED      WindowsMalwareState = "cleanFailed"
	WINDOWSMALWARESTATE_QUARANTINE_FAILED WindowsMalwareState = "quarantineFailed"
	WINDOWSMALWARESTATE_REMOVE_FAILED     WindowsMalwareState = "removeFailed"
	WINDOWSMALWARESTATE_ALLOW_FAILED      WindowsMalwareState = "allowFailed"
	WINDOWSMALWARESTATE_ABANDONED         WindowsMalwareState = "abandoned"
	WINDOWSMALWARESTATE_BLOCK_FAILED      WindowsMalwareState = "blockFailed"
)

// All allowed values of WindowsMalwareState enum
var AllowedWindowsMalwareStateEnumValues = []WindowsMalwareState{
	"unknown",
	"detected",
	"cleaned",
	"quarantined",
	"removed",
	"allowed",
	"blocked",
	"cleanFailed",
	"quarantineFailed",
	"removeFailed",
	"allowFailed",
	"abandoned",
	"blockFailed",
}

func (v *WindowsMalwareState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := WindowsMalwareState(value)
	for _, existing := range AllowedWindowsMalwareStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid WindowsMalwareState", value)
}

// WindowsMalwareSeverity Malware severity
type WindowsMalwareSeverity string

// List of microsoft.graph.windowsMalwareSeverity
const (
	WINDOWSMALWARESEVERITY_UNKNOWN  WindowsMalwareSeverity = "unknown"
	WINDOWSMALWARESEVERITY_LOW      WindowsMalwareSeverity = "low"
	WINDOWSMALWARESEVERITY_MODERATE WindowsMalwareSeverity = "moderate"
	WINDOWSMALWARESEVERITY_HIGH     WindowsMalwareSeverity = "high"
	WINDOWSMALWARESEVERITY_SEVERE   WindowsMalwareSeverity = "severe"
)

// All allowed values of WindowsMalwareSeverity enum
var AllowedWindowsMalwareSeverityEnumValues = []WindowsMalwareSeverity{
	"unknown",
	"low",
	"moderate",
	"high",
	"severe",
}

func (v *WindowsMalwareSeverity) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := WindowsMalwareSeverity(value)
	for _, existing := range AllowedWindowsMalwareSeverityEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid WindowsMalwareSeverity", value)
}

// WindowsDeviceHealthState Computer endpoint protection state
type WindowsDeviceHealthState string

// List of microsoft.graph.windowsDeviceHealthState
const (
	WINDOWSDEVICEHEALTHSTATE_CLEAN                WindowsDeviceHealthState = "clean"
	WINDOWSDEVICEHEALTHSTATE_FULL_SCAN_PENDING    WindowsDeviceHealthState = "fullScanPending"
	WINDOWSDEVICEHEALTHSTATE_REBOOT_PENDING       WindowsDeviceHealthState = "rebootPending"
	WINDOWSDEVICEHEALTHSTATE_MANUAL_STEPS_PENDING WindowsDeviceHealthState = "manualStepsPending"
	WINDOWSDEVICEHEALTHSTATE_OFFLINE_SCAN_PENDING WindowsDeviceHealthState = "offlineScanPending"
	WINDOWSDEVICEHEALTHSTATE_CRITICAL             WindowsDeviceHealthState = "critical"
)

// All allowed values of WindowsDeviceHealthState enum
var AllowedWindowsDeviceHealthStateEnumValues = []WindowsDeviceHealthState{
	"clean",
	"fullScanPending",
	"rebootPending",
	"manualStepsPending",
	"offlineScanPending",
	"critical",
}

func (v *WindowsDeviceHealthState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := WindowsDeviceHealthState(value)
	for _, existing := range AllowedWindowsDeviceHealthStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid WindowsDeviceHealthState", value)
}

// WindowsDefenderProductStatus Product Status of Windows Defender
type WindowsDefenderProductStatus string

// List of microsoft.graph.windowsDefenderProductStatus
const (
	WINDOWSDEFENDERPRODUCTSTATUS_NO_STATUS                                                 WindowsDefenderProductStatus = "noStatus"
	WINDOWSDEFENDERPRODUCTSTATUS_SERVICE_NOT_RUNNING                                       WindowsDefenderProductStatus = "serviceNotRunning"
	WINDOWSDEFENDERPRODUCTSTATUS_SERVICE_STARTED_WITHOUT_MALWARE_PROTECTION                WindowsDefenderProductStatus = "serviceStartedWithoutMalwareProtection"
	WINDOWSDEFENDERPRODUCTSTATUS_PENDING_FULL_SCAN_DUE_TO_THREAT_ACTION                    WindowsDefenderProductStatus = "pendingFullScanDueToThreatAction"
	WINDOWSDEFENDERPRODUCTSTATUS_PENDING_REBOOT_DUE_TO_THREAT_ACTION                       WindowsDefenderProductStatus = "pendingRebootDueToThreatAction"
	WINDOWSDEFENDERPRODUCTSTATUS_PENDING_MANUAL_STEPS_DUE_TO_THREAT_ACTION                 WindowsDefenderProductStatus = "pendingManualStepsDueToThreatAction"
	WINDOWSDEFENDERPRODUCTSTATUS_AV_SIGNATURES_OUT_OF_DATE                                 WindowsDefenderProductStatus = "avSignaturesOutOfDate"
	WINDOWSDEFENDERPRODUCTSTATUS_AS_SIGNATURES_OUT_OF_DATE                                 WindowsDefenderProductStatus = "asSignaturesOutOfDate"
	WINDOWSDEFENDERPRODUCTSTATUS_NO_QUICK_SCAN_HAPPENED_FOR_SPECIFIED_PERIOD               WindowsDefenderProductStatus = "noQuickScanHappenedForSpecifiedPeriod"
	WINDOWSDEFENDERPRODUCTSTATUS_NO_FULL_SCAN_HAPPENED_FOR_SPECIFIED_PERIOD                WindowsDefenderProductStatus = "noFullScanHappenedForSpecifiedPeriod"
	WINDOWSDEFENDERPRODUCTSTATUS_SYSTEM_INITIATED_SCAN_IN_PROGRESS                         WindowsDefenderProductStatus = "systemInitiatedScanInProgress"
	WINDOWSDEFENDERPRODUCTSTATUS_SYSTEM_INITIATED_CLEAN_IN_PROGRESS                        WindowsDefenderProductStatus = "systemInitiatedCleanInProgress"
	WINDOWSDEFENDERPRODUCTSTATUS_SAMPLES_PENDING_SUBMISSION                                WindowsDefenderProductStatus = "samplesPendingSubmission"
	WINDOWSDEFENDERPRODUCTSTATUS_PRODUCT_RUNNING_IN_EVALUATION_MODE                        WindowsDefenderProductStatus = "productRunningInEvaluationMode"
	WINDOWSDEFENDERPRODUCTSTATUS_PRODUCT_RUNNING_IN_NON_GENUINE_MODE                       WindowsDefenderProductStatus = "productRunningInNonGenuineMode"
	WINDOWSDEFENDERPRODUCTSTATUS_PRODUCT_EXPIRED                                           WindowsDefenderProductStatus = "productExpired"
	WINDOWSDEFENDERPRODUCTSTATUS_OFFLINE_SCAN_REQUIRED                                     WindowsDefenderProductStatus = "offlineScanRequired"
	WINDOWSDEFENDERPRODUCTSTATUS_SERVICE_SHUTDOWN_AS_PART_OF_SYSTEM_SHUTDOWN               WindowsDefenderProductStatus = "serviceShutdownAsPartOfSystemShutdown"
	WINDOWSDEFENDERPRODUCTSTATUS_THREAT_REMEDIATION_FAILED_CRITICALLY                      WindowsDefenderProductStatus = "threatRemediationFailedCritically"
	WINDOWSDEFENDERPRODUCTSTATUS_THREAT_REMEDIATION_FAILED_NON_CRITICALLY                  WindowsDefenderProductStatus = "threatRemediationFailedNonCritically"
	WINDOWSDEFENDERPRODUCTSTATUS_NO_STATUS_FLAGS_SET                                       WindowsDefenderProductStatus = "noStatusFlagsSet"
	WINDOWSDEFENDERPRODUCTSTATUS_PLATFORM_OUT_OF_DATE                                      WindowsDefenderProductStatus = "platformOutOfDate"
	WINDOWSDEFENDERPRODUCTSTATUS_PLATFORM_UPDATE_IN_PROGRESS                               WindowsDefenderProductStatus = "platformUpdateInProgress"
	WINDOWSDEFENDERPRODUCTSTATUS_PLATFORM_ABOUT_TO_BE_OUTDATED                             WindowsDefenderProductStatus = "platformAboutToBeOutdated"
	WINDOWSDEFENDERPRODUCTSTATUS_SIGNATURE_OR_PLATFORM_END_OF_LIFE_IS_PAST_OR_IS_IMPENDING WindowsDefenderProductStatus = "signatureOrPlatformEndOfLifeIsPastOrIsImpending"
	WINDOWSDEFENDERPRODUCTSTATUS_WINDOWS_S_MODE_SIGNATURES_IN_USE_ON_NON_WIN10_S_INSTALL   WindowsDefenderProductStatus = "windowsSModeSignaturesInUseOnNonWin10SInstall"
)

// All allowed values of WindowsDefenderProductStatus enum
var AllowedWindowsDefenderProductStatusEnumValues = []WindowsDefenderProductStatus{
	"noStatus",
	"serviceNotRunning",
	"serviceStartedWithoutMalwareProtection",
	"pendingFullScanDueToThreatAction",
	"pendingRebootDueToThreatAction",
	"pendingManualStepsDueToThreatAction",
	"avSignaturesOutOfDate",
	"asSignaturesOutOfDate",
	"noQuickScanHappenedForSpecifiedPeriod",
	"noFullScanHappenedForSpecifiedPeriod",
	"systemInitiatedScanInProgress",
	"systemInitiatedCleanInProgress",
	"samplesPendingSubmission",
	"productRunningInEvaluationMode",
	"productRunningInNonGenuineMode",
	"productExpired",
	"offlineScanRequired",
	"serviceShutdownAsPartOfSystemShutdown",
	"threatRemediationFailedCritically",
	"threatRemediationFailedNonCritically",
	"noStatusFlagsSet",
	"platformOutOfDate",
	"platformUpdateInProgress",
	"platformAboutToBeOutdated",
	"signatureOrPlatformEndOfLifeIsPastOrIsImpending",
	"windowsSModeSignaturesInUseOnNonWin10SInstall",
}

func (v *WindowsDefenderProductStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := WindowsDefenderProductStatus(value)
	for _, existing := range AllowedWindowsDefenderProductStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid WindowsDefenderProductStatus", value)
}

// DeviceLogCollectionResponse struct for DeviceLogCollectionResponse
type DeviceLogCollectionResponse struct {
	Entity
	// The User Principal Name (UPN) of the user that enrolled the device.
	EnrolledByUser *string `json:"enrolledByUser,omitempty"`
	// The DateTime of the expiration of the logs.
	ExpirationDateTimeUTC *time.Time `json:"expirationDateTimeUTC,omitempty"`
	// The UPN for who initiated the request.
	InitiatedByUserPrincipalName *string `json:"initiatedByUserPrincipalName,omitempty"`
	// Indicates Intune device unique identifier.
	ManagedDeviceId *string `json:"managedDeviceId,omitempty"`
	// The DateTime the request was received.
	ReceivedDateTimeUTC *time.Time `json:"receivedDateTimeUTC,omitempty"`
	// The DateTime of the request.
	RequestedDateTimeUTC *time.Time                           `json:"requestedDateTimeUTC,omitempty"`
	SizeInKB             *DeviceLogCollectionResponseSizeInKB `json:"sizeInKB,omitempty"`
	Status               *AppLogUploadState                   `json:"status,omitempty"`
	OdataType            string                               `json:"@odata.type"`
}

// AppLogUploadState AppLogUploadStatus
type AppLogUploadState string

// List of microsoft.graph.appLogUploadState
const (
	APPLOGUPLOADSTATE_PENDING              AppLogUploadState = "pending"
	APPLOGUPLOADSTATE_COMPLETED            AppLogUploadState = "completed"
	APPLOGUPLOADSTATE_FAILED               AppLogUploadState = "failed"
	APPLOGUPLOADSTATE_UNKNOWN_FUTURE_VALUE AppLogUploadState = "unknownFutureValue"
)

// All allowed values of AppLogUploadState enum
var AllowedAppLogUploadStateEnumValues = []AppLogUploadState{
	"pending",
	"completed",
	"failed",
	"unknownFutureValue",
}

func (v *AppLogUploadState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := AppLogUploadState(value)
	for _, existing := range AllowedAppLogUploadStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid AppLogUploadState", value)
}

// DeviceLogCollectionResponseSizeInKB - The size of the logs in KB. Valid values -1.79769313486232E+308 to 1.79769313486232E+308
type DeviceLogCollectionResponseSizeInKB struct {
	ReferenceNumeric *ReferenceNumeric
	Float64          *float64
	String           *string
}

// ReferenceNumeric the model 'ReferenceNumeric'
type ReferenceNumeric string

// List of ReferenceNumeric
const (
	REFERENCENUMERIC_INF  ReferenceNumeric = "-INF"
	REFERENCENUMERIC_INF2 ReferenceNumeric = "INF"
	REFERENCENUMERIC_NA_N ReferenceNumeric = "NaN"
)

// All allowed values of ReferenceNumeric enum
var AllowedReferenceNumericEnumValues = []ReferenceNumeric{
	"-INF",
	"INF",
	"NaN",
}

func (v *ReferenceNumeric) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ReferenceNumeric(value)
	for _, existing := range AllowedReferenceNumericEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ReferenceNumeric", value)
}

// DeviceCategory struct for DeviceCategory
type DeviceCategory struct {
	Entity
	// Optional description for the device category.
	Description *string `json:"description,omitempty"`
	// Display name for the device category.
	DisplayName *string `json:"displayName,omitempty"`
	OdataType   string  `json:"@odata.type"`
}

// DeviceConfigurationSettingState Device Configuration Setting State for a given device.
type DeviceConfigurationSettingState struct {
	// Current value of setting on device
	CurrentValue *string `json:"currentValue,omitempty"`
	// Error code for the setting
	ErrorCode *int64 `json:"errorCode,omitempty"`
	// Error description
	ErrorDescription *string `json:"errorDescription,omitempty"`
	// Name of setting instance that is being reported.
	InstanceDisplayName *string `json:"instanceDisplayName,omitempty"`
	// The setting that is being reported
	Setting *string `json:"setting,omitempty"`
	// Localized/user friendly setting name that is being reported
	SettingName *string `json:"settingName,omitempty"`
	// Contributing policies
	Sources []SettingSource   `json:"sources,omitempty"`
	State   *ComplianceStatus `json:"state,omitempty"`
	// UserEmail
	UserEmail *string `json:"userEmail,omitempty"`
	// UserId
	UserId *string `json:"userId,omitempty"`
	// UserName
	UserName *string `json:"userName,omitempty"`
	// UserPrincipalName.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// DeviceCompliancePolicyState struct for DeviceCompliancePolicyState
type DeviceCompliancePolicyState struct {
	Entity
	// The name of the policy for this policyBase
	DisplayName  *string             `json:"displayName,omitempty"`
	PlatformType *PolicyPlatformType `json:"platformType,omitempty"`
	// Count of how many setting a policy holds
	SettingCount  *int32                               `json:"settingCount,omitempty"`
	SettingStates []DeviceCompliancePolicySettingState `json:"settingStates,omitempty"`
	State         *ComplianceStatus                    `json:"state,omitempty"`
	// The version of the policy
	Version   *int32 `json:"version,omitempty"`
	OdataType string `json:"@odata.type"`
}

// DeviceCompliancePolicySettingState Device Compilance Policy Setting State for a given device.
type DeviceCompliancePolicySettingState struct {
	// Current value of setting on device
	CurrentValue *string `json:"currentValue,omitempty"`
	// Error code for the setting
	ErrorCode *int64 `json:"errorCode,omitempty"`
	// Error description
	ErrorDescription *string `json:"errorDescription,omitempty"`
	// Name of setting instance that is being reported.
	InstanceDisplayName *string `json:"instanceDisplayName,omitempty"`
	// The setting that is being reported
	Setting *string `json:"setting,omitempty"`
	// Localized/user friendly setting name that is being reported
	SettingName *string `json:"settingName,omitempty"`
	// Contributing policies
	Sources []SettingSource   `json:"sources,omitempty"`
	State   *ComplianceStatus `json:"state,omitempty"`
	// UserEmail
	UserEmail *string `json:"userEmail,omitempty"`
	// UserId
	UserId *string `json:"userId,omitempty"`
	// UserName
	UserName *string `json:"userName,omitempty"`
	// UserPrincipalName.
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// DeviceConfigurationState struct for DeviceConfigurationState
type DeviceConfigurationState struct {
	Entity
	// The name of the policy for this policyBase
	DisplayName  *string             `json:"displayName,omitempty"`
	PlatformType *PolicyPlatformType `json:"platformType,omitempty"`
	// Count of how many setting a policy holds
	SettingCount  *int32                            `json:"settingCount,omitempty"`
	SettingStates []DeviceConfigurationSettingState `json:"settingStates,omitempty"`
	State         *ComplianceStatus                 `json:"state,omitempty"`
	// The version of the policy
	Version   *int32 `json:"version,omitempty"`
	OdataType string `json:"@odata.type"`
}

// ComplianceStatus the model 'ComplianceStatus'
type ComplianceStatus string

// List of microsoft.graph.complianceStatus
const (
	COMPLIANCESTATUS_UNKNOWN        ComplianceStatus = "unknown"
	COMPLIANCESTATUS_NOT_APPLICABLE ComplianceStatus = "notApplicable"
	COMPLIANCESTATUS_COMPLIANT      ComplianceStatus = "compliant"
	COMPLIANCESTATUS_REMEDIATED     ComplianceStatus = "remediated"
	COMPLIANCESTATUS_NON_COMPLIANT  ComplianceStatus = "nonCompliant"
	COMPLIANCESTATUS_ERROR          ComplianceStatus = "error"
	COMPLIANCESTATUS_CONFLICT       ComplianceStatus = "conflict"
	COMPLIANCESTATUS_NOT_ASSIGNED   ComplianceStatus = "notAssigned"
)

// All allowed values of ComplianceStatus enum
var AllowedComplianceStatusEnumValues = []ComplianceStatus{
	"unknown",
	"notApplicable",
	"compliant",
	"remediated",
	"nonCompliant",
	"error",
	"conflict",
	"notAssigned",
}

func (v *ComplianceStatus) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ComplianceStatus(value)
	for _, existing := range AllowedComplianceStatusEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ComplianceStatus", value)
}

// SettingSource struct for SettingSource
type SettingSource struct {
	// Not yet documented
	DisplayName *string `json:"displayName,omitempty"`
	// Not yet documented
	Id         *string            `json:"id,omitempty"`
	SourceType *SettingSourceType `json:"sourceType,omitempty"`
	OdataType  string             `json:"@odata.type"`
}

// SettingSourceType the model 'SettingSourceType'
type SettingSourceType string

// List of microsoft.graph.settingSourceType
const (
	SETTINGSOURCETYPE_DEVICE_CONFIGURATION SettingSourceType = "deviceConfiguration"
	SETTINGSOURCETYPE_DEVICE_INTENT        SettingSourceType = "deviceIntent"
)

// All allowed values of SettingSourceType enum
var AllowedSettingSourceTypeEnumValues = []SettingSourceType{
	"deviceConfiguration",
	"deviceIntent",
}

func (v *SettingSourceType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := SettingSourceType(value)
	for _, existing := range AllowedSettingSourceTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid SettingSourceType", value)
}

// PolicyPlatformType Supported platform types for policies.
type PolicyPlatformType string

// List of microsoft.graph.policyPlatformType
const (
	POLICYPLATFORMTYPE_ANDROID             PolicyPlatformType = "android"
	POLICYPLATFORMTYPE_ANDROID_FOR_WORK    PolicyPlatformType = "androidForWork"
	POLICYPLATFORMTYPE_I_OS                PolicyPlatformType = "iOS"
	POLICYPLATFORMTYPE_MAC_OS              PolicyPlatformType = "macOS"
	POLICYPLATFORMTYPE_WINDOWS_PHONE81     PolicyPlatformType = "windowsPhone81"
	POLICYPLATFORMTYPE_WINDOWS81_AND_LATER PolicyPlatformType = "windows81AndLater"
	POLICYPLATFORMTYPE_WINDOWS10_AND_LATER PolicyPlatformType = "windows10AndLater"
	POLICYPLATFORMTYPE_ALL                 PolicyPlatformType = "all"
)

// All allowed values of PolicyPlatformType enum
var AllowedPolicyPlatformTypeEnumValues = []PolicyPlatformType{
	"android",
	"androidForWork",
	"iOS",
	"macOS",
	"windowsPhone81",
	"windows81AndLater",
	"windows10AndLater",
	"all",
}

func (v *PolicyPlatformType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := PolicyPlatformType(value)
	for _, existing := range AllowedPolicyPlatformTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid PolicyPlatformType", value)
}

// ManagedDevicePartnerReportedHealthState Available health states for the Device Health API
type ManagedDevicePartnerReportedHealthState string

// List of microsoft.graph.managedDevicePartnerReportedHealthState
const (
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_UNKNOWN         ManagedDevicePartnerReportedHealthState = "unknown"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_ACTIVATED       ManagedDevicePartnerReportedHealthState = "activated"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_DEACTIVATED     ManagedDevicePartnerReportedHealthState = "deactivated"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_SECURED         ManagedDevicePartnerReportedHealthState = "secured"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_LOW_SEVERITY    ManagedDevicePartnerReportedHealthState = "lowSeverity"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_MEDIUM_SEVERITY ManagedDevicePartnerReportedHealthState = "mediumSeverity"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_HIGH_SEVERITY   ManagedDevicePartnerReportedHealthState = "highSeverity"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_UNRESPONSIVE    ManagedDevicePartnerReportedHealthState = "unresponsive"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_COMPROMISED     ManagedDevicePartnerReportedHealthState = "compromised"
	MANAGEDDEVICEPARTNERREPORTEDHEALTHSTATE_MISCONFIGURED   ManagedDevicePartnerReportedHealthState = "misconfigured"
)

// All allowed values of ManagedDevicePartnerReportedHealthState enum
var AllowedManagedDevicePartnerReportedHealthStateEnumValues = []ManagedDevicePartnerReportedHealthState{
	"unknown",
	"activated",
	"deactivated",
	"secured",
	"lowSeverity",
	"mediumSeverity",
	"highSeverity",
	"unresponsive",
	"compromised",
	"misconfigured",
}

func (v *ManagedDevicePartnerReportedHealthState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ManagedDevicePartnerReportedHealthState(value)
	for _, existing := range AllowedManagedDevicePartnerReportedHealthStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ManagedDevicePartnerReportedHealthState", value)
}

// ManagementAgentType the model 'ManagementAgentType'
type ManagementAgentType string

// List of microsoft.graph.managementAgentType
const (
	MANAGEMENTAGENTTYPE_EAS                                   ManagementAgentType = "eas"
	MANAGEMENTAGENTTYPE_MDM                                   ManagementAgentType = "mdm"
	MANAGEMENTAGENTTYPE_EAS_MDM                               ManagementAgentType = "easMdm"
	MANAGEMENTAGENTTYPE_INTUNE_CLIENT                         ManagementAgentType = "intuneClient"
	MANAGEMENTAGENTTYPE_EAS_INTUNE_CLIENT                     ManagementAgentType = "easIntuneClient"
	MANAGEMENTAGENTTYPE_CONFIGURATION_MANAGER_CLIENT          ManagementAgentType = "configurationManagerClient"
	MANAGEMENTAGENTTYPE_CONFIGURATION_MANAGER_CLIENT_MDM      ManagementAgentType = "configurationManagerClientMdm"
	MANAGEMENTAGENTTYPE_CONFIGURATION_MANAGER_CLIENT_MDM_EAS  ManagementAgentType = "configurationManagerClientMdmEas"
	MANAGEMENTAGENTTYPE_UNKNOWN                               ManagementAgentType = "unknown"
	MANAGEMENTAGENTTYPE_JAMF                                  ManagementAgentType = "jamf"
	MANAGEMENTAGENTTYPE_GOOGLE_CLOUD_DEVICE_POLICY_CONTROLLER ManagementAgentType = "googleCloudDevicePolicyController"
	MANAGEMENTAGENTTYPE_MICROSOFT365_MANAGED_MDM              ManagementAgentType = "microsoft365ManagedMdm"
	MANAGEMENTAGENTTYPE_MS_SENSE                              ManagementAgentType = "msSense"
)

// All allowed values of ManagementAgentType enum
var AllowedManagementAgentTypeEnumValues = []ManagementAgentType{
	"eas",
	"mdm",
	"easMdm",
	"intuneClient",
	"easIntuneClient",
	"configurationManagerClient",
	"configurationManagerClientMdm",
	"configurationManagerClientMdmEas",
	"unknown",
	"jamf",
	"googleCloudDevicePolicyController",
	"microsoft365ManagedMdm",
	"msSense",
}

func (v *ManagementAgentType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ManagementAgentType(value)
	for _, existing := range AllowedManagementAgentTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ManagementAgentType", value)
}

// ManagedDeviceOwnerType Owner type of device.
type ManagedDeviceOwnerType string

// List of microsoft.graph.managedDeviceOwnerType
const (
	MANAGEDDEVICEOWNERTYPE_UNKNOWN  ManagedDeviceOwnerType = "unknown"
	MANAGEDDEVICEOWNERTYPE_COMPANY  ManagedDeviceOwnerType = "company"
	MANAGEDDEVICEOWNERTYPE_PERSONAL ManagedDeviceOwnerType = "personal"
)

// All allowed values of ManagedDeviceOwnerType enum
var AllowedManagedDeviceOwnerTypeEnumValues = []ManagedDeviceOwnerType{
	"unknown",
	"company",
	"personal",
}

func (v *ManagedDeviceOwnerType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ManagedDeviceOwnerType(value)
	for _, existing := range AllowedManagedDeviceOwnerTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ManagedDeviceOwnerType", value)
}

// DeviceManagementExchangeAccessStateReason Device Exchange Access State Reason.
type DeviceManagementExchangeAccessStateReason string

// List of microsoft.graph.deviceManagementExchangeAccessStateReason
const (
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_NONE                                DeviceManagementExchangeAccessStateReason = "none"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_UNKNOWN                             DeviceManagementExchangeAccessStateReason = "unknown"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_EXCHANGE_GLOBAL_RULE                DeviceManagementExchangeAccessStateReason = "exchangeGlobalRule"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_EXCHANGE_INDIVIDUAL_RULE            DeviceManagementExchangeAccessStateReason = "exchangeIndividualRule"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_EXCHANGE_DEVICE_RULE                DeviceManagementExchangeAccessStateReason = "exchangeDeviceRule"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_EXCHANGE_UPGRADE                    DeviceManagementExchangeAccessStateReason = "exchangeUpgrade"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_EXCHANGE_MAILBOX_POLICY             DeviceManagementExchangeAccessStateReason = "exchangeMailboxPolicy"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_OTHER                               DeviceManagementExchangeAccessStateReason = "other"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_COMPLIANT                           DeviceManagementExchangeAccessStateReason = "compliant"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_NOT_COMPLIANT                       DeviceManagementExchangeAccessStateReason = "notCompliant"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_NOT_ENROLLED                        DeviceManagementExchangeAccessStateReason = "notEnrolled"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_UNKNOWN_LOCATION                    DeviceManagementExchangeAccessStateReason = "unknownLocation"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_MFA_REQUIRED                        DeviceManagementExchangeAccessStateReason = "mfaRequired"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_AZURE_AD_BLOCK_DUE_TO_ACCESS_POLICY DeviceManagementExchangeAccessStateReason = "azureADBlockDueToAccessPolicy"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_COMPROMISED_PASSWORD                DeviceManagementExchangeAccessStateReason = "compromisedPassword"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATEREASON_DEVICE_NOT_KNOWN_WITH_MANAGED_APP   DeviceManagementExchangeAccessStateReason = "deviceNotKnownWithManagedApp"
)

// All allowed values of DeviceManagementExchangeAccessStateReason enum
var AllowedDeviceManagementExchangeAccessStateReasonEnumValues = []DeviceManagementExchangeAccessStateReason{
	"none",
	"unknown",
	"exchangeGlobalRule",
	"exchangeIndividualRule",
	"exchangeDeviceRule",
	"exchangeUpgrade",
	"exchangeMailboxPolicy",
	"other",
	"compliant",
	"notCompliant",
	"notEnrolled",
	"unknownLocation",
	"mfaRequired",
	"azureADBlockDueToAccessPolicy",
	"compromisedPassword",
	"deviceNotKnownWithManagedApp",
}

func (v *DeviceManagementExchangeAccessStateReason) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementExchangeAccessStateReason(value)
	for _, existing := range AllowedDeviceManagementExchangeAccessStateReasonEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementExchangeAccessStateReason", value)
}

// DeviceManagementExchangeAccessState Device Exchange Access State.
type DeviceManagementExchangeAccessState string

// List of microsoft.graph.deviceManagementExchangeAccessState
const (
	DEVICEMANAGEMENTEXCHANGEACCESSSTATE_NONE        DeviceManagementExchangeAccessState = "none"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATE_UNKNOWN     DeviceManagementExchangeAccessState = "unknown"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATE_ALLOWED     DeviceManagementExchangeAccessState = "allowed"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATE_BLOCKED     DeviceManagementExchangeAccessState = "blocked"
	DEVICEMANAGEMENTEXCHANGEACCESSSTATE_QUARANTINED DeviceManagementExchangeAccessState = "quarantined"
)

// All allowed values of DeviceManagementExchangeAccessState enum
var AllowedDeviceManagementExchangeAccessStateEnumValues = []DeviceManagementExchangeAccessState{
	"none",
	"unknown",
	"allowed",
	"blocked",
	"quarantined",
}

func (v *DeviceManagementExchangeAccessState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementExchangeAccessState(value)
	for _, existing := range AllowedDeviceManagementExchangeAccessStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementExchangeAccessState", value)
}

// DeviceRegistrationState Device registration status.
type DeviceRegistrationState string

// List of microsoft.graph.deviceRegistrationState
const (
	DEVICEREGISTRATIONSTATE_NOT_REGISTERED                    DeviceRegistrationState = "notRegistered"
	DEVICEREGISTRATIONSTATE_REGISTERED                        DeviceRegistrationState = "registered"
	DEVICEREGISTRATIONSTATE_REVOKED                           DeviceRegistrationState = "revoked"
	DEVICEREGISTRATIONSTATE_KEY_CONFLICT                      DeviceRegistrationState = "keyConflict"
	DEVICEREGISTRATIONSTATE_APPROVAL_PENDING                  DeviceRegistrationState = "approvalPending"
	DEVICEREGISTRATIONSTATE_CERTIFICATE_RESET                 DeviceRegistrationState = "certificateReset"
	DEVICEREGISTRATIONSTATE_NOT_REGISTERED_PENDING_ENROLLMENT DeviceRegistrationState = "notRegisteredPendingEnrollment"
	DEVICEREGISTRATIONSTATE_UNKNOWN                           DeviceRegistrationState = "unknown"
)

// All allowed values of DeviceRegistrationState enum
var AllowedDeviceRegistrationStateEnumValues = []DeviceRegistrationState{
	"notRegistered",
	"registered",
	"revoked",
	"keyConflict",
	"approvalPending",
	"certificateReset",
	"notRegisteredPendingEnrollment",
	"unknown",
}

func (v *DeviceRegistrationState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceRegistrationState(value)
	for _, existing := range AllowedDeviceRegistrationStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceRegistrationState", value)
}

// DeviceHealthAttestationState struct for DeviceHealthAttestationState
type DeviceHealthAttestationState struct {
	// TWhen an Attestation Identity Key (AIK) is present on a device, it indicates that the device has an endorsement key (EK) certificate.
	AttestationIdentityKey *string `json:"attestationIdentityKey,omitempty"`
	// On or Off of BitLocker Drive Encryption
	BitLockerStatus *string `json:"bitLockerStatus,omitempty"`
	// The security version number of the Boot Application
	BootAppSecurityVersion *string `json:"bootAppSecurityVersion,omitempty"`
	// When bootDebugging is enabled, the device is used in development and testing
	BootDebugging *string `json:"bootDebugging,omitempty"`
	// The security version number of the Boot Application
	BootManagerSecurityVersion *string `json:"bootManagerSecurityVersion,omitempty"`
	// The version of the Boot Manager
	BootManagerVersion *string `json:"bootManagerVersion,omitempty"`
	// The Boot Revision List that was loaded during initial boot on the attested device
	BootRevisionListInfo *string `json:"bootRevisionListInfo,omitempty"`
	// When code integrity is enabled, code execution is restricted to integrity verified code
	CodeIntegrity *string `json:"codeIntegrity,omitempty"`
	// The version of the Boot Manager
	CodeIntegrityCheckVersion *string `json:"codeIntegrityCheckVersion,omitempty"`
	// The Code Integrity policy that is controlling the security of the boot environment
	CodeIntegrityPolicy *string `json:"codeIntegrityPolicy,omitempty"`
	// The DHA report version. (Namespace version)
	ContentNamespaceUrl *string `json:"contentNamespaceUrl,omitempty"`
	// The HealthAttestation state schema version
	ContentVersion *string `json:"contentVersion,omitempty"`
	// DEP Policy defines a set of hardware and software technologies that perform additional checks on memory
	DataExcutionPolicy *string `json:"dataExcutionPolicy,omitempty"`
	// The DHA report version. (Namespace version)
	DeviceHealthAttestationStatus *string `json:"deviceHealthAttestationStatus,omitempty"`
	// ELAM provides protection for the computers in your network when they start up
	EarlyLaunchAntiMalwareDriverProtection *string `json:"earlyLaunchAntiMalwareDriverProtection,omitempty"`
	// This attribute indicates if DHA is supported for the device
	HealthAttestationSupportedStatus *string `json:"healthAttestationSupportedStatus,omitempty"`
	// This attribute appears if DHA-Service detects an integrity issue
	HealthStatusMismatchInfo *string `json:"healthStatusMismatchInfo,omitempty"`
	// The DateTime when device was evaluated or issued to MDM
	IssuedDateTime *time.Time `json:"issuedDateTime,omitempty"`
	// The Timestamp of the last update.
	LastUpdateDateTime *string `json:"lastUpdateDateTime,omitempty"`
	// When operatingSystemKernelDebugging is enabled, the device is used in development and testing
	OperatingSystemKernelDebugging *string `json:"operatingSystemKernelDebugging,omitempty"`
	// The Operating System Revision List that was loaded during initial boot on the attested device
	OperatingSystemRevListInfo *string `json:"operatingSystemRevListInfo,omitempty"`
	// The measurement that is captured in PCR[0]
	Pcr0 *string `json:"pcr0,omitempty"`
	// Informational attribute that identifies the HASH algorithm that was used by TPM
	PcrHashAlgorithm *string `json:"pcrHashAlgorithm,omitempty"`
	// The number of times a PC device has hibernated or resumed
	ResetCount *int64 `json:"resetCount,omitempty"`
	// The number of times a PC device has rebooted
	RestartCount *int64 `json:"restartCount,omitempty"`
	// Safe mode is a troubleshooting option for Windows that starts your computer in a limited state
	SafeMode *string `json:"safeMode,omitempty"`
	// When Secure Boot is enabled, the core components must have the correct cryptographic signatures
	SecureBoot *string `json:"secureBoot,omitempty"`
	// Fingerprint of the Custom Secure Boot Configuration Policy
	SecureBootConfigurationPolicyFingerPrint *string `json:"secureBootConfigurationPolicyFingerPrint,omitempty"`
	// When test signing is allowed, the device does not enforce signature validation during boot
	TestSigning *string `json:"testSigning,omitempty"`
	// The security version number of the Boot Application
	TpmVersion *string `json:"tpmVersion,omitempty"`
	// VSM is a container that protects high value assets from a compromised kernel
	VirtualSecureMode *string `json:"virtualSecureMode,omitempty"`
	// Operating system running with limited services that is used to prepare a computer for Windows
	WindowsPE *string `json:"windowsPE,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// DeviceEnrollmentType Possible ways of adding a mobile device to management.
type DeviceEnrollmentType string

// List of microsoft.graph.deviceEnrollmentType
const (
	DEVICEENROLLMENTTYPE_UNKNOWN                                    DeviceEnrollmentType = "unknown"
	DEVICEENROLLMENTTYPE_USER_ENROLLMENT                            DeviceEnrollmentType = "userEnrollment"
	DEVICEENROLLMENTTYPE_DEVICE_ENROLLMENT_MANAGER                  DeviceEnrollmentType = "deviceEnrollmentManager"
	DEVICEENROLLMENTTYPE_APPLE_BULK_WITH_USER                       DeviceEnrollmentType = "appleBulkWithUser"
	DEVICEENROLLMENTTYPE_APPLE_BULK_WITHOUT_USER                    DeviceEnrollmentType = "appleBulkWithoutUser"
	DEVICEENROLLMENTTYPE_WINDOWS_AZURE_AD_JOIN                      DeviceEnrollmentType = "windowsAzureADJoin"
	DEVICEENROLLMENTTYPE_WINDOWS_BULK_USERLESS                      DeviceEnrollmentType = "windowsBulkUserless"
	DEVICEENROLLMENTTYPE_WINDOWS_AUTO_ENROLLMENT                    DeviceEnrollmentType = "windowsAutoEnrollment"
	DEVICEENROLLMENTTYPE_WINDOWS_BULK_AZURE_DOMAIN_JOIN             DeviceEnrollmentType = "windowsBulkAzureDomainJoin"
	DEVICEENROLLMENTTYPE_WINDOWS_CO_MANAGEMENT                      DeviceEnrollmentType = "windowsCoManagement"
	DEVICEENROLLMENTTYPE_WINDOWS_AZURE_AD_JOIN_USING_DEVICE_AUTH    DeviceEnrollmentType = "windowsAzureADJoinUsingDeviceAuth"
	DEVICEENROLLMENTTYPE_APPLE_USER_ENROLLMENT                      DeviceEnrollmentType = "appleUserEnrollment"
	DEVICEENROLLMENTTYPE_APPLE_USER_ENROLLMENT_WITH_SERVICE_ACCOUNT DeviceEnrollmentType = "appleUserEnrollmentWithServiceAccount"
)

// All allowed values of DeviceEnrollmentType enum
var AllowedDeviceEnrollmentTypeEnumValues = []DeviceEnrollmentType{
	"unknown",
	"userEnrollment",
	"deviceEnrollmentManager",
	"appleBulkWithUser",
	"appleBulkWithoutUser",
	"windowsAzureADJoin",
	"windowsBulkUserless",
	"windowsAutoEnrollment",
	"windowsBulkAzureDomainJoin",
	"windowsCoManagement",
	"windowsAzureADJoinUsingDeviceAuth",
	"appleUserEnrollment",
	"appleUserEnrollmentWithServiceAccount",
}

func (v *DeviceEnrollmentType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceEnrollmentType(value)
	for _, existing := range AllowedDeviceEnrollmentTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceEnrollmentType", value)
}

// ActionResult Device action result
type DeviceActionResult struct {
	// Action name
	ActionName  *string      `json:"actionName,omitempty"`
	ActionState *ActionState `json:"actionState,omitempty"`
	// Time the action state was last updated
	LastUpdatedDateTime *time.Time `json:"lastUpdatedDateTime,omitempty"`
	// Time the action was initiated
	StartDateTime *time.Time `json:"startDateTime,omitempty"`
	OdataType     string     `json:"@odata.type"`
}

// ActionState State of the action on the device
type ActionState string

// List of microsoft.graph.actionState
const (
	ACTIONSTATE_NONE          ActionState = "none"
	ACTIONSTATE_PENDING       ActionState = "pending"
	ACTIONSTATE_CANCELED      ActionState = "canceled"
	ACTIONSTATE_ACTIVE        ActionState = "active"
	ACTIONSTATE_DONE          ActionState = "done"
	ACTIONSTATE_FAILED        ActionState = "failed"
	ACTIONSTATE_NOT_SUPPORTED ActionState = "notSupported"
)

// All allowed values of ActionState enum
var AllowedActionStateEnumValues = []ActionState{
	"none",
	"pending",
	"canceled",
	"active",
	"done",
	"failed",
	"notSupported",
}

func (v *ActionState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ActionState(value)
	for _, existing := range AllowedActionStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ActionState", value)
}

// ConfigurationManagerClientEnabledFeatures configuration Manager client enabled features
type ConfigurationManagerClientEnabledFeatures struct {
	// Whether compliance policy is managed by Intune
	CompliancePolicy *bool `json:"compliancePolicy,omitempty"`
	// Whether device configuration is managed by Intune
	DeviceConfiguration *bool `json:"deviceConfiguration,omitempty"`
	// Whether inventory is managed by Intune
	Inventory *bool `json:"inventory,omitempty"`
	// Whether modern application is managed by Intune
	ModernApps *bool `json:"modernApps,omitempty"`
	// Whether resource access is managed by Intune
	ResourceAccess *bool `json:"resourceAccess,omitempty"`
	// Whether Windows Update for Business is managed by Intune
	WindowsUpdateForBusiness *bool  `json:"windowsUpdateForBusiness,omitempty"`
	OdataType                string `json:"@odata.type"`
}

// ComplianceState Compliance state.
type ComplianceState string

// List of microsoft.graph.complianceState
const (
	COMPLIANCESTATE_UNKNOWN         ComplianceState = "unknown"
	COMPLIANCESTATE_COMPLIANT       ComplianceState = "compliant"
	COMPLIANCESTATE_NONCOMPLIANT    ComplianceState = "noncompliant"
	COMPLIANCESTATE_CONFLICT        ComplianceState = "conflict"
	COMPLIANCESTATE_ERROR           ComplianceState = "error"
	COMPLIANCESTATE_IN_GRACE_PERIOD ComplianceState = "inGracePeriod"
	COMPLIANCESTATE_CONFIG_MANAGER  ComplianceState = "configManager"
)

// All allowed values of ComplianceState enum
var AllowedComplianceStateEnumValues = []ComplianceState{
	"unknown",
	"compliant",
	"noncompliant",
	"conflict",
	"error",
	"inGracePeriod",
	"configManager",
}

func (v *ComplianceState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := ComplianceState(value)
	for _, existing := range AllowedComplianceStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid ComplianceState", value)
}

// DetectedAppPlatformType Indicates the operating system / platform of the discovered application.  Some possible values are Windows, iOS, macOS. The default value is unknown (0).
type DetectedAppPlatformType string

// List of microsoft.graph.detectedAppPlatformType
const (
	DETECTEDAPPPLATFORMTYPE_UNKNOWN                             DetectedAppPlatformType = "unknown"
	DETECTEDAPPPLATFORMTYPE_WINDOWS                             DetectedAppPlatformType = "windows"
	DETECTEDAPPPLATFORMTYPE_WINDOWS_MOBILE                      DetectedAppPlatformType = "windowsMobile"
	DETECTEDAPPPLATFORMTYPE_WINDOWS_HOLOGRAPHIC                 DetectedAppPlatformType = "windowsHolographic"
	DETECTEDAPPPLATFORMTYPE_IOS                                 DetectedAppPlatformType = "ios"
	DETECTEDAPPPLATFORMTYPE_MAC_OS                              DetectedAppPlatformType = "macOS"
	DETECTEDAPPPLATFORMTYPE_CHROME_OS                           DetectedAppPlatformType = "chromeOS"
	DETECTEDAPPPLATFORMTYPE_ANDROID_OSP                         DetectedAppPlatformType = "androidOSP"
	DETECTEDAPPPLATFORMTYPE_ANDROID_DEVICE_ADMINISTRATOR        DetectedAppPlatformType = "androidDeviceAdministrator"
	DETECTEDAPPPLATFORMTYPE_ANDROID_WORK_PROFILE                DetectedAppPlatformType = "androidWorkProfile"
	DETECTEDAPPPLATFORMTYPE_ANDROID_DEDICATED_AND_FULLY_MANAGED DetectedAppPlatformType = "androidDedicatedAndFullyManaged"
	DETECTEDAPPPLATFORMTYPE_UNKNOWN_FUTURE_VALUE                DetectedAppPlatformType = "unknownFutureValue"
)

// All allowed values of DetectedAppPlatformType enum
var AllowedDetectedAppPlatformTypeEnumValues = []DetectedAppPlatformType{
	"unknown",
	"windows",
	"windowsMobile",
	"windowsHolographic",
	"ios",
	"macOS",
	"chromeOS",
	"androidOSP",
	"androidDeviceAdministrator",
	"androidWorkProfile",
	"androidDedicatedAndFullyManaged",
	"unknownFutureValue",
}

func (v *DetectedAppPlatformType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DetectedAppPlatformType(value)
	for _, existing := range AllowedDetectedAppPlatformTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DetectedAppPlatformType", value)
}

// OnPremisesConditionalAccessSettings struct for OnPremisesConditionalAccessSettings
type OnPremisesConditionalAccessSettings struct {
	Entity
	// Indicates if on premises conditional access is enabled for this organization
	Enabled *bool `json:"enabled,omitempty"`
	// User groups that will be exempt by on premises conditional access. All users in these groups will be exempt from the conditional access policy.
	ExcludedGroups []string `json:"excludedGroups,omitempty"`
	// User groups that will be targeted by on premises conditional access. All users in these groups will be required to have mobile device managed and compliant for mail access.
	IncludedGroups []string `json:"includedGroups,omitempty"`
	// Override the default access rule when allowing a device to ensure access is granted.
	OverrideDefaultRule *bool  `json:"overrideDefaultRule,omitempty"`
	OdataType           string `json:"@odata.type"`
}

// ComplianceManagementPartner struct for ComplianceManagementPartner
type ComplianceManagementPartner struct {
	Entity
	// User groups which enroll Android devices through partner.
	AndroidEnrollmentAssignments []ComplianceManagementPartnerAssignment `json:"androidEnrollmentAssignments,omitempty"`
	// Partner onboarded for Android devices.
	AndroidOnboarded *bool `json:"androidOnboarded,omitempty"`
	// Partner display name
	DisplayName *string `json:"displayName,omitempty"`
	// User groups which enroll ios devices through partner.
	IosEnrollmentAssignments []ComplianceManagementPartnerAssignment `json:"iosEnrollmentAssignments,omitempty"`
	// Partner onboarded for ios devices.
	IosOnboarded *bool `json:"iosOnboarded,omitempty"`
	// Timestamp of last heartbeat after admin onboarded to the compliance management partner
	LastHeartbeatDateTime *time.Time `json:"lastHeartbeatDateTime,omitempty"`
	// User groups which enroll Mac devices through partner.
	MacOsEnrollmentAssignments []ComplianceManagementPartnerAssignment `json:"macOsEnrollmentAssignments,omitempty"`
	// Partner onboarded for Mac devices.
	MacOsOnboarded *bool                               `json:"macOsOnboarded,omitempty"`
	PartnerState   *DeviceManagementPartnerTenantState `json:"partnerState,omitempty"`
	OdataType      string                              `json:"@odata.type"`
}

// DeviceManagementPartnerTenantState Partner state of this tenant.
type DeviceManagementPartnerTenantState string

// List of microsoft.graph.deviceManagementPartnerTenantState
const (
	DEVICEMANAGEMENTPARTNERTENANTSTATE_UNKNOWN      DeviceManagementPartnerTenantState = "unknown"
	DEVICEMANAGEMENTPARTNERTENANTSTATE_UNAVAILABLE  DeviceManagementPartnerTenantState = "unavailable"
	DEVICEMANAGEMENTPARTNERTENANTSTATE_ENABLED      DeviceManagementPartnerTenantState = "enabled"
	DEVICEMANAGEMENTPARTNERTENANTSTATE_TERMINATED   DeviceManagementPartnerTenantState = "terminated"
	DEVICEMANAGEMENTPARTNERTENANTSTATE_REJECTED     DeviceManagementPartnerTenantState = "rejected"
	DEVICEMANAGEMENTPARTNERTENANTSTATE_UNRESPONSIVE DeviceManagementPartnerTenantState = "unresponsive"
)

// All allowed values of DeviceManagementPartnerTenantState enum
var AllowedDeviceManagementPartnerTenantStateEnumValues = []DeviceManagementPartnerTenantState{
	"unknown",
	"unavailable",
	"enabled",
	"terminated",
	"rejected",
	"unresponsive",
}

func (v *DeviceManagementPartnerTenantState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementPartnerTenantState(value)
	for _, existing := range AllowedDeviceManagementPartnerTenantStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementPartnerTenantState", value)
}

// ComplianceManagementPartnerAssignment User group targeting for Compliance Management Partner
type ComplianceManagementPartnerAssignment struct {
	Target    *DeviceAndAppManagementAssignmentTarget `json:"target,omitempty"`
	OdataType string                                  `json:"@odata.type"`
}

// AuditEvent struct for AuditEvent
type AuditEvent struct {
	Entity
	// Friendly name of the activity.
	Activity *string `json:"activity,omitempty"`
	// The date time in UTC when the activity was performed.
	ActivityDateTime *time.Time `json:"activityDateTime,omitempty"`
	// The HTTP operation type of the activity.
	ActivityOperationType *string `json:"activityOperationType,omitempty"`
	// The result of the activity.
	ActivityResult *string `json:"activityResult,omitempty"`
	// The type of activity that was being performed.
	ActivityType *string     `json:"activityType,omitempty"`
	Actor        *AuditActor `json:"actor,omitempty"`
	// Audit category.
	Category *string `json:"category,omitempty"`
	// Component name.
	ComponentName *string `json:"componentName,omitempty"`
	// The client request Id that is used to correlate activity within the system.
	CorrelationId *string `json:"correlationId,omitempty"`
	// Event display name.
	DisplayName *string `json:"displayName,omitempty"`
	// Resources being modified.
	Resources []AuditResource `json:"resources,omitempty"`
	OdataType string          `json:"@odata.type"`
}

// AuditResource A class containing the properties for Audit Resource.
type AuditResource struct {
	// Audit resource's type.
	AuditResourceType *string `json:"auditResourceType,omitempty"`
	// Display name.
	DisplayName *string `json:"displayName,omitempty"`
	// List of modified properties.
	ModifiedProperties []AuditProperty `json:"modifiedProperties,omitempty"`
	// Audit resource's Id.
	ResourceId *string `json:"resourceId,omitempty"`
	OdataType  string  `json:"@odata.type"`
}

// AuditProperty A class containing the properties for Audit Property.
type AuditProperty struct {
	// Display name.
	DisplayName *string `json:"displayName,omitempty"`
	// New value.
	NewValue *string `json:"newValue,omitempty"`
	// Old value.
	OldValue  *string `json:"oldValue,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// AuditActor A class containing the properties for Audit Actor.
type AuditActor struct {
	// Name of the Application.
	ApplicationDisplayName *string `json:"applicationDisplayName,omitempty"`
	// AAD Application Id.
	ApplicationId *string `json:"applicationId,omitempty"`
	// Actor Type.
	AuditActorType *string `json:"auditActorType,omitempty"`
	// IPAddress.
	IpAddress *string `json:"ipAddress,omitempty"`
	// Service Principal Name (SPN).
	ServicePrincipalName *string `json:"servicePrincipalName,omitempty"`
	// User Id.
	UserId *string `json:"userId,omitempty"`
	// List of user permissions when the audit was performed.
	UserPermissions []*string `json:"userPermissions,omitempty"`
	// User Principal Name (UPN).
	UserPrincipalName *string `json:"userPrincipalName,omitempty"`
	OdataType         string  `json:"@odata.type"`
}

// DeviceManagementApplePushNotificationCertificate struct for ApplePushNotificationCertificate
type DeviceManagementApplePushNotificationCertificate struct {
	Entity
	// Apple Id of the account used to create the MDM push certificate.
	AppleIdentifier *string `json:"appleIdentifier,omitempty"`
	// Not yet documented
	Certificate *string `json:"certificate,omitempty"`
	// Certificate serial number. This property is read-only.
	CertificateSerialNumber *string `json:"certificateSerialNumber,omitempty"`
	// The reason the certificate upload failed.
	CertificateUploadFailureReason *string `json:"certificateUploadFailureReason,omitempty"`
	// The certificate upload status.
	CertificateUploadStatus *string `json:"certificateUploadStatus,omitempty"`
	// The expiration date and time for Apple push notification certificate.
	ExpirationDateTime *time.Time `json:"expirationDateTime,omitempty"`
	// Last modified date and time for Apple push notification certificate.
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime,omitempty"`
	// Topic Id.
	TopicIdentifier *string `json:"topicIdentifier,omitempty"`
	OdataType       string  `json:"@odata.type"`
}

// DeviceManagementSubscriptionState Tenant mobile device management subscription state.
type DeviceManagementSubscriptionState string

// List of microsoft.graph.deviceManagementSubscriptionState
const (
	DEVICEMANAGEMENTSUBSCRIPTIONSTATE_PENDING    DeviceManagementSubscriptionState = "pending"
	DEVICEMANAGEMENTSUBSCRIPTIONSTATE_ACTIVE     DeviceManagementSubscriptionState = "active"
	DEVICEMANAGEMENTSUBSCRIPTIONSTATE_WARNING    DeviceManagementSubscriptionState = "warning"
	DEVICEMANAGEMENTSUBSCRIPTIONSTATE_DISABLED   DeviceManagementSubscriptionState = "disabled"
	DEVICEMANAGEMENTSUBSCRIPTIONSTATE_DELETED    DeviceManagementSubscriptionState = "deleted"
	DEVICEMANAGEMENTSUBSCRIPTIONSTATE_BLOCKED    DeviceManagementSubscriptionState = "blocked"
	DEVICEMANAGEMENTSUBSCRIPTIONSTATE_LOCKED_OUT DeviceManagementSubscriptionState = "lockedOut"
)

// All allowed values of DeviceManagementSubscriptionState enum
var AllowedDeviceManagementSubscriptionStateEnumValues = []DeviceManagementSubscriptionState{
	"pending",
	"active",
	"warning",
	"disabled",
	"deleted",
	"blocked",
	"lockedOut",
}

func (v *DeviceManagementSubscriptionState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := DeviceManagementSubscriptionState(value)
	for _, existing := range AllowedDeviceManagementSubscriptionStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid DeviceManagementSubscriptionState", value)
}

// UserExperienceAnalyticsSettings The user experience analytics insight is the recomendation to improve the user experience analytics score.
type DeviceManagementUserExperienceAnalyticsSettings struct {
	// When TRUE, indicates Tenant attach is configured properly and System Center Configuration Manager (SCCM) tenant attached devices will show up in endpoint analytics reporting. When FALSE, indicates Tenant attach is not configured. FALSE by default.
	ConfigurationManagerDataConnectorConfigured *bool  `json:"configurationManagerDataConnectorConfigured,omitempty"`
	OdataType                                   string `json:"@odata.type"`
}

// DeviceManagementWindowsMalwareOverview Windows device malware overview.
type DeviceManagementWindowsMalwareOverview struct {
	// List of device counts per malware category
	MalwareCategorySummary []WindowsMalwareCategoryCount `json:"malwareCategorySummary,omitempty"`
	// Count of devices with malware detected in the last 30 days
	MalwareDetectedDeviceCount *int32 `json:"malwareDetectedDeviceCount,omitempty"`
	// List of device counts per malware execution state
	MalwareExecutionStateSummary []WindowsMalwareExecutionStateCount `json:"malwareExecutionStateSummary,omitempty"`
	// List of device counts per malware
	MalwareNameSummary []WindowsMalwareNameCount `json:"malwareNameSummary,omitempty"`
	// List of active malware counts per malware severity
	MalwareSeveritySummary []WindowsMalwareSeverityCount `json:"malwareSeveritySummary,omitempty"`
	// List of device counts per malware state
	MalwareStateSummary []WindowsMalwareStateCount `json:"malwareStateSummary,omitempty"`
	// List of device counts with malware per windows OS version
	OsVersionsSummary []OsVersionCount `json:"osVersionsSummary,omitempty"`
	// Count of all distinct malwares detected across all devices. Valid values -2147483648 to 2147483647
	TotalDistinctMalwareCount *int32 `json:"totalDistinctMalwareCount,omitempty"`
	// Count of all malware detections across all devices. Valid values -2147483648 to 2147483647
	TotalMalwareCount *int32 `json:"totalMalwareCount,omitempty"`
	OdataType         string `json:"@odata.type"`
}

// OsVersionCount Count of devices with malware for each OS version
type OsVersionCount struct {
	// Count of devices with malware for the OS version
	DeviceCount *int32 `json:"deviceCount,omitempty"`
	// The Timestamp of the last update for the device count in UTC
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	// OS version
	OsVersion *string `json:"osVersion,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// WindowsMalwareStateCount Windows Malware State Summary.
type WindowsMalwareStateCount struct {
	// Count of devices with malware detections for this malware State
	DeviceCount *int32 `json:"deviceCount,omitempty"`
	// Count of distinct malwares for this malware State. Valid values -2147483648 to 2147483647
	DistinctMalwareCount *int32 `json:"distinctMalwareCount,omitempty"`
	// The Timestamp of the last update for the device count in UTC
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	// Count of total malware detections for this malware State. Valid values -2147483648 to 2147483647
	MalwareDetectionCount *int32                     `json:"malwareDetectionCount,omitempty"`
	State                 *WindowsMalwareThreatState `json:"state,omitempty"`
	OdataType             string                     `json:"@odata.type"`
}

// WindowsMalwareThreatState Malware threat status
type WindowsMalwareThreatState string

// List of microsoft.graph.windowsMalwareThreatState
const (
	WINDOWSMALWARETHREATSTATE_ACTIVE                                WindowsMalwareThreatState = "active"
	WINDOWSMALWARETHREATSTATE_ACTION_FAILED                         WindowsMalwareThreatState = "actionFailed"
	WINDOWSMALWARETHREATSTATE_MANUAL_STEPS_REQUIRED                 WindowsMalwareThreatState = "manualStepsRequired"
	WINDOWSMALWARETHREATSTATE_FULL_SCAN_REQUIRED                    WindowsMalwareThreatState = "fullScanRequired"
	WINDOWSMALWARETHREATSTATE_REBOOT_REQUIRED                       WindowsMalwareThreatState = "rebootRequired"
	WINDOWSMALWARETHREATSTATE_REMEDIATED_WITH_NON_CRITICAL_FAILURES WindowsMalwareThreatState = "remediatedWithNonCriticalFailures"
	WINDOWSMALWARETHREATSTATE_QUARANTINED                           WindowsMalwareThreatState = "quarantined"
	WINDOWSMALWARETHREATSTATE_REMOVED                               WindowsMalwareThreatState = "removed"
	WINDOWSMALWARETHREATSTATE_CLEANED                               WindowsMalwareThreatState = "cleaned"
	WINDOWSMALWARETHREATSTATE_ALLOWED                               WindowsMalwareThreatState = "allowed"
	WINDOWSMALWARETHREATSTATE_NO_STATUS_CLEARED                     WindowsMalwareThreatState = "noStatusCleared"
)

// All allowed values of WindowsMalwareThreatState enum
var AllowedWindowsMalwareThreatStateEnumValues = []WindowsMalwareThreatState{
	"active",
	"actionFailed",
	"manualStepsRequired",
	"fullScanRequired",
	"rebootRequired",
	"remediatedWithNonCriticalFailures",
	"quarantined",
	"removed",
	"cleaned",
	"allowed",
	"noStatusCleared",
}

func (v *WindowsMalwareThreatState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := WindowsMalwareThreatState(value)
	for _, existing := range AllowedWindowsMalwareThreatStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid WindowsMalwareThreatState", value)
}

// WindowsMalwareSeverityCount Windows Malware Severity Count Summary
type WindowsMalwareSeverityCount struct {
	// Count of distinct malwares for this malware State. Valid values -2147483648 to 2147483647
	DistinctMalwareCount *int32 `json:"distinctMalwareCount,omitempty"`
	// The Timestamp of the last update for the WindowsMalwareSeverityCount in UTC
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	// Count of threats detections for this malware severity. Valid values -2147483648 to 2147483647
	MalwareDetectionCount *int32                  `json:"malwareDetectionCount,omitempty"`
	Severity              *WindowsMalwareSeverity `json:"severity,omitempty"`
	OdataType             string                  `json:"@odata.type"`
}

// WindowsMalwareNameCount Malware name device count
type WindowsMalwareNameCount struct {
	// Count of devices with malware dectected for this malware
	DeviceCount *int32 `json:"deviceCount,omitempty"`
	// The Timestamp of the last update for the device count in UTC
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	// The unique identifier. This is malware identifier
	MalwareIdentifier *string `json:"malwareIdentifier,omitempty"`
	// Malware name
	Name      *string `json:"name,omitempty"`
	OdataType string  `json:"@odata.type"`
}

// WindowsMalwareCategoryCount Malware category device count
type WindowsMalwareCategoryCount struct {
	// Count of active malware detections for this malware category. Valid values -2147483648 to 2147483647
	ActiveMalwareDetectionCount *int32                  `json:"activeMalwareDetectionCount,omitempty"`
	Category                    *WindowsMalwareCategory `json:"category,omitempty"`
	// Count of devices with malware detections for this malware category
	DeviceCount *int32 `json:"deviceCount,omitempty"`
	// Count of distinct active malwares for this malware category. Valid values -2147483648 to 2147483647
	DistinctActiveMalwareCount *int32 `json:"distinctActiveMalwareCount,omitempty"`
	// The Timestamp of the last update for the device count in UTC
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	OdataType          string     `json:"@odata.type"`
}

// WindowsMalwareCategory Malware category id
type WindowsMalwareCategory string

// List of microsoft.graph.windowsMalwareCategory
const (
	WINDOWSMALWARECATEGORY_INVALID                      WindowsMalwareCategory = "invalid"
	WINDOWSMALWARECATEGORY_ADWARE                       WindowsMalwareCategory = "adware"
	WINDOWSMALWARECATEGORY_SPYWARE                      WindowsMalwareCategory = "spyware"
	WINDOWSMALWARECATEGORY_PASSWORD_STEALER             WindowsMalwareCategory = "passwordStealer"
	WINDOWSMALWARECATEGORY_TROJAN_DOWNLOADER            WindowsMalwareCategory = "trojanDownloader"
	WINDOWSMALWARECATEGORY_WORM                         WindowsMalwareCategory = "worm"
	WINDOWSMALWARECATEGORY_BACKDOOR                     WindowsMalwareCategory = "backdoor"
	WINDOWSMALWARECATEGORY_REMOTE_ACCESS_TROJAN         WindowsMalwareCategory = "remoteAccessTrojan"
	WINDOWSMALWARECATEGORY_TROJAN                       WindowsMalwareCategory = "trojan"
	WINDOWSMALWARECATEGORY_EMAIL_FLOODER                WindowsMalwareCategory = "emailFlooder"
	WINDOWSMALWARECATEGORY_KEYLOGGER                    WindowsMalwareCategory = "keylogger"
	WINDOWSMALWARECATEGORY_DIALER                       WindowsMalwareCategory = "dialer"
	WINDOWSMALWARECATEGORY_MONITORING_SOFTWARE          WindowsMalwareCategory = "monitoringSoftware"
	WINDOWSMALWARECATEGORY_BROWSER_MODIFIER             WindowsMalwareCategory = "browserModifier"
	WINDOWSMALWARECATEGORY_COOKIE                       WindowsMalwareCategory = "cookie"
	WINDOWSMALWARECATEGORY_BROWSER_PLUGIN               WindowsMalwareCategory = "browserPlugin"
	WINDOWSMALWARECATEGORY_AOL_EXPLOIT                  WindowsMalwareCategory = "aolExploit"
	WINDOWSMALWARECATEGORY_NUKER                        WindowsMalwareCategory = "nuker"
	WINDOWSMALWARECATEGORY_SECURITY_DISABLER            WindowsMalwareCategory = "securityDisabler"
	WINDOWSMALWARECATEGORY_JOKE_PROGRAM                 WindowsMalwareCategory = "jokeProgram"
	WINDOWSMALWARECATEGORY_HOSTILE_ACTIVE_X_CONTROL     WindowsMalwareCategory = "hostileActiveXControl"
	WINDOWSMALWARECATEGORY_SOFTWARE_BUNDLER             WindowsMalwareCategory = "softwareBundler"
	WINDOWSMALWARECATEGORY_STEALTH_NOTIFIER             WindowsMalwareCategory = "stealthNotifier"
	WINDOWSMALWARECATEGORY_SETTINGS_MODIFIER            WindowsMalwareCategory = "settingsModifier"
	WINDOWSMALWARECATEGORY_TOOL_BAR                     WindowsMalwareCategory = "toolBar"
	WINDOWSMALWARECATEGORY_REMOTE_CONTROL_SOFTWARE      WindowsMalwareCategory = "remoteControlSoftware"
	WINDOWSMALWARECATEGORY_TROJAN_FTP                   WindowsMalwareCategory = "trojanFtp"
	WINDOWSMALWARECATEGORY_POTENTIAL_UNWANTED_SOFTWARE  WindowsMalwareCategory = "potentialUnwantedSoftware"
	WINDOWSMALWARECATEGORY_ICQ_EXPLOIT                  WindowsMalwareCategory = "icqExploit"
	WINDOWSMALWARECATEGORY_TROJAN_TELNET                WindowsMalwareCategory = "trojanTelnet"
	WINDOWSMALWARECATEGORY_EXPLOIT                      WindowsMalwareCategory = "exploit"
	WINDOWSMALWARECATEGORY_FILESHARING_PROGRAM          WindowsMalwareCategory = "filesharingProgram"
	WINDOWSMALWARECATEGORY_MALWARE_CREATION_TOOL        WindowsMalwareCategory = "malwareCreationTool"
	WINDOWSMALWARECATEGORY_REMOTE_CONTROL_SOFTWARE2     WindowsMalwareCategory = "remote_Control_Software"
	WINDOWSMALWARECATEGORY_TOOL                         WindowsMalwareCategory = "tool"
	WINDOWSMALWARECATEGORY_TROJAN_DENIAL_OF_SERVICE     WindowsMalwareCategory = "trojanDenialOfService"
	WINDOWSMALWARECATEGORY_TROJAN_DROPPER               WindowsMalwareCategory = "trojanDropper"
	WINDOWSMALWARECATEGORY_TROJAN_MASS_MAILER           WindowsMalwareCategory = "trojanMassMailer"
	WINDOWSMALWARECATEGORY_TROJAN_MONITORING_SOFTWARE   WindowsMalwareCategory = "trojanMonitoringSoftware"
	WINDOWSMALWARECATEGORY_TROJAN_PROXY_SERVER          WindowsMalwareCategory = "trojanProxyServer"
	WINDOWSMALWARECATEGORY_VIRUS                        WindowsMalwareCategory = "virus"
	WINDOWSMALWARECATEGORY_KNOWN                        WindowsMalwareCategory = "known"
	WINDOWSMALWARECATEGORY_UNKNOWN                      WindowsMalwareCategory = "unknown"
	WINDOWSMALWARECATEGORY_SPP                          WindowsMalwareCategory = "spp"
	WINDOWSMALWARECATEGORY_BEHAVIOR                     WindowsMalwareCategory = "behavior"
	WINDOWSMALWARECATEGORY_VULNERABILITY                WindowsMalwareCategory = "vulnerability"
	WINDOWSMALWARECATEGORY_POLICY                       WindowsMalwareCategory = "policy"
	WINDOWSMALWARECATEGORY_ENTERPRISE_UNWANTED_SOFTWARE WindowsMalwareCategory = "enterpriseUnwantedSoftware"
	WINDOWSMALWARECATEGORY_RANSOM                       WindowsMalwareCategory = "ransom"
	WINDOWSMALWARECATEGORY_HIPS_RULE                    WindowsMalwareCategory = "hipsRule"
)

// All allowed values of WindowsMalwareCategory enum
var AllowedWindowsMalwareCategoryEnumValues = []WindowsMalwareCategory{
	"invalid",
	"adware",
	"spyware",
	"passwordStealer",
	"trojanDownloader",
	"worm",
	"backdoor",
	"remoteAccessTrojan",
	"trojan",
	"emailFlooder",
	"keylogger",
	"dialer",
	"monitoringSoftware",
	"browserModifier",
	"cookie",
	"browserPlugin",
	"aolExploit",
	"nuker",
	"securityDisabler",
	"jokeProgram",
	"hostileActiveXControl",
	"softwareBundler",
	"stealthNotifier",
	"settingsModifier",
	"toolBar",
	"remoteControlSoftware",
	"trojanFtp",
	"potentialUnwantedSoftware",
	"icqExploit",
	"trojanTelnet",
	"exploit",
	"filesharingProgram",
	"malwareCreationTool",
	"remote_Control_Software",
	"tool",
	"trojanDenialOfService",
	"trojanDropper",
	"trojanMassMailer",
	"trojanMonitoringSoftware",
	"trojanProxyServer",
	"virus",
	"known",
	"unknown",
	"spp",
	"behavior",
	"vulnerability",
	"policy",
	"enterpriseUnwantedSoftware",
	"ransom",
	"hipsRule",
}

func (v *WindowsMalwareCategory) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := WindowsMalwareCategory(value)
	for _, existing := range AllowedWindowsMalwareCategoryEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid WindowsMalwareCategory", value)
}

// WindowsMalwareExecutionStateCount Windows malware execution state summary.
type WindowsMalwareExecutionStateCount struct {
	// Count of devices with malware detections for this malware execution state
	DeviceCount    *int32                        `json:"deviceCount,omitempty"`
	ExecutionState *WindowsMalwareExecutionState `json:"executionState,omitempty"`
	// The Timestamp of the last update for the device count in UTC
	LastUpdateDateTime *time.Time `json:"lastUpdateDateTime,omitempty"`
	OdataType          string     `json:"@odata.type"`
}

// WindowsMalwareExecutionState Malware execution status
type WindowsMalwareExecutionState string

// List of microsoft.graph.windowsMalwareExecutionState
const (
	WINDOWSMALWAREEXECUTIONSTATE_UNKNOWN     WindowsMalwareExecutionState = "unknown"
	WINDOWSMALWAREEXECUTIONSTATE_BLOCKED     WindowsMalwareExecutionState = "blocked"
	WINDOWSMALWAREEXECUTIONSTATE_ALLOWED     WindowsMalwareExecutionState = "allowed"
	WINDOWSMALWAREEXECUTIONSTATE_RUNNING     WindowsMalwareExecutionState = "running"
	WINDOWSMALWAREEXECUTIONSTATE_NOT_RUNNING WindowsMalwareExecutionState = "notRunning"
)

// All allowed values of WindowsMalwareExecutionState enum
var AllowedWindowsMalwareExecutionStateEnumValues = []WindowsMalwareExecutionState{
	"unknown",
	"blocked",
	"allowed",
	"running",
	"notRunning",
}

func (v *WindowsMalwareExecutionState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := WindowsMalwareExecutionState(value)
	for _, existing := range AllowedWindowsMalwareExecutionStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid WindowsMalwareExecutionState", value)
}
