package zabbix

import (
	"errors"
	"fmt"
)

const (
	// HostSourceDefault indicates that a Host was created in the normal way.
	HostSourceDefault = 0

	// HostSourceDiscovery indicates that a Host was created by Host discovery.
	HostSourceDiscovery = 4

	// HostAvailabilityUnknown Unknown availability of host, never has come online
	HostAvailabilityUnknown = 0

	// HostAvailabilityAvailable Host is available
	HostAvailabilityAvailable = 1

	// HostAvailabilityUnavailable Host is NOT available
	HostAvailabilityUnavailable = 2

	// HostInventoryModeDisabled Host inventory in disabled
	HostInventoryModeDisabled = -1

	// HostInventoryModeManual Host inventory is managed manually
	HostInventoryModeManual = 0

	// HostInventoryModeAutomatic Host inventory is managed automatically
	HostInventoryModeAutomatic = 1

	// HostTLSConnectUnencryped connect unencrypted to or from host
	HostTLSConnectUnencryped = 1

	// HostTLSConnectPSK connect with PSK to or from host
	HostTLSConnectPSK = 2

	// HostTLSConnectCertificate connect with certificate to or from host
	HostTLSConnectCertificate = 4

	// HostStatusMonitored Host is monitored
	HostStatusMonitored = 0

	// HostStatusUnmonitored Host is not monitored
	HostStatusUnmonitored = 1
)

// Host represents a Zabbix Host returned from the Zabbix API.
//
// See: https://www.zabbix.com/documentation/2.2/manual/config/hosts
type Host struct {
	// HostID is the unique ID of the Host.
	HostID string

	// Hostname is the technical name of the Host.
	Hostname string

	// DisplayName is the visible name of the Host.
	DisplayName string

	// Source is the origin of the Host and must be one of the HostSource
	// constants.
	Source int

	// Macros contains all Host Macros assigned to the Host.
	Macros []HostMacro

	// Groups contains all Host Groups assigned to the Host.
	Groups []Hostgroup

	// Status of the host
	Status int

	// Availbility of host
	Available int

	// Description of host
	Description string

	// Inventory mode
	InventoryMode int

	// HostID of the proxy managing this host
	ProxyHostID int

	// How should we connect to host
	TLSConnect int

	// What type of connections we accept from host
	TLSAccept int

	TLSIssuer      string
	TLSSubject     string
	TLSPSKIdentity string
	TLSPSK         string
}

// HostGetParams represent the parameters for a `host.get` API call.
//
// See: https://www.zabbix.com/documentation/2.2/manual/api/reference/host/get#parameters
type HostGetParams struct {
	GetParameters

	// GroupIDs filters search results to hosts that are members of the given
	// Group IDs.
	GroupIDs []string `json:"groupids,omitempty"`

	// ApplicationIDs filters search results to hosts that have items in the
	// given Application IDs.
	ApplicationIDs []string `json:"applicationids,omitempty"`

	// DiscoveredServiceIDs filters search results to hosts that are related to
	// the given discovered service IDs.
	DiscoveredServiceIDs []string `json:"dserviceids,omitempty"`

	// GraphIDs filters search results to hosts that have the given graph IDs.
	GraphIDs []string `json:"graphids,omitempty"`

	// HostIDs filters search results to hosts that matched the given Host IDs.
	HostIDs []string `json:"hostids,omitempty"`

	// WebCheckIDs filters search results to hosts with the given Web Check IDs.
	WebCheckIDs []string `json:"httptestids,omitempty"`

	// InterfaceIDs filters search results to hosts that use the given Interface
	// IDs.
	InterfaceIDs []string `json:"interfaceids,omitempty"`

	// ItemIDs filters search results to hosts with the given Item IDs.
	ItemIDs []string `json:"itemids,omitempty"`

	// MaintenanceIDs filters search results to hosts that are affected by the
	// given Maintenance IDs
	MaintenanceIDs []string `json:"maintenanceids,omitempty"`

	// MonitoredOnly filters search results to return only monitored hosts.
	MonitoredOnly bool `json:"monitored_hosts,omitempty"`

	// ProxyOnly filters search results to hosts which are Zabbix proxies.
	ProxiesOnly bool `json:"proxy_host,omitempty"`

	// ProxyIDs filters search results to hosts monitored by the given Proxy
	// IDs.
	ProxyIDs []string `json:"proxyids,omitempty"`

	// IncludeTemplates extends search results to include Templates.
	IncludeTemplates bool `json:"templated_hosts,omitempty"`

	// SelectGroups causes the Host Groups that each Host belongs to to be
	// attached in the search results.
	SelectGroups SelectQuery `json:"selectGroups,omitempty"`

	// SelectApplications causes the Applications from each Host to be attached
	// in the search results.
	SelectApplications SelectQuery `json:"selectApplications,omitempty"`

	// SelectDiscoveries causes the Low-Level Discoveries from each Host to be
	// attached in the search results.
	SelectDiscoveries SelectQuery `json:"selectDiscoveries,omitempty"`

	// SelectDiscoveryRule causes the Low-Level Discovery Rule that created each
	// Host to be attached in the search results.
	SelectDiscoveryRule SelectQuery `json:"selectDiscoveryRule,omitempty"`

	// SelectGraphs causes the Graphs from each Host to be attached in the
	// search results.
	SelectGraphs SelectQuery `json:"selectGraphs,omitempty"`

	// SelectHostDiscovery causes the hostDiscovery property from each host
	// to be attached in the search results
	SelectHostDiscovery SelectQuery `json:"selectHostDiscovery,omitempty"`

	// SelectWebScenarios causes the web scenarios from each host to be attached
	// in the search results
	SelectWebScenarios SelectQuery `json:"selectHttpTests,omitempty"`

	// SelectInterfaces causes the interfaces from each host to be attached in the
	// search results
	SelectInterfaces SelectQuery `json:"selectInterfaces,omitempty"`

	// SelectInventory causes the	inventory from each host to be attached in the
	// search results
	SelectInventory SelectQuery `json:"selectInventory,omitempty"`

	// SelectItems causes the items from each host to be attached in the search
	// results
	SelectItems SelectQuery `json:"selectItems,omitempty"`

	// SelectMacros causes the macros from each host to be attached in the search
	// results
	SelectMacros SelectQuery `json:"selectMacros,omitempty"`

	// SelectParentTemplates causes the templates to which the host is linked to
	// be attached in the search results
	SelectParentTemplates SelectQuery `json:"selectParentTemplates,omitempty"`

	// SelectScreens causes the templates associated with each host to be attached
	// in the search results
	SelectScreens SelectQuery `json:"selectScreens,omitempty"`

	// SelectTriggers causes the triggers associated with each host to be attached
	// in the search results
	SelectTriggers SelectQuery `json:"selectTriggers,omitempty"`
}

// GetHosts queries the Zabbix API for Hosts matching the given search
// parameters.
//
// ErrEventNotFound is returned if the search result set is empty.
// An error is returned if a transport, parsing or API error occurs.
func (c *Session) GetHosts(params HostGetParams) ([]Host, error) {
	hosts := make([]jHost, 0)
	err := c.Get("host.get", params, &hosts)
	if err != nil {
		return nil, err
	}

	if len(hosts) == 0 {
		return nil, ErrNotFound
	}

	// map JSON Events to Go Events
	out := make([]Host, len(hosts))
	for i, jhost := range hosts {
		host, err := jhost.Host()
		if err != nil {
			return nil, fmt.Errorf("Error mapping Host %d in response: %v", i, err)
		}

		out[i] = *host
	}

	return out, nil
}

// Interface is a definition of the interface of a host
type Interface struct {
	// Type is the interface type, possible values are:
	//
	// 1 : agent
	// 2 : SNMP
	// 3 : IPMI
	// 4 : JMX
	Type int `json:"type"`

	// Main is whether the interface is used as default on
	// the host. Only one interface of some type can be set
	// as default. Possible values are:
	//
	// 0 : Not default
	// 1 : Default
	Main int `json:"main"`

	// UseIP is whether the connection should be made via IP.
	// Possible values are:
	//
	// 0 : Connect using host DNS name
	// 1 : Connect using host IP address for this interface
	UseIP int `json:"useip"`

	// IP is the IP address used by the interface
	// Can be empty if the connection is made via DNS
	IP string `json:"ip"`

	// DNS is the DNS name used by the interface
	// Can be empty if the connection is made via IP
	DNS string `json:"dns"`

	// Port is the port number used by the interface.
	// This can contain  user macros
	Port string `json:"port"`

	// Bulk chooses whether to use bulk SNMP requests.
	// Possible values are:
	//
	// 0 : don't use bulk requests
	// 1 : (default) use bulk requests
	Bulk int `json:"bulk"`
}

// Group is a definition of a group to attach to a host
type Group struct {
	// GroupID is the ID of the group to attach
	GroupID string `json:"groupid"`
}

// Template is a definition of a template to attach to a host
type Template struct {
	// TemplateID is the ID of the template to attach
	TemplateID string `json:"templateid"`
}

// MacroContainer is a definition of a macro to attach to a host
type MacroContainer struct {
	// Macro is the macro string to attach
	Macro string `json:"macro"`

	// Value is the effective value to attach
	Value string `json:"value"`
}

// Inventory is a definition of an inventory to attach to a host.
// Most fields left uncommented as they are self explanatory
type Inventory struct {
	Alias          string `json:"alias,omitempty"`
	AssetTag       string `json:"asset_tag,omitempty"`
	Chassis        string `json:"chassis,omitempty"`
	Contact        string `json:"contact,omitempty"`
	ContractNumber string `json:"contract_number,omitempty"`

	// DateHWDecomm is the hardware decommissioning date
	DateHWDecomm string `json:"date_hw_decomm,omitempty"`

	// DateHWExpiry is the hardware maintenance expiry date
	DateHWExpiry string `json:"date_hw_expiry,omitempty"`

	// DateHWInstall is the hardware installation date
	DateHWInstall string `json:"date_hw_install,omitempty"`

	// DateHWPurchase is the hardware purchase date
	DateHWPurchase string `json:"date_hw_purchase,omitempty"`

	DeploymentStatus string `json:"deployment_status,omitempty"`
	Hardware         string `json:"hardware,omitempty"`

	// HardwareFull is the full details of the hardware
	HardwareFull string `json:"hardware_full,omitempty"`

	HostNetmask  string `json:"host_netmask,omitempty"`
	HostNetworks string `json:"host_networks,omitempty"`
	HostRouter   string `json:"host_router,omitempty"`

	// HWArch is the hardware architecture
	HWArch string `json:"hw_arch,omitempty"`

	InstallerName string `json:"installer_name,omitempty"`
	Location      string `json:"location,omitempty"`
	LocationLat   string `json:"location_lat,omitempty"`
	LocationLon   string `json:"location_lon,omitempty"`
	MacAddressA   string `json:"macaddress_a,omitempty"`
	MacAddressB   string `json:"macaddress_b,omitempty"`
	Model         string `json:"model,omitempty"`
	Name          string `json:"name,omitempty"`
	Notes         string `json:"notes,omitempty"`

	// OOBIP is the out of band IP address
	OOBIP string `json:"oob_ip,omitempty"`

	// OOBNetmask is the out of band netmask
	OOBNetmask string `json:"oob_netmask,omitempty"`

	// OOBRouter is the out of band router
	OOBRouter string `json:"oob_router,omitempty"`

	// OS is the operating system
	OS string `json:"os,omitempty"`

	// OSFull is the full details of the operating system
	OSFull string `json:"os_full,omitempty"`

	// OSShort is the short operating system name
	OSShort string `json:"os_short,omitempty"`

	// Primary Point of Contact contact details
	POC1Cell   string `json:"poc_1_cell,omitempty"`
	POC1Email  string `json:"poc_1_email,omitempty"`
	POC1Name   string `json:"poc_1_name,omitempty"`
	POC1Notes  string `json:"poc_1_notes,omitempty"`
	POC1PhoneA string `json:"poc_1_phone_a,omitempty"`
	POC1PhoneB string `json:"poc_1_phone_b,omitempty"`

	// Primary Point of Contact screen name
	POC1Screen string `json:"poc_1_screen,omitempty"`

	// Secondary Point of Contact contact details
	POC2Cell   string `json:"poc_2_cell,omitempty"`
	POC2Email  string `json:"poc_2_email,omitempty"`
	POC2Name   string `json:"poc_2_name,omitempty"`
	POC2Notes  string `json:"poc_2_notes,omitempty"`
	POC2PhoneA string `json:"poc_2_phone_a,omitempty"`
	POC2PhoneB string `json:"poc_2_phone_b,omitempty"`

	// Secondary Point of Contact screen name
	POC2Screen string `json:"poc_2_screen,omitempty"`

	SerialNoA    string `json:"serialno_a,omitempty"`
	SerialNoB    string `json:"serialno_b,omitempty"`
	SiteAddressA string `json:"site_address_a,omitempty"`
	SiteAddressB string `json:"site_address_b,omitempty"`
	SiteAddressC string `json:"site_address_c,omitempty"`
	SiteCity     string `json:"site_city,omitempty"`
	SiteCountry  string `json:"site_country,omitempty"`
	SiteNotes    string `json:"site_notes,omitempty"`
	SiteRack     string `json:"site_rack,omitempty"`
	SiteState    string `json:"site_state,omitempty"`
	SiteZIP      string `json:"site_zip,omitempty"`
	Software     string `json:"software,omitempty"`
	SoftwareAppA string `json:"software_app_a,omitempty"`
	SoftwareAppB string `json:"software_app_b,omitempty"`
	SoftwareAppC string `json:"software_app_c,omitempty"`
	SoftwareAppD string `json:"software_app_d,omitempty"`
	SoftwareAppE string `json:"software_app_e,omitempty"`
	SoftwareFull string `json:"software_full,omitempty"`
	Tag          string `json:"tag,omitempty"`
	Type         string `json:"type,omitempty"`

	// Full type details
	TypeFull string `json:"type_full,omitempty"`

	URLA   string `json:"url_a,omitempty"`
	URLB   string `json:"url_b,omitempty"`
	URLC   string `json:"url_c,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

// HostCreateParams describe the host that you want to create
type HostCreateParams struct {
	// Host is the name of the host
	Host string `json:"host"`

	// Interfaces describes any interfaces to attach
	Interfaces []Interface `json:"interfaces"`

	// Groups describes any groups to attach
	Groups []Group `json:"groups"`

	// Templates describes any templates to attach
	Templates []Template `json:"templates"`

	// Macros describes any macros to attach
	Macros []MacroContainer `json:"macros"`

	// InventoryMode must be one of:
	//
	// -1 : "Disabled"
	// 0  : "Manual"
	// 1  : "Automatic"
	InventoryMode int `json:"inventory_mode"`

	// Inventory describes the extended inventory properties
	// to attach
	Inventory Inventory `json:"inventory"`
}

func validateHostParams(params HostCreateParams) bool {
	// InventoryMode validation
	validInventoryModes := []int{-1, 0, 1}
	for _, b := range validInventoryModes {
		if b == params.InventoryMode {
			return false
		}
	}

	return true
}

// HostCreate queries the Zabbix API for Hosts matching the given search
// parameters.
//
// An error is returned if a transport, parsing or API error occurs.
func (c *Session) HostCreate(host HostCreateParams) (string, error) {
	if isInvalid := validateHostParams(host); isInvalid == true {
		return "", errors.New("Invalid host parameters found")
	}

	hostID := ""
	err := c.Get("host.create", host, &hostID)
	if err != nil {
		return "", err
	}

	return hostID, nil
}
