package packet

import (
	"sync"

	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/dictionary"
)

// Global instance for attribute type lookups
var (
	defaultDict *dictionary.Dictionary
	dictOnce    sync.Once
)

// initDictionary initializes the default dictionary once
func initDictionary() {
	dictOnce.Do(func() {
		defaultDict = dictionaries.NewStandardDictionary()
	})
}

// getAttrType is a helper function to get attribute type from dictionary
func getAttrType(name string) uint8 {
	initDictionary()
	attrType, err := defaultDict.GetAttributeTypeByName(name)
	if err != nil {
		// Fallback to 0 if not found (this shouldn't happen with RFC dictionary)
		return 0
	}
	return attrType
}

// Dictionary-based attribute type variables
// These maintain backward compatibility while using dictionary lookups

// RFC 2865 attributes
var (
	AttrUserName               = getAttrType("User-Name")                // 1
	AttrUserPassword           = getAttrType("User-Password")            // 2
	AttrNASIPAddress           = getAttrType("NAS-IP-Address")           // 4
	AttrNASPort                = getAttrType("NAS-Port")                 // 5
	AttrServiceType            = getAttrType("Service-Type")             // 6
	AttrFramedProtocol         = getAttrType("Framed-Protocol")          // 7
	AttrFramedIPAddress        = getAttrType("Framed-IP-Address")        // 8
	AttrFramedIPNetmask        = getAttrType("Framed-IP-Netmask")        // 9
	AttrFramedRouting          = getAttrType("Framed-Routing")           // 10
	AttrFilterID               = getAttrType("Filter-Id")                // 11
	AttrFramedMTU              = getAttrType("Framed-MTU")               // 12
	AttrFramedCompression      = getAttrType("Framed-Compression")       // 13
	AttrLoginIPHost            = getAttrType("Login-IP-Host")            // 14
	AttrLoginService           = getAttrType("Login-Service")            // 15
	AttrLoginTCPPort           = getAttrType("Login-TCP-Port")           // 16
	AttrReplyMessage           = getAttrType("Reply-Message")            // 18
	AttrCallbackNumber         = getAttrType("Callback-Number")          // 19
	AttrCallbackID             = getAttrType("Callback-Id")              // 20
	AttrFramedRoute            = getAttrType("Framed-Route")             // 22
	AttrFramedIPXNetwork       = getAttrType("Framed-IPX-Network")       // 23
	AttrState                  = getAttrType("State")                    // 24
	AttrClass                  = getAttrType("Class")                    // 25
	AttrVendorSpecific         = getAttrType("Vendor-Specific")          // 26
	AttrSessionTimeout         = getAttrType("Session-Timeout")          // 27
	AttrIdleTimeout            = getAttrType("Idle-Timeout")             // 28
	AttrTerminationAction      = getAttrType("Termination-Action")       // 29
	AttrCalledStationID        = getAttrType("Called-Station-Id")        // 30
	AttrCallingStationID       = getAttrType("Calling-Station-Id")       // 31
	AttrNASIdentifier          = getAttrType("NAS-Identifier")           // 32
	AttrProxyState             = getAttrType("Proxy-State")              // 33
	AttrLoginLATService        = getAttrType("Login-LAT-Service")        // 34
	AttrLoginLATNode           = getAttrType("Login-LAT-Node")           // 35
	AttrLoginLATGroup          = getAttrType("Login-LAT-Group")          // 36
	AttrFramedAppleTalkLink    = getAttrType("Framed-AppleTalk-Link")    // 37
	AttrFramedAppleTalkNetwork = getAttrType("Framed-AppleTalk-Network") // 38
	AttrFramedAppleTalkZone    = getAttrType("Framed-AppleTalk-Zone")    // 39
)

// RFC 2866 accounting attributes
var (
	AttrAcctStatusType     = getAttrType("Acct-Status-Type")      // 40
	AttrAcctDelayTime      = getAttrType("Acct-Delay-Time")       // 41
	AttrAcctInputOctets    = getAttrType("Acct-Input-Octets")     // 42
	AttrAcctOutputOctets   = getAttrType("Acct-Output-Octets")    // 43
	AttrAcctSessionID      = getAttrType("Acct-Session-Id")       // 44
	AttrAcctAuthentic      = getAttrType("Acct-Authentic")        // 45
	AttrAcctSessionTime    = getAttrType("Acct-Session-Time")     // 46
	AttrAcctInputPackets   = getAttrType("Acct-Input-Packets")    // 47
	AttrAcctOutputPackets  = getAttrType("Acct-Output-Packets")   // 48
	AttrAcctTerminateCause = getAttrType("Acct-Terminate-Cause")  // 49
	AttrAcctMultiSessionID = getAttrType("Acct-Multi-Session-Id") // 50
	AttrAcctLinkCount      = getAttrType("Acct-Link-Count")       // 51
)

// RFC 2869 extension attributes
var (
	AttrCHAPChallenge        = getAttrType("CHAP-Challenge")         // 60
	AttrNASPortType          = getAttrType("NAS-Port-Type")          // 61
	AttrPortLimit            = getAttrType("Port-Limit")             // 62
	AttrLoginLATPort         = getAttrType("Login-LAT-Port")         // 63
	AttrTunnelType           = getAttrType("Tunnel-Type")            // 64
	AttrTunnelMediumType     = getAttrType("Tunnel-Medium-Type")     // 65
	AttrTunnelClientEndpoint = getAttrType("Tunnel-Client-Endpoint") // 66
	AttrTunnelServerEndpoint = getAttrType("Tunnel-Server-Endpoint") // 67
	AttrAcctTunnelConnection = getAttrType("Acct-Tunnel-Connection") // 68
	AttrTunnelPassword       = getAttrType("Tunnel-Password")        // 69
	AttrARAPPassword         = getAttrType("ARAP-Password")          // 70
	AttrARAPFeatures         = getAttrType("ARAP-Features")          // 71
	AttrARAPZoneAccess       = getAttrType("ARAP-Zone-Access")       // 72
	AttrARAPSecurity         = getAttrType("ARAP-Security")          // 73
	AttrARAPSecurityData     = getAttrType("ARAP-Security-Data")     // 74
	AttrPasswordRetry        = getAttrType("Password-Retry")         // 75
	AttrPrompt               = getAttrType("Prompt")                 // 76
	AttrConnectInfo          = getAttrType("Connect-Info")           // 77
	AttrConfigurationToken   = getAttrType("Configuration-Token")    // 78
	AttrEAPMessage           = getAttrType("EAP-Message")            // 79
	AttrMessageAuthenticator = getAttrType("Message-Authenticator")  // 80
)

// GetDefaultDictionary returns the default RFC 2865 dictionary
func GetDefaultDictionary() *dictionary.Dictionary {
	initDictionary()
	return defaultDict
}

// AttributeTypes provides dictionary-based attribute type lookups
type AttributeTypes struct {
	dict *dictionary.Dictionary
}

// NewAttributeTypes creates a new AttributeTypes instance with the given dictionary
func NewAttributeTypes(dict *dictionary.Dictionary) *AttributeTypes {
	return &AttributeTypes{dict: dict}
}

// GetType returns the attribute type for a given name
func (at *AttributeTypes) GetType(name string) (uint8, error) {
	return at.dict.GetAttributeTypeByName(name)
}

// GetName returns the attribute name for a given type
func (at *AttributeTypes) GetName(attrType uint8) string {
	return at.dict.GetAttributeNameByType(attrType)
}
