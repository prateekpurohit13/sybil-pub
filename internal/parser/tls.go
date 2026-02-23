package parser
import(
	"errors"
	"golang.org/x/crypto/cryptobyte"
)

type ParsedTLS struct{
	TLSVersion      uint16
	SNI             string
	ALPN            string
	CipherSuites    []uint16
	Extensions      []uint16
	SupportedGroups []uint16
	SignatureAlgorithms []uint16
}

func IsGrease(v uint16) bool{
	return (v&0x0F0F == 0x0A0A) && ((v >> 8) == (v & 0xFF))
}

func ParseTLS(rawBytes []byte)(*ParsedTLS, error){
	s := cryptobyte.String(rawBytes)
	info := &ParsedTLS{}
	var contentType uint8
	if !s.ReadUint8(&contentType) || contentType != 22 {
		return nil, errors.New("not a TLS handshake record")
	}

	var recordVersion, recordLength uint16
	if !s.ReadUint16(&recordVersion) || !s.ReadUint16(&recordLength){
		return nil, errors.New("failed to read record header")
	}

	var handshakeBytes []byte
	if !s.ReadBytes(&handshakeBytes, int(recordLength)){
		return nil, errors.New("incomplete TLS record")
	}
	handshake := cryptobyte.String(handshakeBytes)
	var handshakeType uint8
	if !handshake.ReadUint8(&handshakeType) || handshakeType != 1 {
		return nil, errors.New("not a Client Hello message")
	}

	var handshakeLength uint32
	if !handshake.ReadUint24(&handshakeLength){
		return nil, errors.New("failed to read handshake length")
	}

	if !handshake.ReadUint16(&info.TLSVersion) || !handshake.Skip(32){
		return nil, errors.New("failed to read TLS version or skip random")
	}

	var sessionID cryptobyte.String
	if !handshake.ReadUint8LengthPrefixed(&sessionID){
		return nil, errors.New("failed to read session ID")
	}

	var cipherSuites cryptobyte.String
	if !handshake.ReadUint16LengthPrefixed(&cipherSuites){
		return nil, errors.New("failed to read cipher suites")
	}

	for !cipherSuites.Empty(){
		var cipher uint16
		if cipherSuites.ReadUint16(&cipher) && !IsGrease(cipher){
			info.CipherSuites = append(info.CipherSuites, cipher)
		}
	}

	var compressionMethods cryptobyte.String
	if !handshake.ReadUint8LengthPrefixed(&compressionMethods){
		return nil, errors.New("failed to read compression methods")
	}
	if handshake.Empty(){
		return info, nil
	}

	var extensions cryptobyte.String
	if !handshake.ReadUint16LengthPrefixed(&extensions){
		return nil, errors.New("failed to read extensions")
	}

	for !extensions.Empty(){
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData){
			break
		}
		if !IsGrease(extType){
			info.Extensions = append(info.Extensions, extType)
		}

		switch extType{
		case 0:
			var serverNameList cryptobyte.String
			if extData.ReadUint16LengthPrefixed(&serverNameList){
				for !serverNameList.Empty(){
					var nameType uint8
					var serverName cryptobyte.String
					if serverNameList.ReadUint8(&nameType) && serverNameList.ReadUint16LengthPrefixed(&serverName){
						if nameType == 0 {
							info.SNI = string(serverName)
							break
						}
					}
				}
			}
		case 16:
			var alpnList cryptobyte.String
			if extData.ReadUint16LengthPrefixed(&alpnList) && !alpnList.Empty(){
				var firstALPN cryptobyte.String
				if alpnList.ReadUint8LengthPrefixed(&firstALPN){
					info.ALPN = string(firstALPN)
				}
			}
		case 10:
			var groupList cryptobyte.String
			if extData.ReadUint16LengthPrefixed(&groupList){
				for !groupList.Empty(){
					var group uint16
					if groupList.ReadUint16(&group) && !IsGrease(group){
						info.SupportedGroups = append(info.SupportedGroups, group)
					}
				}
			}
		case 13:
			var sigList cryptobyte.String
			if extData.ReadUint16LengthPrefixed(&sigList){
				for !sigList.Empty(){
					var sig uint16
					if sigList.ReadUint16(&sig) && !IsGrease(sig){
						info.SignatureAlgorithms = append(info.SignatureAlgorithms, sig)
					}
				}
			}
		}
	}

	return info, nil
}