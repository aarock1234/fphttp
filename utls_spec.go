package http

import (
	"errors"
	"fmt"
	"reflect"
	"slices"

	utls "github.com/refraction-networking/utls"
)

func cloneClientHelloSpec(spec *utls.ClientHelloSpec) (*utls.ClientHelloSpec, error) {
	if err := validateClientHelloExtensions(spec); err != nil {
		return nil, err
	}

	clone := *spec
	clone.CipherSuites = slices.Clone(spec.CipherSuites)
	clone.CompressionMethods = slices.Clone(spec.CompressionMethods)
	clone.Extensions = make([]utls.TLSExtension, len(spec.Extensions))

	for i, extension := range spec.Extensions {
		copy, err := cloneClientHelloExtension(extension)
		if err != nil {
			return nil, fmt.Errorf("fphttp: ClientHelloSpec.Extensions[%d]: %w", i, err)
		}
		clone.Extensions[i] = copy
	}

	return &clone, nil
}

func validateClientHelloExtensions(spec *utls.ClientHelloSpec) error {
	for i, extension := range spec.Extensions {
		value := reflect.ValueOf(extension)
		if extension == nil || (value.Kind() == reflect.Pointer && value.IsNil()) {
			return fmt.Errorf("fphttp: ClientHelloSpec.Extensions[%d] is nil", i)
		}
	}

	return nil
}

func cloneClientHelloExtension(extension utls.TLSExtension) (utls.TLSExtension, error) {
	switch source := extension.(type) {
	case *utls.SNIExtension:
		clone := *source

		return &clone, nil
	case *utls.StatusRequestExtension:
		return &utls.StatusRequestExtension{}, nil
	case *utls.StatusRequestV2Extension:
		return &utls.StatusRequestV2Extension{}, nil
	case *utls.SupportedCurvesExtension:
		return &utls.SupportedCurvesExtension{Curves: slices.Clone(source.Curves)}, nil
	case *utls.SupportedPointsExtension:
		return &utls.SupportedPointsExtension{SupportedPoints: slices.Clone(source.SupportedPoints)}, nil
	case *utls.SignatureAlgorithmsExtension:
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: slices.Clone(source.SupportedSignatureAlgorithms)}, nil
	case *utls.SignatureAlgorithmsCertExtension:
		return &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: slices.Clone(source.SupportedSignatureAlgorithms)}, nil
	case *utls.ALPNExtension:
		return &utls.ALPNExtension{AlpnProtocols: slices.Clone(source.AlpnProtocols)}, nil
	case *utls.ApplicationSettingsExtension:
		return &utls.ApplicationSettingsExtension{SupportedProtocols: slices.Clone(source.SupportedProtocols)}, nil
	case *utls.ApplicationSettingsExtensionNew:
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: slices.Clone(source.SupportedProtocols)}, nil
	case *utls.SCTExtension:
		return &utls.SCTExtension{}, nil
	case *utls.ExtendedMasterSecretExtension:
		return &utls.ExtendedMasterSecretExtension{}, nil
	case *utls.GenericExtension:
		return &utls.GenericExtension{
			Id:   source.Id,
			Data: slices.Clone(source.Data),
		}, nil
	case *utls.UtlsGREASEExtension:
		return &utls.UtlsGREASEExtension{
			Value: source.Value,
			Body:  slices.Clone(source.Body),
		}, nil
	case *utls.UtlsPaddingExtension:
		clone := *source

		return &clone, nil
	case *utls.UtlsCompressCertExtension:
		return &utls.UtlsCompressCertExtension{Algorithms: slices.Clone(source.Algorithms)}, nil
	case *utls.KeyShareExtension:
		shares := slices.Clone(source.KeyShares)
		for i := range shares {
			if shares[i].Group != utls.CurveID(utls.GREASE_PLACEHOLDER) && len(shares[i].Data) > 0 {
				return nil, errors.New("key shares must be generated during the handshake; use ClientHelloSpecFactory for custom key material")
			}
			shares[i].Data = slices.Clone(shares[i].Data)
		}

		return &utls.KeyShareExtension{KeyShares: shares}, nil
	case *utls.PSKKeyExchangeModesExtension:
		return &utls.PSKKeyExchangeModesExtension{Modes: slices.Clone(source.Modes)}, nil
	case *utls.SupportedVersionsExtension:
		return &utls.SupportedVersionsExtension{Versions: slices.Clone(source.Versions)}, nil
	case *utls.CookieExtension:
		return &utls.CookieExtension{Cookie: slices.Clone(source.Cookie)}, nil
	case *utls.NPNExtension:
		return &utls.NPNExtension{NextProtos: slices.Clone(source.NextProtos)}, nil
	case *utls.RenegotiationInfoExtension:
		clone := *source
		clone.RenegotiatedConnection = slices.Clone(source.RenegotiatedConnection)

		return &clone, nil
	case *utls.SessionTicketExtension:
		if source.Initialized || source.Session != nil || len(source.Ticket) > 0 {
			return nil, errors.New("initialized session tickets require ClientHelloSpecFactory")
		}

		return &utls.SessionTicketExtension{}, nil
	case *utls.FakeRecordSizeLimitExtension:
		clone := *source

		return &clone, nil
	case *utls.FakeDelegatedCredentialsExtension:
		return &utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: slices.Clone(source.SupportedSignatureAlgorithms)}, nil
	default:
		return nil, fmt.Errorf("extension %T requires ClientHelloSpecFactory", extension)
	}
}
