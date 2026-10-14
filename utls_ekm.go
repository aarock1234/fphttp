package http

import (
	"crypto/tls"
	"reflect"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

// keyingMaterialExporter is the signature of crypto/tls.ConnectionState's
// unexported ekm field, which ExportKeyingMaterial calls.
type keyingMaterialExporter = func(label string, context []byte, length int) ([]byte, error)

// setKeyingMaterialExporter makes state.ExportKeyingMaterial derive keying
// material from the uTLS connection described by ucs, so that callers use
// the standard crypto/tls method on uTLS connections.
//
// crypto/tls keeps the exporter in an unexported field that only its own
// handshake sets, so reflect and unsafe are the only way to supply it. The
// field is located by name and its type checked first, so a Go release that
// renames or retypes it leaves state unchanged instead of corrupting it.
// Audit this function whenever the Go toolchain version changes.
func setKeyingMaterialExporter(state *tls.ConnectionState, ucs utls.ConnectionState) {
	field := reflect.ValueOf(state).Elem().FieldByName("ekm")
	if !field.IsValid() || field.Type() != reflect.TypeFor[keyingMaterialExporter]() {
		return
	}

	export := keyingMaterialExporter(ucs.ExportKeyingMaterial)
	settable := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	settable.Set(reflect.ValueOf(export))
}
