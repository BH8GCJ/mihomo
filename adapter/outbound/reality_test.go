package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

func TestRealityOptionsSupportX25519MLKEM768(t *testing.T) {
	const publicKey = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM"

	t.Run("default enabled", func(t *testing.T) {
		config, err := (RealityOptions{PublicKey: publicKey}).Parse()
		if err != nil {
			t.Fatal(err)
		}
		if !config.SupportX25519MLKEM768 {
			t.Error("X25519MLKEM768 should be enabled by default")
		}
	})

	for _, tc := range []struct {
		name  string
		value bool
	}{
		{"explicitly enabled", true},
		{"explicitly disabled", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := tc.value
			config, err := (RealityOptions{
				PublicKey:             publicKey,
				SupportX25519MLKEM768: &value,
			}).Parse()
			if err != nil {
				t.Fatal(err)
			}
			if config.SupportX25519MLKEM768 != tc.value {
				t.Errorf("SupportX25519MLKEM768 = %v, want %v", config.SupportX25519MLKEM768, tc.value)
			}
		})
	}
}

func TestRealityOptionsDecodeSupportX25519MLKEM768(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	for _, tc := range []struct {
		name  string
		value any
		want  *bool
	}{
		{"absent", nil, nil},
		{"enabled", true, boolPointer(true)},
		{"disabled", false, boolPointer(false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mapping := map[string]any{"public-key": "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM"}
			if tc.value != nil {
				mapping["support-x25519mlkem768"] = tc.value
			}
			var option RealityOptions
			if err := decoder.Decode(mapping, &option); err != nil {
				t.Fatalf("decode: %v", err)
			}
			switch {
			case tc.want == nil && option.SupportX25519MLKEM768 != nil:
				t.Errorf("SupportX25519MLKEM768 = %v, want nil", *option.SupportX25519MLKEM768)
			case tc.want != nil && (option.SupportX25519MLKEM768 == nil || *option.SupportX25519MLKEM768 != *tc.want):
				t.Errorf("SupportX25519MLKEM768 = %v, want %v", option.SupportX25519MLKEM768, *tc.want)
			}
		})
	}
}

func boolPointer(value bool) *bool {
	return &value
}
