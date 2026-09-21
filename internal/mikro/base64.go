package mikro

// MTB64Table is MikroTik's base64 alphabet.
const MTB64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var mtb64Index = func() [256]int {
	var idx [256]int
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(MTB64Table); i++ {
		idx[MTB64Table[i]] = i
	}
	return idx
}()

// MTB64Encode is keygen.py's mt_b64_encode: a bespoke 6-bit packing, not
// RFC 4648.
func MTB64Encode(data []byte, pad bool) string {
	out := make([]byte, 0, len(data)*2)
	left := 0
	for i := 0; i < len(data); i++ {
		switch left {
		case 0:
			out = append(out, MTB64Table[data[i]&0x3F])
			left = 2
		case 6:
			out = append(out, MTB64Table[data[i-1]>>2])
			out = append(out, MTB64Table[data[i]&0x3F])
			left = 2
		default:
			index := ((data[i-1] >> (8 - left)) | (data[i] << left)) & 0x3F
			out = append(out, MTB64Table[index])
			left += 2
		}
	}
	if left != 0 {
		out = append(out, MTB64Table[data[len(data)-1]>>(8-left)])
	}
	if pad {
		for len(out)%4 != 0 {
			out = append(out, '=')
		}
	}
	return string(out)
}

// MTB64Decode reverses MTB64Encode.
func MTB64Decode(text string) ([]byte, error) {
	clean := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		if text[i] != '=' {
			clean = append(clean, text[i])
		}
	}
	out := make([]byte, 0, len(clean))
	left := 0
	for i := 0; i < len(clean); i++ {
		if left == 0 {
			left = 6
			continue
		}
		v1 := mtb64Index[clean[i-1]] >> (6 - left)
		v2 := mtb64Index[clean[i]] & (1<<(8-left) - 1)
		out = append(out, byte(v1|(v2<<left)))
		left -= 2
	}
	return out, nil
}
